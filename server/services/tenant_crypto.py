"""
tenant_crypto.py — Organization envelope encryption
----------------------------------------------------
With KEY_SERVICE_SOCKET configured, all public operations run in the separate
key service. The application retains neither the master key nor unwrapped DEKs.
The service never exports keys, but authorized decryption returns plaintext to
Warden. Application compromise can still abuse that authority; host compromise
can also compromise the key service. This is not end-to-end encryption.
BYOK keys then survive an application restart, but not a key-service restart.
The local mode described below remains for deployments without key custody.

The single organization gets an AES-256-GCM Data Encryption Key (DEK).
Sensitive organization data (job payloads/output, escalation payloads, raw
sysinfo — see db.py's encrypt_field/decrypt_field callers) is encrypted
with that DEK before it's written to Postgres, so a raw DB dump or a
database operator inspecting rows directly sees ciphertext, not organization
data.

Two key-custody modes, chosen per-company (see db.set_company_encryption):

  "managed" (default) — the DEK is wrapped with a server-held master key
  (TENANT_MASTER_KEK_B64). Always unwrappable by the running server, so
  agents can keep pushing data 24/7 with no administrator online. This does
  NOT stop the application code itself from decrypting; it protects database
  backups and direct database inspection from exposing plaintext.

  "byok" — the DEK is wrapped with a key derived (scrypt) from a
  passphrase only the organization knows; the server never persists the
  passphrase or the derived key. The unwrapped DEK is cached in this
  process's memory only after an administrator calls unlock_byok() with the
  correct passphrase, and expires after a server-chosen random 7–30 days.
  Reading, encrypting, or reopening a browser never extends that expiry.
  The key is also lost on key-owner process restart or an explicit
  lock_company(). While locked, encrypt/decrypt for that company raises
  VaultLocked — callers (job creation/dispatch, sysinfo ingestion) must
  handle that by refusing the write/read and surfacing a clear error,
  not by silently falling back to plaintext. This is a genuine
  availability trade-off the organization is opting into, not a bug.

Neither mode is a claim that the platform's own server process can never
see plaintext — the server has to decrypt to actually dispatch commands to
agents and render data to the organization's own admins. What this buys is
encrypted data at rest in the database; it is not a claim that a compromised
application server cannot see plaintext while actively serving requests.
"""
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

import config
from services.key_service_client import delegated

log = logging.getLogger("tenant_crypto")

_DEK_LEN = 32          # AES-256
_NONCE_LEN = 12        # standard GCM nonce size
_SCRYPT_SALT_LEN = 16
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2 ** 15, 8, 1
_V2_PREFIX = "v2:"


def _aad(company_id: str, purpose: str) -> bytes:
    return f"warden:tenant:v2:{company_id}:{purpose}".encode("utf-8")


class VaultLocked(Exception):
    """Raised when a BYOK-mode company's DEK isn't currently unwrapped in
    memory. Callers must handle this explicitly — see module docstring."""


# ── In-process DEK cache ──────────────────────────────────────────────────
# company_id (str) -> raw DEK bytes. Never written to disk. For "managed"
# companies this is populated lazily (and can always be re-derived from
# wrapped_dek + the master key). For "byok" companies this is populated
# ONLY by unlock_byok() and cleared by lock_company() or process restart.
_dek_cache: dict[str, bytes] = {}
_dek_cache_context: dict[str, tuple[str, str]] = {}
_dek_cache_expiry: dict[str, tuple[float, int]] = {}
_cache_lock = threading.Lock()


def _cache_dek(company_id, mode, wrapped_dek, dek):
    with _cache_lock:
        key = str(company_id)
        _dek_cache[key] = dek
        _dek_cache_context[key] = (mode, wrapped_dek)
        if mode == "byok":
            duration = (7 + secrets.randbelow(24)) * 86400
            _dek_cache_expiry[key] = (time.monotonic() + duration, int(time.time()) + duration)
        else:
            _dek_cache_expiry.pop(key, None)


def _expire_cached_keys():
    """Caller holds cache lock. Fixed deadlines never extend on access."""
    monotonic_now, wall_now = time.monotonic(), time.time()
    for key, (deadline, expires) in list(_dek_cache_expiry.items()):
        if monotonic_now >= deadline or wall_now >= expires or key not in _dek_cache:
            _dek_cache.pop(key, None)
            _dek_cache_context.pop(key, None)
            _dek_cache_expiry.pop(key, None)


def start_expiry_worker():
    """Key-service worker clears expired memory even without a request."""
    def sweep():
        while True:
            time.sleep(30)
            with _cache_lock:
                _expire_cached_keys()
    threading.Thread(target=sweep, name="byok-expiry", daemon=True).start()


def _master_kek() -> bytes:
    if getattr(config, "KEY_SERVICE_SOCKET", ""):
        raise RuntimeError("Master keys are held by the key service")
    raw = config.TENANT_MASTER_KEK_B64
    if not raw:
        raise RuntimeError(
            "TENANT_MASTER_KEK_B64 is not set — required for managed-mode "
            "tenant encryption. Generate with: python3 -c "
            "\"import secrets,base64; print(base64.b64encode(secrets.token_bytes(32)).decode())\""
        )
    key = base64.b64decode(raw)
    if len(key) != 32:
        raise RuntimeError("TENANT_MASTER_KEK_B64 must decode to exactly 32 bytes")
    return key


def _aes_wrap(kek: bytes, dek: bytes, company_id: str) -> str:
    """Return base64(nonce || ciphertext) for dek encrypted under kek."""
    nonce = os.urandom(_NONCE_LEN)
    ct = AESGCM(kek).encrypt(nonce, dek, _aad(company_id, "wrapped-dek"))
    return _V2_PREFIX + base64.b64encode(nonce + ct).decode()


def _aes_unwrap(kek: bytes, wrapped_b64: str, company_id: str) -> bytes:
    versioned = wrapped_b64.startswith(_V2_PREFIX)
    encoded = wrapped_b64[len(_V2_PREFIX):] if versioned else wrapped_b64
    raw = base64.b64decode(encoded)
    nonce, ct = raw[:_NONCE_LEN], raw[_NONCE_LEN:]
    return AESGCM(kek).decrypt(
        nonce, ct, _aad(company_id, "wrapped-dek") if versioned else None
    )


def _derive_kek_from_passphrase(passphrase: str, salt: bytes) -> bytes:
    if not isinstance(passphrase, str) or not passphrase or len(passphrase) > 4096:
        raise ValueError("Invalid vault passphrase")
    if len(salt) != _SCRYPT_SALT_LEN:
        raise ValueError("Invalid vault salt")
    kdf = Scrypt(salt=salt, length=32, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
    return kdf.derive(passphrase.encode("utf-8"))


# ── Provisioning ───────────────────────────────────────────────────────────

@delegated("tenant.provision_managed")
def provision_managed(company_id: str) -> dict:
    """Generate a new DEK for a managed-mode company, wrapped with the
    server master key. Returns fields to persist via
    db.set_company_encryption()."""
    dek = os.urandom(_DEK_LEN)
    wrapped = _aes_wrap(_master_kek(), dek, company_id)
    _cache_dek(company_id, "managed", wrapped, dek)
    return {"encryption_mode": "managed", "wrapped_dek": wrapped, "byok_salt": None}


@delegated("tenant.provision_byok")
def provision_byok(company_id: str, passphrase: str) -> dict:
    """Generate a *brand-new* DEK for a company that has never been
    provisioned before (i.e. at company creation, if BYOK is chosen up
    front). Do NOT call this to switch an existing company from managed
    to BYOK — that would orphan every row already encrypted under the
    old DEK. Use rewrap_to_byok() for that instead."""
    if not passphrase or len(passphrase) < 12:
        raise ValueError("BYOK passphrase must be at least 12 characters")
    dek = os.urandom(_DEK_LEN)
    return _wrap_dek_for_byok(company_id, dek, passphrase)


@delegated("tenant.rewrap_to_byok")
def rewrap_to_byok(company_id: str, current_mode: str, current_wrapped_dek: str, passphrase: str) -> dict:
    """Switch an existing company to BYOK mode WITHOUT losing access to
    data already encrypted under its current DEK: unwraps the DEK using
    whatever key currently protects it (the master key for managed mode,
    or the current BYOK passphrase's derived key), then re-wraps that
    SAME DEK under a newly derived key from the new passphrase. Every
    row already encrypted under the old DEK stays decryptable — nothing
    is re-encrypted, because the DEK itself never changes, only what
    wraps it."""
    if not passphrase or len(passphrase) < 12:
        raise ValueError("BYOK passphrase must be at least 12 characters")
    dek = _get_dek(company_id, current_mode, current_wrapped_dek)
    return _wrap_dek_for_byok(company_id, dek, passphrase)


@delegated("tenant.rewrap_to_managed")
def rewrap_to_managed(company_id: str, current_mode: str, current_wrapped_dek: str) -> dict:
    """Re-wrap the existing cached DEK with the platform KEK.

    BYOK callers must first prove the current passphrase with unlock_byok;
    otherwise _get_dek fails closed while the vault is locked.
    """
    dek = _get_dek(company_id, current_mode, current_wrapped_dek)
    wrapped = _aes_wrap(_master_kek(), dek, company_id)
    _cache_dek(company_id, "managed", wrapped, dek)
    return {"encryption_mode": "managed", "wrapped_dek": wrapped, "byok_salt": None}


def _wrap_dek_for_byok(company_id: str, dek: bytes, passphrase: str) -> dict:
    salt = os.urandom(_SCRYPT_SALT_LEN)
    kek = _derive_kek_from_passphrase(passphrase, salt)
    wrapped = _aes_wrap(kek, dek, company_id)
    _cache_dek(company_id, "byok", wrapped, dek)
    return {
        "encryption_mode": "byok",
        "wrapped_dek": wrapped,
        "byok_salt": base64.b64encode(salt).decode(),
    }


# ── Unlock / lock (BYOK only) ───────────────────────────────────────────────

@delegated("tenant.unlock_byok")
def unlock_byok(company_id: str, passphrase: str, wrapped_dek: str, byok_salt_b64: str) -> None:
    """Verify the passphrase and cache the unwrapped DEK in memory. Raises
    ValueError on a wrong passphrase (AESGCM authentication failure)."""
    salt = base64.b64decode(byok_salt_b64, validate=True)
    kek = _derive_kek_from_passphrase(passphrase, salt)
    try:
        dek = _aes_unwrap(kek, wrapped_dek, company_id)
    except Exception:
        raise ValueError("Incorrect vault passphrase")
    _cache_dek(company_id, "byok", wrapped_dek, dek)


@delegated("tenant.lock_company")
def lock_company(company_id: str) -> None:
    """Drop a company's cached DEK from memory. For managed-mode companies
    this is harmless — the next encrypt/decrypt call just re-derives it
    from the master key. For BYOK-mode companies this actually locks the
    vault until unlock_byok() is called again."""
    with _cache_lock:
        _dek_cache.pop(str(company_id), None)
        _dek_cache_context.pop(str(company_id), None)
        _dek_cache_expiry.pop(str(company_id), None)


@delegated("tenant.is_unlocked")
def is_unlocked(company_id: str) -> bool:
    with _cache_lock:
        _expire_cached_keys()
        return str(company_id) in _dek_cache


@delegated("tenant.vault_status")
def vault_status(company_id: str) -> dict:
    """Return only lock state and server-issued expiry; never export a key."""
    with _cache_lock:
        _expire_cached_keys()
        key = str(company_id)
        expiry = _dek_cache_expiry.get(key)
        return {"unlocked": key in _dek_cache, "expires_at": expiry[1] if expiry else None}


# ── Encrypt / decrypt ────────────────────────────────────────────────────

def _get_dek(company_id: str, mode: str, wrapped_dek: str) -> bytes:
    if getattr(config, "KEY_SERVICE_SOCKET", ""):
        raise RuntimeError("Tenant keys are held by the key service")
    key = str(company_id)
    with _cache_lock:
        _expire_cached_keys()
        cached = _dek_cache.get(key)
        context = _dek_cache_context.get(key)
    if cached is not None and context == (mode, wrapped_dek):
        return cached
    if mode == "managed":
        dek = _aes_unwrap(_master_kek(), wrapped_dek, company_id)
        _cache_dek(company_id, mode, wrapped_dek, dek)
        return dek
    raise VaultLocked(
        f"Tenant vault for company {company_id} is locked — a tenant admin "
        "must call unlock_byok() before encrypted data can be read or written."
    )


@delegated("tenant.encrypt_value")
def encrypt_value(company_id: str, mode: str, wrapped_dek: str, plaintext,
                  purpose: str = "generic") -> str:
    """Encrypt plaintext (any JSON-serializable value) for a company.
    Returns base64(nonce || ciphertext). Raises VaultLocked for a locked
    BYOK company — callers must not swallow that into silent plaintext
    storage."""
    dek = _get_dek(company_id, mode, wrapped_dek)
    data = json.dumps(plaintext).encode("utf-8")
    nonce = os.urandom(_NONCE_LEN)
    ct = AESGCM(dek).encrypt(nonce, data, _aad(company_id, purpose))
    return _V2_PREFIX + base64.b64encode(nonce + ct).decode()


@delegated("tenant.decrypt_value")
def decrypt_value(company_id: str, mode: str, wrapped_dek: str,
                  ciphertext_b64: str, purpose: str = "generic"):
    dek = _get_dek(company_id, mode, wrapped_dek)
    versioned = ciphertext_b64.startswith(_V2_PREFIX)
    encoded = ciphertext_b64[len(_V2_PREFIX):] if versioned else ciphertext_b64
    raw = base64.b64decode(encoded)
    nonce, ct = raw[:_NONCE_LEN], raw[_NONCE_LEN:]
    data = AESGCM(dek).decrypt(
        nonce, ct, _aad(company_id, purpose) if versioned else None
    )
    return json.loads(data.decode("utf-8"))


@delegated("tenant.blind_index_value")
def blind_index_value(company_id: str, mode: str, wrapped_dek: str, value,
                      purpose: str) -> str:
    """Return a tenant- and field-scoped deterministic lookup token.

    The plaintext is never stored.  A purpose-specific HMAC key is derived
    from the tenant DEK, so equal values in different tenants or fields do
    not correlate.  Blind indexes support exact lookups only; they are not
    reversible and intentionally do not support prefix/fuzzy search.
    """
    dek = _get_dek(company_id, mode, wrapped_dek)
    index_key = hmac.new(
        dek, f"warden:blind-index:v1:{purpose}".encode("utf-8"), hashlib.sha256
    ).digest()
    normalized = str(value or "").strip().casefold().encode("utf-8")
    return hmac.new(index_key, normalized, hashlib.sha256).hexdigest()
