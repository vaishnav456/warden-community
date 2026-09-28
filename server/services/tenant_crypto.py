"""
tenant_crypto.py — Organization envelope encryption
----------------------------------------------------
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
  correct passphrase, and is lost on process restart or an explicit
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
import threading

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

import config

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
_cache_lock = threading.Lock()


def _master_kek() -> bytes:
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
    kdf = Scrypt(salt=salt, length=32, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
    return kdf.derive(passphrase.encode("utf-8"))


# ── Provisioning ───────────────────────────────────────────────────────────

def provision_managed(company_id: str) -> dict:
    """Generate a new DEK for a managed-mode company, wrapped with the
    server master key. Returns fields to persist via
    db.set_company_encryption()."""
    dek = os.urandom(_DEK_LEN)
    wrapped = _aes_wrap(_master_kek(), dek, company_id)
    with _cache_lock:
        _dek_cache[str(company_id)] = dek
    return {"encryption_mode": "managed", "wrapped_dek": wrapped, "byok_salt": None}


def provision_byok(company_id: str, passphrase: str) -> dict:
    """Generate a *brand-new* DEK for a company that has never been
    provisioned before (i.e. at company creation, if BYOK is chosen up
    front). Do NOT call this to switch an existing company from managed
    to BYOK — that would orphan every row already encrypted under the
    old DEK. Use rewrap_to_byok() for that instead."""
    if not passphrase or len(passphrase) < 12:
        raise ValueError("BYOK passphrase must be at least 12 characters")
    dek = os.urandom(_DEK_LEN)
    with _cache_lock:
        _dek_cache[str(company_id)] = dek
    return _wrap_dek_for_byok(company_id, dek, passphrase)


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


def rewrap_to_managed(company_id: str, current_mode: str, current_wrapped_dek: str) -> dict:
    """Re-wrap the existing cached DEK with the platform KEK.

    BYOK callers must first prove the current passphrase with unlock_byok;
    otherwise _get_dek fails closed while the vault is locked.
    """
    dek = _get_dek(company_id, current_mode, current_wrapped_dek)
    wrapped = _aes_wrap(_master_kek(), dek, company_id)
    with _cache_lock:
        _dek_cache[str(company_id)] = dek
    return {"encryption_mode": "managed", "wrapped_dek": wrapped, "byok_salt": None}


def _wrap_dek_for_byok(company_id: str, dek: bytes, passphrase: str) -> dict:
    salt = os.urandom(_SCRYPT_SALT_LEN)
    kek = _derive_kek_from_passphrase(passphrase, salt)
    wrapped = _aes_wrap(kek, dek, company_id)
    with _cache_lock:
        _dek_cache[str(company_id)] = dek
    return {
        "encryption_mode": "byok",
        "wrapped_dek": wrapped,
        "byok_salt": base64.b64encode(salt).decode(),
    }


# ── Unlock / lock (BYOK only) ───────────────────────────────────────────────

def unlock_byok(company_id: str, passphrase: str, wrapped_dek: str, byok_salt_b64: str) -> None:
    """Verify the passphrase and cache the unwrapped DEK in memory. Raises
    ValueError on a wrong passphrase (AESGCM authentication failure)."""
    salt = base64.b64decode(byok_salt_b64)
    kek = _derive_kek_from_passphrase(passphrase, salt)
    try:
        dek = _aes_unwrap(kek, wrapped_dek, company_id)
    except Exception:
        raise ValueError("Incorrect vault passphrase")
    with _cache_lock:
        _dek_cache[str(company_id)] = dek


def lock_company(company_id: str) -> None:
    """Drop a company's cached DEK from memory. For managed-mode companies
    this is harmless — the next encrypt/decrypt call just re-derives it
    from the master key. For BYOK-mode companies this actually locks the
    vault until unlock_byok() is called again."""
    with _cache_lock:
        _dek_cache.pop(str(company_id), None)


def is_unlocked(company_id: str) -> bool:
    with _cache_lock:
        return str(company_id) in _dek_cache


# ── Encrypt / decrypt ────────────────────────────────────────────────────

def _get_dek(company_id: str, mode: str, wrapped_dek: str) -> bytes:
    key = str(company_id)
    with _cache_lock:
        cached = _dek_cache.get(key)
    if cached is not None:
        return cached
    if mode == "managed":
        dek = _aes_unwrap(_master_kek(), wrapped_dek, company_id)
        with _cache_lock:
            _dek_cache[key] = dek
        return dek
    raise VaultLocked(
        f"Tenant vault for company {company_id} is locked — a tenant admin "
        "must call unlock_byok() before encrypted data can be read or written."
    )


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
