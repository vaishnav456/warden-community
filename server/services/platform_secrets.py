"""Encryption and one-way verification for platform authentication secrets."""
import base64
import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import config

_ENC_PREFIX = "enc:v1:"
_HASH_PREFIX = "h1:"


def _key() -> bytes:
    raw = config.TENANT_MASTER_KEK_B64
    if not raw:
        raise RuntimeError("TENANT_MASTER_KEK_B64 is required to protect MFA secrets")
    key = base64.b64decode(raw, validate=True)
    if len(key) != 32:
        raise RuntimeError("TENANT_MASTER_KEK_B64 must decode to exactly 32 bytes")
    return key


def encrypt_mfa_secret(admin_id, secret: str) -> str:
    if secret.startswith(_ENC_PREFIX):
        return secret
    nonce = os.urandom(12)
    aad = f"warden:mfa:{admin_id}".encode()
    encrypted = AESGCM(_key()).encrypt(nonce, secret.encode(), aad)
    return _ENC_PREFIX + base64.urlsafe_b64encode(nonce + encrypted).decode()


def decrypt_mfa_secret(admin_id, value):
    if not value or not str(value).startswith(_ENC_PREFIX):
        return value  # rolling-upgrade support for legacy plaintext rows
    raw = base64.urlsafe_b64decode(str(value)[len(_ENC_PREFIX):])
    aad = f"warden:mfa:{admin_id}".encode()
    return AESGCM(_key()).decrypt(raw[:12], raw[12:], aad).decode()


def encrypt_platform_field(record_id, purpose: str, value: str) -> str:
    """Encrypt application profile data with record- and purpose-bound AAD."""
    nonce = os.urandom(12)
    aad = f"warden:platform:{purpose}:{record_id}".encode()
    encrypted = AESGCM(_key()).encrypt(nonce, str(value).encode(), aad)
    return _ENC_PREFIX + base64.urlsafe_b64encode(nonce + encrypted).decode()


def decrypt_platform_field(record_id, purpose: str, value: str) -> str:
    if not value or not str(value).startswith(_ENC_PREFIX):
        raise ValueError("platform field is not encrypted")
    raw = base64.urlsafe_b64decode(str(value)[len(_ENC_PREFIX):])
    aad = f"warden:platform:{purpose}:{record_id}".encode()
    return AESGCM(_key()).decrypt(raw[:12], raw[12:], aad).decode()


def hash_backup_code(code: str) -> str:
    digest = hmac.new(_key(), str(code).strip().encode(), hashlib.sha256).hexdigest()
    return _HASH_PREFIX + digest


def backup_code_matches(candidate: str, stored: str) -> bool:
    if str(stored).startswith(_HASH_PREFIX):
        return hmac.compare_digest(hash_backup_code(candidate), str(stored))
    # Legacy plaintext codes remain usable once and are rewritten/removed.
    return hmac.compare_digest(str(candidate), str(stored))
