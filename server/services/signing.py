"""
Warden — Command signing service
Ed25519-based signing for all commands dispatched to agents.
Agents verify every envelope before executing.
"""
import base64
import hashlib
import json
import secrets
import time
from collections import OrderedDict

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
    load_pem_private_key,
)

import config

_private_key: Ed25519PrivateKey | None = None
_public_key_b64: str = ""

# LRU nonce cache — last 2000 nonces (covers ~33 min at 1 cmd/sec)
_seen_nonces: OrderedDict = OrderedDict()
_NONCE_CACHE_SIZE = 2000
# Hypervisor resume and pre-time-service boot can leave a Windows guest a few
# minutes behind even while HTTPS and heartbeat traffic work normally. Expiry
# and the durable per-agent nonce cache remain the replay boundaries, so
# backdating issued_at prevents valid freshly-delivered jobs from looking as
# though they came from the future to an older agent.
_ISSUED_AT_BACKDATE_SEC = 2 * 60 * 60


def _get_private_key() -> Ed25519PrivateKey:
    global _private_key
    if _private_key is None:
        raw = base64.b64decode(config.ED25519_PRIVATE_KEY_B64)
        _private_key = Ed25519PrivateKey.from_private_bytes(raw)
    return _private_key


def get_server_pubkey_b64() -> str:
    """Return server Ed25519 public key as base64 — baked into agent at build time."""
    global _public_key_b64
    if not _public_key_b64:
        pub = _get_private_key().public_key()
        raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        _public_key_b64 = base64.b64encode(raw).decode()
    return _public_key_b64


def sign_canonical_payload(payload: dict) -> bytes:
    """Sign a stable JSON object for an offline-verifying Warden component."""
    message = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return _get_private_key().sign(message)


def sign_job(job_id: str, operation: str, payload: dict,
             company_id: str, endpoint_id: str) -> dict:
    """
    Build a signed command envelope for dispatch to agent.
    Envelope includes nonce + timestamps to prevent replay.
    """
    now = int(time.time())
    nonce = secrets.token_hex(16)
    envelope = {
        "job_id": job_id,
        "company_id": company_id,
        "endpoint_id": endpoint_id,
        "nonce": nonce,
        "issued_at": now - _ISSUED_AT_BACKDATE_SEC,
        "expires_at": now + config.COMMAND_MAX_AGE_SEC,
        "operation": operation,
        "payload": payload,
    }
    # Sign canonical JSON (sorted keys, no whitespace)
    message = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
    sig = _get_private_key().sign(message)
    envelope["signature"] = base64.b64encode(sig).decode()
    return envelope


def verify_envelope(envelope: dict, pubkey_b64: str | None = None) -> bool:
    """
    Verify an envelope's Ed25519 signature, expiry, and nonce uniqueness.
    Returns True only if ALL checks pass.
    """
    try:
        sig_b64 = envelope.get("signature", "")
        if not sig_b64:
            return False

        # Check expiry
        now = int(time.time())
        if now > envelope.get("expires_at", 0):
            return False
        if now < envelope.get("issued_at", now) - 5:  # 5s clock skew allowance
            return False

        # Check nonce uniqueness
        nonce = envelope.get("nonce", "")
        if not nonce or nonce in _seen_nonces:
            return False

        if not envelope.get("company_id") or not envelope.get("endpoint_id"):
            return False

        # Verify signature — reconstruct canonical message without signature field
        payload_for_verify = {k: v for k, v in envelope.items() if k != "signature"}
        message = json.dumps(payload_for_verify, sort_keys=True, separators=(",", ":")).encode()
        sig = base64.b64decode(sig_b64)

        if pubkey_b64:
            raw_pub = base64.b64decode(pubkey_b64)
            pub_key = Ed25519PublicKey.from_public_bytes(raw_pub)
        else:
            pub_key = _get_private_key().public_key()

        pub_key.verify(sig, message)

        # Record nonce only after successful verification
        _seen_nonces[nonce] = now
        if len(_seen_nonces) > _NONCE_CACHE_SIZE:
            _seen_nonces.popitem(last=False)

        return True
    except Exception:
        return False
