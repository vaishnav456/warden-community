"""Verify possession of an endpoint's already-issued device certificate key."""
import base64
import hashlib
import hmac
import re
import time
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


def certificate_fingerprint_matches(endpoint, actual, *, now=None):
    """Allow only the current pin and a bounded previous-pin renewal grace."""
    actual = str(actual or "").lower().replace(":", "")
    if not actual:
        return False
    expected = str(endpoint.get("client_cert_fingerprint") or "").lower().replace(":", "")
    if expected and hmac.compare_digest(expected, actual):
        return True
    previous = str(endpoint.get("previous_client_cert_fingerprint") or "").lower().replace(":", "")
    try:
        expires = datetime.fromisoformat(str(endpoint.get("previous_client_cert_expires_at") or "").replace("Z", "+00:00"))
        valid = expires.tzinfo is not None and expires > (now or datetime.now(timezone.utc))
    except (TypeError, ValueError):
        valid = False
    return bool(previous and valid and hmac.compare_digest(previous, actual))


def validate_renewal_identity(endpoint, certificate_pem, csr_pem):
    """CSR possession must match the pinned existing key, not just an API token."""
    if not isinstance(certificate_pem, str) or len(certificate_pem) > 16384:
        raise ValueError("invalid certificate")
    if not isinstance(csr_pem, str) or len(csr_pem) > 32000:
        raise ValueError("invalid CSR")
    certificate = x509.load_pem_x509_certificate(certificate_pem.encode())
    if not certificate_fingerprint_matches(endpoint, certificate.fingerprint(hashes.SHA256()).hex()):
        raise ValueError("device certificate binding mismatch")
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    if not csr.is_signature_valid or csr.public_key().public_numbers() != certificate.public_key().public_numbers():
        raise ValueError("renewal must retain the existing device key")
    return certificate.fingerprint(hashes.SHA256()).hex()


def verify_device_signature(endpoint, certificate_pem, signature_b64, message):
    if not isinstance(certificate_pem, str) or len(certificate_pem) > 16384:
        raise ValueError("invalid certificate")
    if not isinstance(signature_b64, str) or len(signature_b64) > 4096:
        raise ValueError("invalid signature")
    certificate = x509.load_pem_x509_certificate(certificate_pem.encode())
    actual = certificate.fingerprint(hashes.SHA256()).hex()
    if not certificate_fingerprint_matches(endpoint, actual):
        raise ValueError("device certificate binding mismatch")
    public = certificate.public_key()
    if not isinstance(public, rsa.RSAPublicKey) or public.key_size < 2048:
        raise ValueError("unsupported device key")
    public.verify(base64.b64decode(signature_b64, validate=True), message,
                  padding.PKCS1v15(), hashes.SHA256())


def heartbeat_proof_message(envelope, context):
    values = [envelope.get(key) for key in ("ephemeral_key", "nonce", "ciphertext")]
    if not all(isinstance(value, str) for value in values):
        raise ValueError("invalid message")
    digest = hashlib.sha256("|".join(values).encode()).hexdigest()
    return context + b"|device-proof|" + digest.encode()


def verify_agent_request(endpoint, headers, method, target, body=b""):
    """Bind device possession to the exact request and consume a shared nonce."""
    import db
    timestamp = headers.get("X-Warden-Device-Time", "")
    nonce = headers.get("X-Warden-Device-Nonce", "")
    if not re.fullmatch(r"[0-9]{10}", timestamp) or abs(int(timestamp)-int(time.time())) > 60 or not re.fullmatch(r"[0-9a-f]{32}", nonce):
        raise ValueError("invalid device request proof")
    encoded = headers.get("X-Warden-Device-Certificate", "")
    if len(encoded) > 24000:
        raise ValueError("invalid device certificate")
    certificate = base64.b64decode(encoded, validate=True).decode()
    digest = hashlib.sha256(body).hexdigest()
    message = f"warden-request-v1|{endpoint['id']}|{method}|{target}|{timestamp}|{nonce}|{digest}".encode()
    verify_device_signature(endpoint, certificate, headers.get("X-Warden-Device-Signature", ""), message)
    if not db.consume_rate_limit(f"device-request:{endpoint['id']}:{nonce}", 1, 600):
        raise ValueError("replayed device request")
