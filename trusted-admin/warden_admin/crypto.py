"""Client-owned keys and authenticated, context-bound encryption.

This module is never imported by the public Warden server or relay. A compromised
host running this application can read its unlocked keys; process isolation is
not a substitute for moving the application to a trusted machine.
"""
import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


MAX_VALUE = 32 * 1024 * 1024


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def seal(key, context, plaintext):
    if len(key) != 32 or len(plaintext) > MAX_VALUE:
        raise ValueError("Invalid encryption input")
    nonce = os.urandom(12)
    return "wa1:" + base64.b64encode(nonce + AESGCM(key).encrypt(
        nonce, plaintext, b"warden:trusted-admin:v1:" + canonical(context))).decode("ascii")


def unseal(key, context, ciphertext):
    if not isinstance(ciphertext, str) or not ciphertext.startswith("wa1:"):
        raise ValueError("Invalid encrypted record")
    if len(ciphertext) > (MAX_VALUE + 28) * 4 // 3 + 8:
        raise ValueError("Encrypted record is too large")
    raw = base64.b64decode(ciphertext[4:], validate=True)
    if not 28 <= len(raw) <= MAX_VALUE + 28:
        raise ValueError("Invalid encrypted record")
    return AESGCM(key).decrypt(raw[:12], raw[12:],
                               b"warden:trusted-admin:v1:" + canonical(context))


def _password_key(password, salt):
    if not isinstance(password, str) or not 16 <= len(password) <= 4096:
        raise ValueError("Use an unlock phrase of at least 16 characters")
    # Parameters are fixed by this format, never supplied by an untrusted file.
    return Scrypt(salt=salt, length=32, n=2**17, r=8, p=1).derive(password.encode("utf-8"))


class Vault:
    def __init__(self, identifier, key):
        self.identifier = identifier
        self._key = key

    @classmethod
    def create(cls, path, password):
        import uuid
        salt = os.urandom(16)
        identifier = uuid.uuid4().hex
        key = os.urandom(32)
        wrapped = seal(_password_key(password, salt), {"vault": identifier}, key)
        payload = canonical({"v": 1, "id": identifier,
                             "salt": base64.b64encode(salt).decode("ascii"), "wrapped": wrapped})
        # Exclusive creation prevents accidental replacement of the only key.
        descriptor = os.open(Path(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        return cls(identifier, key)

    @classmethod
    def unlock(cls, path, password):
        path = Path(path)
        if path.stat().st_size > 8192:
            raise ValueError("Invalid vault")
        payload = json.loads(path.read_bytes())
        if set(payload) != {"v", "id", "salt", "wrapped"} or payload["v"] != 1:
            raise ValueError("Unsupported vault")
        import re
        if not isinstance(payload["id"], str) or not re.fullmatch(r"[0-9a-f]{32}", payload["id"]):
            raise ValueError("Invalid vault")
        salt = base64.b64decode(payload["salt"], validate=True)
        if len(salt) != 16:
            raise ValueError("Invalid vault")
        key = unseal(_password_key(password, salt), {"vault": payload["id"]}, payload["wrapped"])
        if len(key) != 32:
            raise ValueError("Invalid vault")
        return cls(payload["id"], key)

    @property
    def key(self):
        if self._key is None:
            raise RuntimeError("Vault is locked")
        return self._key

    def lock(self):
        # Python/cryptography do not promise zeroization of prior allocations.
        # End the process to discard unlocked state; do not claim secure erasure.
        self._key = None
