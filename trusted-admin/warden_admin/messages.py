"""End-to-end records for future endpoint/automation relay paths.

The relay receives public framing and ciphertext only. Sender identities and
recipient public keys must be approved/pinned outside that relay. This module is
not wired to legacy agents; those agents still trust server-issued commands.
"""
import base64
import os
import re

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


PREFIX = b"warden:client-only:v1:"
MAX_MESSAGE = 16 * 1024 * 1024


def _public(key):
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _derive(root, purpose):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=PREFIX + purpose).derive(root)


def admin_keys(vault):
    # Independently derived keys; no reuse of legacy server keys or wrapping KEK.
    return (X25519PrivateKey.from_private_bytes(_derive(vault.key, b"admin-recipient")),
            Ed25519PrivateKey.from_private_bytes(_derive(vault.key, b"admin-signing")))


def public_identity(vault):
    recipient, signing = admin_keys(vault)
    return {"recipient": base64.b64encode(_public(recipient.public_key())).decode("ascii"),
            "signing": base64.b64encode(_public(signing.public_key())).decode("ascii")}


def _frame(channel, identifier, ephemeral, recipient):
    if any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{32}", value)
           for value in (channel, identifier)):
        raise ValueError("Invalid message routing identifier")
    return PREFIX + channel.encode("ascii") + identifier.encode("ascii") + ephemeral + recipient


def encrypt_message(recipient_public, signing_private, channel, identifier, plaintext):
    if len(plaintext) > MAX_MESSAGE:
        raise ValueError("Message is too large")
    recipient = X25519PublicKey.from_public_bytes(recipient_public)
    ephemeral = X25519PrivateKey.generate()
    ephemeral_public = _public(ephemeral.public_key())
    frame = _frame(channel, identifier, ephemeral_public, recipient_public)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=frame).derive(ephemeral.exchange(recipient))
    nonce = os.urandom(12)
    body = AESGCM(key).encrypt(nonce, plaintext, frame)
    signature = signing_private.sign(frame + nonce + body)
    return {"v": 1, "channel": channel, "id": identifier,
            **{name: base64.b64encode(value).decode("ascii") for name, value in (
                ("ephemeral", ephemeral_public), ("nonce", nonce), ("body", body), ("signature", signature))}}


def decrypt_message(recipient_private, pinned_sender_public, envelope):
    if (not isinstance(envelope, dict) or set(envelope) != {
            "v", "channel", "id", "ephemeral", "nonce", "body", "signature"}
            or type(envelope["v"]) is not int or envelope["v"] != 1):
        raise ValueError("Unsupported message envelope")
    values = {}
    for name, bound in (("ephemeral", 32), ("nonce", 12), ("body", MAX_MESSAGE + 16), ("signature", 64)):
        encoded = envelope[name]
        if not isinstance(encoded, str) or len(encoded) > (bound + 2) * 4 // 3:
            raise ValueError("Invalid message encoding")
        values[name] = base64.b64decode(encoded, validate=True)
        if ((name != "body" and len(values[name]) != bound)
                or (name == "body" and not 16 <= len(values[name]) <= bound)):
            raise ValueError("Invalid message length")
    recipient_public = _public(recipient_private.public_key())
    frame = _frame(envelope["channel"], envelope["id"], values["ephemeral"], recipient_public)
    # Authenticate the independently pinned sender BEFORE decryption.
    Ed25519PublicKey.from_public_bytes(pinned_sender_public).verify(
        values["signature"], frame + values["nonce"] + values["body"])
    shared = recipient_private.exchange(X25519PublicKey.from_public_bytes(values["ephemeral"]))
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=frame).derive(shared)
    return AESGCM(key).decrypt(values["nonce"], values["body"], frame)
