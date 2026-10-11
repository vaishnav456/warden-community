import base64
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from warden_admin.messages import encrypt_message, decrypt_message


def public(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


class MessageTests(unittest.TestCase):
    def setUp(self):
        self.recipient = X25519PrivateKey.generate()
        self.sender = Ed25519PrivateKey.generate()
        self.plaintext = b'{"operation":"test-only","expires_at":"2030-01-01","sensitive":"PRIVATE-DATA"}'
        self.message = encrypt_message(public(self.recipient), self.sender, "a"*32, "b"*32, self.plaintext)

    def test_only_recipient_and_pinned_sender_can_open(self):
        self.assertEqual(decrypt_message(self.recipient, public(self.sender), self.message), self.plaintext)
        self.assertNotIn("PRIVATE-DATA", str(self.message))
        for private, sender in ((X25519PrivateKey.generate(), public(self.sender)),
                                (self.recipient, public(Ed25519PrivateKey.generate()))):
            with self.assertRaises(InvalidSignature):
                decrypt_message(private, sender, self.message)

    def test_compromised_relay_cannot_change_routing_or_content(self):
        for name in ("channel", "id", "body", "ephemeral", "nonce", "signature"):
            changed = dict(self.message)
            if name in {"channel", "id"}:
                changed[name] = "c"*32
            else:
                raw = bytearray(base64.b64decode(changed[name]))
                raw[-1] ^= 1
                changed[name] = base64.b64encode(raw).decode("ascii")
            with self.assertRaises(InvalidSignature):
                decrypt_message(self.recipient, public(self.sender), changed)

    def test_no_plaintext_or_unknown_version_fallback(self):
        for changed in ({**self.message, "v": 0}, {**self.message, "extra": "plaintext"},
                        {**self.message, "v": True}, {**self.message, "body": "plaintext"}):
            with self.assertRaises(ValueError):
                decrypt_message(self.recipient, public(self.sender), changed)


if __name__ == "__main__":
    unittest.main()
