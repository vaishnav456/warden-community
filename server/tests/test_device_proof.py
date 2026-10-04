import base64
import datetime
import unittest
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from services.device_proof import (verify_device_signature, heartbeat_proof_message,
                                   validate_renewal_identity, certificate_fingerprint_matches)


class DeviceProofTests(unittest.TestCase):
    def setUp(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-device")])
        now = datetime.datetime.now(datetime.timezone.utc)
        self.cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(self.key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-datetime.timedelta(minutes=1))
            .not_valid_after(now+datetime.timedelta(days=1)).sign(self.key, hashes.SHA256()))
        self.pem = self.cert.public_bytes(serialization.Encoding.PEM).decode()
        self.endpoint = {"client_cert_fingerprint": self.cert.fingerprint(hashes.SHA256()).hex()}

    def signature(self, message):
        return base64.b64encode(self.key.sign(message, padding.PKCS1v15(), hashes.SHA256())).decode()

    def test_pinned_device_key_and_message_binding(self):
        message = b"endpoint-and-ciphertext-bound-message"
        verify_device_signature(self.endpoint, self.pem, self.signature(message), message)
        for endpoint, payload in (({"client_cert_fingerprint": "00"*32}, message),
                                   (self.endpoint, message+b"changed")):
            with self.assertRaises(Exception):
                verify_device_signature(endpoint, self.pem, self.signature(message), payload)

    def test_missing_or_malformed_proof_is_rejected(self):
        for certificate, signature in ((None, None), ("invalid", "!"), (self.pem, "!")):
            with self.assertRaises(Exception):
                verify_device_signature(self.endpoint, certificate, signature, b"message")

    def test_ciphertext_proof_changes_with_every_envelope_component(self):
        envelope = dict(ephemeral_key="key", nonce="nonce", ciphertext="cipher")
        original = heartbeat_proof_message(envelope, b"context")
        for field in envelope:
            changed = dict(envelope, **{field: "different"})
            self.assertNotEqual(original, heartbeat_proof_message(changed, b"context"))
        self.assertNotEqual(original, heartbeat_proof_message(envelope, b"other-endpoint"))

    def test_renewal_requires_possession_of_existing_key(self):
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "renewal")])
        csr = x509.CertificateSigningRequestBuilder().subject_name(name).sign(self.key, hashes.SHA256())
        validate_renewal_identity(self.endpoint, self.pem, csr.public_bytes(serialization.Encoding.PEM).decode())
        attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = x509.CertificateSigningRequestBuilder().subject_name(name).sign(attacker, hashes.SHA256())
        with self.assertRaises(ValueError):
            validate_renewal_identity(self.endpoint, self.pem, csr.public_bytes(serialization.Encoding.PEM).decode())
        with self.assertRaises(ValueError):
            validate_renewal_identity(self.endpoint, None, "invalid")

    def test_previous_certificate_grace_is_bounded_and_revocable(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        fingerprint = self.endpoint["client_cert_fingerprint"]
        endpoint = dict(client_cert_fingerprint="00" * 32,
                        previous_client_cert_fingerprint=fingerprint,
                        previous_client_cert_expires_at=(now+datetime.timedelta(hours=1)).isoformat())
        self.assertTrue(certificate_fingerprint_matches(endpoint, fingerprint, now=now))
        self.assertFalse(certificate_fingerprint_matches(endpoint, fingerprint, now=now+datetime.timedelta(hours=2)))
        endpoint["previous_client_cert_expires_at"] = "invalid"
        self.assertFalse(certificate_fingerprint_matches(endpoint, fingerprint, now=now))
