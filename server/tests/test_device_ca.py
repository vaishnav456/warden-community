import pathlib
import shutil
import sys
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID


SERVER_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

import config
from services.agent_ca import ca_bundle_pem, sign_agent_csr, sign_home_node_csr


def make_csr(common_name):
    key = ec.generate_private_key(ec.SECP256R1())
    request = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)]))
               .sign(key, hashes.SHA256()))
    return key, request.public_bytes(serialization.Encoding.PEM).decode()


class DeviceCATests(unittest.TestCase):
    def setUp(self):
        test_tmp = SERVER_DIR.parent / "tmp"
        test_tmp.mkdir(exist_ok=True)
        self.directory = test_tmp / f"device-ca-test-{uuid.uuid4().hex}"
        self.directory.mkdir()
        self.ca_dir = patch.object(config, "DEVICE_CA_DIR", self.directory)
        self.bootstrap = patch.object(config, "DEVICE_CA_AUTO_BOOTSTRAP", True)
        self.validity = patch.object(config, "DEVICE_CERT_VALIDITY_DAYS", 7)
        self.clock_skew = patch.object(config, "DEVICE_CERT_CLOCK_SKEW_HOURS", 24)
        self.ca_dir.start()
        self.bootstrap.start()
        self.validity.start()
        self.clock_skew.start()

    def tearDown(self):
        self.clock_skew.stop()
        self.validity.stop()
        self.bootstrap.stop()
        self.ca_dir.stop()
        shutil.rmtree(self.directory)

    def test_endpoint_certificate_has_organization_bound_spiffe_identity(self):
        key, csr = make_csr("untrusted-request-name")
        chain, fingerprint, reference = sign_agent_csr(
            csr, "endpoint-a", company_id="tenant-a",
        )
        leaf = x509.load_pem_x509_certificate(chain.encode())
        self.assertEqual(leaf.fingerprint(hashes.SHA256()).hex(), fingerprint)
        self.assertTrue(reference.startswith("local:"))
        self.assertEqual(
            [uri.value for uri in leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
             if isinstance(uri, x509.UniformResourceIdentifier)],
            ["spiffe://warden/endpoint/tenant-a/endpoint-a"],
        )
        self.assertEqual(leaf.public_key().public_numbers(), key.public_key().public_numbers())
        self.assertLessEqual(
            leaf.not_valid_before_utc,
            datetime.now(timezone.utc) - timedelta(hours=23, minutes=59),
        )

    def test_home_certificate_uses_only_registered_url_names(self):
        _, csr = make_csr("attacker.example")
        chain, _, _, _ = sign_home_node_csr(csr, {
            "id": "node-a", "company_id": "tenant-a",
            "local_url": "https://10.20.30.40:9443",
            "public_url": "https://files.example.com:9443",
        })
        leaf = x509.load_pem_x509_certificate(chain.encode())
        sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertIn("files.example.com", sans.get_values_for_type(x509.DNSName))
        self.assertEqual([str(v) for v in sans.get_values_for_type(x509.IPAddress)], ["10.20.30.40"])
        usages = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        self.assertIn(ExtendedKeyUsageOID.SERVER_AUTH, usages)
        self.assertIn(ExtendedKeyUsageOID.CLIENT_AUTH, usages)
        self.assertNotIn("attacker.example", sans.get_values_for_type(x509.DNSName))

    def test_root_key_can_be_taken_offline_after_bootstrap(self):
        _, csr = make_csr("endpoint")
        sign_agent_csr(csr, "endpoint-a", company_id="tenant-a")
        pathlib.Path(self.directory, "root-ca.key.pem").unlink()
        _, second_csr = make_csr("endpoint")
        sign_agent_csr(second_csr, "endpoint-b", company_id="tenant-a")
        self.assertIn("BEGIN CERTIFICATE", ca_bundle_pem())


if __name__ == "__main__":
    unittest.main()
