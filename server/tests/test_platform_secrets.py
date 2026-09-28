import base64
import pathlib
import sys
import unittest
from unittest import mock


SERVER_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from services import platform_secrets


class PlatformSecretTests(unittest.TestCase):
    def setUp(self):
        self.key = base64.b64encode(b"k" * 32).decode()
        self.patch = mock.patch.object(platform_secrets.config, "TENANT_MASTER_KEK_B64", self.key)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()

    def test_mfa_secret_is_authenticated_and_bound_to_admin(self):
        encrypted = platform_secrets.encrypt_mfa_secret("admin-1", "JBSWY3DPEHPK3PXP")
        self.assertTrue(encrypted.startswith("enc:v1:"))
        self.assertNotIn("JBSWY3DPEHPK3PXP", encrypted)
        self.assertEqual(
            platform_secrets.decrypt_mfa_secret("admin-1", encrypted),
            "JBSWY3DPEHPK3PXP",
        )
        with self.assertRaises(Exception):
            platform_secrets.decrypt_mfa_secret("admin-2", encrypted)

    def test_backup_codes_are_one_way_and_constant_time_verifiable(self):
        stored = platform_secrets.hash_backup_code("RECOVERY123")
        self.assertTrue(stored.startswith("h1:"))
        self.assertNotIn("RECOVERY123", stored)
        self.assertTrue(platform_secrets.backup_code_matches("RECOVERY123", stored))
        self.assertFalse(platform_secrets.backup_code_matches("WRONG", stored))


if __name__ == "__main__":
    unittest.main()
