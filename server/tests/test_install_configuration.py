import argparse
import base64
import hashlib
import hmac
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "configure_install", ROOT / "tools" / "configure_install.py"
)
configure_install = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(configure_install)


class InstallConfigurationTests(unittest.TestCase):
    def _root(self):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        (root / "server").mkdir()
        (root / "build-service").mkdir()
        (root / "db-init").mkdir()
        for relative in (
            ".env.example",
            "server/.env.example",
            "build-service/.env.example",
            "db-init/01-roles.sql.example",
            "db-init/04-bootstrap-admin.sql.example",
        ):
            shutil.copy2(ROOT / relative, root / relative)
        return temporary, root

    @staticmethod
    def _args(**updates):
        values = {
            "server_url": "https://warden.example.test",
            "organization_name": "Example Ltd",
            "organization_slug": "example",
            "admin_email": "admin@example.test",
            "admin_name": "Administrator",
            "brand_name": "Example Control",
            "force": False,
        }
        values.update(updates)
        return argparse.Namespace(**values)

    def test_service_role_token_is_a_valid_local_hs256_jwt(self):
        secret = "local-secret"
        token = configure_install.service_role_jwt(secret)
        header, payload, signature = token.split(".")
        decoded = json.loads(base64.urlsafe_b64decode(payload + "=="))
        expected = base64.urlsafe_b64encode(
            hmac.new(secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
        ).rstrip(b"=").decode()
        self.assertEqual(decoded, {"role": "service_role"})
        self.assertEqual(signature, expected)

    def test_generate_writes_local_postgrest_and_single_org_bootstrap(self):
        temporary, root = self._root()
        self.addCleanup(temporary.cleanup)
        outputs = configure_install.generate(root, self._args(), "LongEnoughPassword!123")
        self.assertEqual(len(outputs), 5)
        server_env = (root / "server/.env").read_text()
        bootstrap = (root / "db-init/04-bootstrap-admin.sql").read_text()
        self.assertIn("SUPABASE_URL=http://postgrest:3000", server_env)
        self.assertIn("SERVER_URL=https://warden.example.test", server_env)
        self.assertIn("DEVICE_CA_AUTO_BOOTSTRAP=true", server_env)
        self.assertIn("'example', 'Example Ltd'", bootstrap)
        self.assertIn("'admin@example.test'", bootstrap)
        self.assertNotIn("change-me", "\n".join(path.read_text() for path in outputs))

    def test_existing_file_prevents_all_writes(self):
        temporary, root = self._root()
        self.addCleanup(temporary.cleanup)
        (root / "server/.env").write_text("keep-me")
        with self.assertRaises(FileExistsError):
            configure_install.generate(root, self._args(), "LongEnoughPassword!123")
        self.assertEqual((root / "server/.env").read_text(), "keep-me")
        self.assertFalse((root / ".env").exists())

    def test_rejects_multiline_values_and_url_paths(self):
        temporary, root = self._root()
        self.addCleanup(temporary.cleanup)
        with self.assertRaises(ValueError):
            configure_install.generate(
                root, self._args(organization_name="Bad\nINJECTED=value"), "LongEnoughPassword!123"
            )
        with self.assertRaises(ValueError):
            configure_install.generate(
                root, self._args(server_url="https://warden.example.test/path"), "LongEnoughPassword!123"
            )


if __name__ == "__main__":
    unittest.main()
