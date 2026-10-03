import json
from pathlib import Path
import tempfile
import unittest

from notices import agent_notice_bundle


class NoticeFixture:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.license = self.root / "third_party/licenses/go/example/LICENSE"
        self.license.parent.mkdir(parents=True)
        self.license.write_text("Copyright Example\nPermission is granted.\n" * 2)
        (self.root / "THIRD_PARTY_NOTICES.md").write_text("Dependency credits and release obligations.\n")
        self.go = self.root / "GO_LICENSE"
        self.go.write_text("Copyright Go Authors. BSD license text.\n")
        self.inventory = self.root / "third_party/inventory.json"
        self.set_path("third_party/licenses/go/example/LICENSE")

    def set_path(self, path):
        self.inventory.write_text(json.dumps({"dependencies": [dict(ecosystem="go", name="example",
            version="v1.0.0", license_files=[dict(path=path)])]}))


class NoticeTests(NoticeFixture, unittest.TestCase):
    def test_bundle_contains_credits_dependency_and_standard_library(self):
        result = agent_notice_bundle(self.root, self.go)
        self.assertEqual(set(result), {"THIRD_PARTY_NOTICES.md", "THIRD_PARTY_LICENSES.txt"})
        self.assertIn(b"Copyright Example", result["THIRD_PARTY_LICENSES.txt"])
        self.assertIn(b"Go Authors", result["THIRD_PARTY_LICENSES.txt"])

    def test_missing_license_fails_instead_of_shipping_partial_notices(self):
        self.license.unlink()
        with self.assertRaises(FileNotFoundError):
            agent_notice_bundle(self.root, self.go)

    def test_path_escape_fails(self):
        self.set_path("third_party/licenses/go/../../../../outside.txt")
        with self.assertRaises((ValueError, FileNotFoundError)):
            agent_notice_bundle(self.root, self.go)

    def test_empty_license_fails(self):
        self.license.write_bytes(b"")
        with self.assertRaises(ValueError):
            agent_notice_bundle(self.root, self.go)

    def test_wrong_ecosystem_directory_fails(self):
        self.set_path("third_party/licenses/python/example/LICENSE")
        with self.assertRaises(ValueError):
            agent_notice_bundle(self.root, self.go)


if __name__ == "__main__":
    unittest.main()
