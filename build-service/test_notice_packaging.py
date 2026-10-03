"""Packaging contracts without signing, enrollment, a database or device jobs."""
import importlib.util
from pathlib import Path
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

from test_notices import NoticeFixture


class PackagingTests(NoticeFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.output = self.root / "output"
        self.output.mkdir()
        self.exe = self.root / "agent.exe"
        self.exe.write_bytes(b"test binary; not executable")
        self.cfg = self.root / "config.json"
        self.cfg.write_text("{}")
        self.provider = self.root / "provider.dll"
        self.provider.write_bytes(b"test provider; not executable")
        config = ModuleType("config")
        config.OUTPUT_DIR = self.output
        config.NOTICE_SOURCE_DIR = self.root
        config.GO_LICENSE_PATH = self.go
        config.AGENT_DISPLAY_NAME = "Warden Agent"
        config.AGENT_MANUFACTURER = "Warden"
        modules = dict(config=config, db=ModuleType("db"), requests=ModuleType("requests"))
        spec = importlib.util.spec_from_file_location("notice_test_builder", Path(__file__).with_name("builder.py"))
        self.builder = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, modules):
            spec.loader.exec_module(self.builder)
        self.request = dict(config_json=dict(company_slug="fixture", branch_slug="lab"))

    def test_windows_and_posix_zips_include_notices(self):
        for target in ("windows-amd64", "linux-amd64", "darwin-arm64"):
            self.request["target_platform"] = target
            artifact = self.builder.package_zip(self.request, self.exe, self.cfg, self.provider)
            with zipfile.ZipFile(artifact) as archive:
                self.assertIn("THIRD_PARTY_NOTICES.md", archive.namelist())
                self.assertIn(b"Copyright Example", archive.read("THIRD_PARTY_LICENSES.txt"))
                self.assertIn(b"Go Authors", archive.read("THIRD_PARTY_LICENSES.txt"))

    def test_msi_stages_and_references_both_notice_files(self):
        def compile_msi(cmd, **kwargs):
            xml = (self.root / "warden-agent.wxs").read_text()
            stage = Path(kwargs["cwd"])
            for name in ("THIRD_PARTY_NOTICES.md", "THIRD_PARTY_LICENSES.txt"):
                self.assertIn('Source="' + name + '"', xml)
                self.assertTrue((stage / name).is_file())
            Path(cmd[cmd.index("-o") + 1]).write_bytes(b"fixture MSI")
            return SimpleNamespace(returncode=0)
        with patch.object(self.builder.subprocess, "run", side_effect=compile_msi):
            artifact = self.builder.build_msi(self.request, self.exe, self.cfg, "2.6.58", self.root, self.provider)
        self.assertTrue(artifact.is_file())

    def test_missing_notices_cannot_publish_an_agent_zip(self):
        self.license.unlink()
        with self.assertRaises(FileNotFoundError):
            self.builder.package_zip(self.request, self.exe, self.cfg, self.provider)
        self.assertEqual(list(self.output.glob("*.zip")), [])


if __name__ == "__main__":
    unittest.main()
