import base64
import hashlib
import inspect
import io
import json
import pathlib
import sys
import tarfile
import tempfile
import unittest
import zipfile
from unittest import mock
from urllib.parse import parse_qs, urlparse

from flask import Flask, g
from werkzeug.exceptions import Forbidden


SERVER_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from routes import home


class HomeBootstrapPackageTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.secret_key = "test-only"
        self.node_key = "one-time-node-key"
        self.encryption_key = base64.b64encode(b"k" * 32).decode()
        self.node = {
            "id": "node-a",
            "company_id": "tenant-a",
            "node_key_hash": hashlib.sha256(self.node_key.encode()).hexdigest(),
            "deployment_mode": "p2p",
            "storage_cluster_id": "",
        }
        self.download = inspect.unwrap(home.download_home_node_bootstrap_package)
        self.generic_download = inspect.unwrap(home.download_home_node)
        self.reset_bootstrap = inspect.unwrap(home.reset_node_bootstrap)

    def _request_package(self, directory, platform):
        storage_root = "D:/WardenHome" if platform == "windows" else "/srv/warden-home"
        with self.app.test_request_context(
            f"/storage/nodes/node-a/bootstrap-package/{platform}",
            method="POST",
            data={"node_key": self.node_key, "encryption_key": self.encryption_key,
                  "storage_root": storage_root},
        ):
            g.company = {"id": "tenant-a"}
            with mock.patch.object(home.db, "get_home_nodes", return_value=[self.node]), \
                    mock.patch.object(home.config, "HOME_NODE_DIST_DIR", pathlib.Path(directory)), \
                    mock.patch.object(home.config, "SERVER_URL", "https://warden.example"), \
                    mock.patch.object(home, "get_server_pubkey_b64", return_value="signing-key"):
                return self.download("node-a", platform)

    def test_windows_zip_contains_binary_config_and_instructions(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = pathlib.Path(directory) / "warden-home-node-windows-amd64.exe"
            binary.write_bytes(b"windows-binary")
            response = self._request_package(directory, "windows")
            response.direct_passthrough = False
            with zipfile.ZipFile(io.BytesIO(response.get_data())) as archive:
                self.assertEqual(
                    set(archive.namelist()),
                    {"warden-home-node-windows-amd64.exe", "warden-home.json", "INSTALL.txt"},
                )
                config = json.loads(archive.read("warden-home.json"))
                self.assertEqual(config["node_key"], self.node_key)
                self.assertEqual(config["warden_url"], "https://warden.example")
                self.assertEqual(config["root"], "D:/WardenHome")
                install = archive.read("INSTALL.txt").decode()
                self.assertIn("Unblock-File", install)
                self.assertIn("Get-Service WardenHomeNode", install)
                self.assertIn("starts automatically after reboot", install)
            self.assertEqual(response.headers["Cache-Control"], "private, no-store")

    def test_generic_windows_download_is_a_zip_not_a_raw_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = pathlib.Path(directory) / "warden-home-node-windows-amd64.exe"
            binary.write_bytes(b"windows-binary")
            with self.app.test_request_context("/storage/download/windows"):
                with mock.patch.object(home.config, "HOME_NODE_DIST_DIR", pathlib.Path(directory)), \
                        mock.patch.object(home.config, "SERVER_URL", "https://warden.example"), \
                        mock.patch.object(home, "get_server_pubkey_b64", return_value="signing-key"):
                    response = self.generic_download("windows")
            response.direct_passthrough = False
            self.assertIn(
                "warden-home-node-windows-amd64.zip",
                response.headers["Content-Disposition"],
            )
            with zipfile.ZipFile(io.BytesIO(response.get_data())) as archive:
                self.assertEqual(
                    set(archive.namelist()),
                    {
                        "warden-home-node-windows-amd64.exe",
                        "warden-home.example.json",
                        "INSTALL.txt",
                    },
                )
                example = json.loads(archive.read("warden-home.example.json"))
                self.assertEqual(example["warden_url"], "https://warden.example")
                self.assertEqual(example["node_id"], "REPLACE_WITH_NODE_ID")
                self.assertEqual(example["root"], "REPLACE_WITH_STORAGE_ROOT")

    def test_windows_package_rejects_system_drive_storage(self):
        with tempfile.TemporaryDirectory() as directory:
            (pathlib.Path(directory) / "warden-home-node-windows-amd64.exe").write_bytes(b"x")
            with self.app.test_request_context(
                "/storage/nodes/node-a/bootstrap-package/windows",
                method="POST",
                data={"node_key": self.node_key, "encryption_key": self.encryption_key,
                      "storage_root": "C:/WardenHome"},
            ):
                g.company = {"id": "tenant-a"}
                with mock.patch.object(home.db, "get_home_nodes", return_value=[self.node]), \
                        mock.patch.object(home.config, "HOME_NODE_DIST_DIR", pathlib.Path(directory)):
                    with self.assertRaises(Exception) as raised:
                        self.download("node-a", "windows")
            self.assertEqual(getattr(raised.exception, "code", None), 400)

    def test_linux_archive_marks_binary_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = pathlib.Path(directory) / "warden-home-node-linux-amd64"
            binary.write_bytes(b"linux-binary")
            response = self._request_package(directory, "linux")
            response.direct_passthrough = False
            with tarfile.open(fileobj=io.BytesIO(response.get_data()), mode="r:gz") as archive:
                names = {member.name for member in archive.getmembers()}
                self.assertEqual(
                    names,
                    {"warden-home-node-linux-amd64", "warden-home.json", "INSTALL.txt"},
                )
                self.assertEqual(
                    archive.getmember("warden-home-node-linux-amd64").mode, 0o755,
                )
                config = json.load(archive.extractfile("warden-home.json"))
                self.assertEqual(config["root"], "/srv/warden-home")

    def test_package_rejects_a_wrong_one_time_node_key(self):
        with tempfile.TemporaryDirectory() as directory:
            (pathlib.Path(directory) / "warden-home-node-windows-amd64.exe").write_bytes(b"x")
            with self.app.test_request_context(
                "/storage/nodes/node-a/bootstrap-package/windows",
                method="POST",
                data={"node_key": "wrong", "encryption_key": self.encryption_key},
            ):
                g.company = {"id": "tenant-a"}
                with mock.patch.object(home.db, "get_home_nodes", return_value=[self.node]), \
                        mock.patch.object(home.config, "HOME_NODE_DIST_DIR", pathlib.Path(directory)):
                    with self.assertRaises(Forbidden):
                        self.download("node-a", "windows")

    def test_never_connected_node_can_regenerate_complete_setup(self):
        self.node["last_seen"] = None
        with self.app.test_request_context(
            "/storage/nodes/node-a/reset-bootstrap", method="POST",
        ):
            g.company = {"id": "tenant-a"}
            g.admin = {"id": "admin-a"}
            with mock.patch.object(home.db, "get_home_nodes", return_value=[self.node]), \
                    mock.patch.object(home.db, "update_home_node") as update, \
                    mock.patch.object(home.db, "audit"), \
                    mock.patch.object(home, "_bootstrap_redirect", side_effect=lambda payload: payload):
                result = self.reset_bootstrap("node-a")
        self.assertEqual(len(base64.b64decode(result["encryption_key"])), 32)
        self.assertEqual(result["node"]["id"], "node-a")
        self.assertTrue(result["key"])
        self.assertEqual(update.call_args.args[0:2], ("node-a", "tenant-a"))

    def test_connected_node_cannot_replace_encryption_key(self):
        self.node["last_seen"] = "2026-09-28T10:00:00Z"
        with self.app.test_request_context(
            "/storage/nodes/node-a/reset-bootstrap", method="POST",
        ):
            g.company = {"id": "tenant-a"}
            g.admin = {"id": "admin-a"}
            with mock.patch.object(home.db, "get_home_nodes", return_value=[self.node]):
                with self.assertRaises(Exception) as raised:
                    self.reset_bootstrap("node-a")
        self.assertEqual(getattr(raised.exception, "code", None), 409)

    def test_bootstrap_handoff_redirect_is_get_only_and_single_use(self):
        payload = {"node": self.node, "key": self.node_key,
                   "encryption_key": self.encryption_key}
        with self.app.test_request_context("/storage/nodes", method="POST"):
            g.company = {"id": "tenant-a"}
            g.admin = {"id": "admin-a"}
            with mock.patch.object(home, "url_for", return_value="/storage?bootstrap=token-placeholder"):
                # Exercise the real token creation while keeping the endpoint
                # independent from blueprint registration in this unit app.
                with mock.patch.object(home, "url_for", side_effect=lambda endpoint, **values: f"/storage?bootstrap={values['bootstrap']}"):
                    response = home._bootstrap_redirect(payload)
        self.assertEqual(response.status_code, 303)
        token = parse_qs(urlparse(response.location).query)["bootstrap"][0]
        with self.app.test_request_context(f"/storage?bootstrap={token}"):
            g.company = {"id": "tenant-a"}
            g.admin = {"id": "admin-a"}
            self.assertEqual(home._consume_bootstrap_handoff(), payload)
        with self.app.test_request_context(f"/storage?bootstrap={token}"):
            g.company = {"id": "tenant-a"}
            g.admin = {"id": "admin-a"}
            self.assertIsNone(home._consume_bootstrap_handoff())


if __name__ == "__main__":
    unittest.main()
