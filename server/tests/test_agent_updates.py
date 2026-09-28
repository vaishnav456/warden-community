import hashlib
import pathlib
import sys
import tempfile
import unittest
import zipfile
from unittest import mock


SERVER_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from services import agent_updates


class AgentUpdateArtifactTests(unittest.TestCase):
    def _build_archive(self, root, build_id="build-1"):
        directory = pathlib.Path(root) / build_id
        directory.mkdir(parents=True)
        with zipfile.ZipFile(directory / "agent-installer.zip", "w") as archive:
            archive.writestr("warden-agent.exe", b"agent-binary")
            archive.writestr("WardenCredentialProvider.dll", b"signed-provider")

    def test_windows_payload_is_build_pinned_and_includes_provider(self):
        with tempfile.TemporaryDirectory() as temp:
            self._build_archive(temp)
            build = {
                "id": "build-1", "status": "completed",
                "target_platform": "windows-amd64", "agent_version": "2.5.1",
                "sha256": hashlib.sha256(b"agent-binary").hexdigest(),
            }
            with mock.patch.object(agent_updates.config, "AGENT_DIST_DIR", pathlib.Path(temp)), \
                    mock.patch.object(agent_updates.config, "SERVER_URL", "https://warden.example/"), \
                    mock.patch.object(agent_updates.db, "endpoint_target_platform", return_value="windows-amd64"), \
                    mock.patch.object(agent_updates.db, "get_latest_completed_build", return_value=build):
                payload = agent_updates.update_payload({"id": "endpoint-1"})
            self.assertEqual(payload["version"], "2.5.1")
            self.assertEqual(
                payload["download_url"],
                "https://warden.example/api/agent/builds/build-1/agent",
            )
            self.assertEqual(
                payload["credential_provider_url"],
                "https://warden.example/api/agent/builds/build-1/credential-provider",
            )
            self.assertEqual(
                payload["credential_provider_sha256"],
                hashlib.sha256(b"signed-provider").hexdigest(),
            )

    def test_build_download_rejects_cross_platform_endpoint(self):
        build = {"id": "build-1", "status": "completed", "target_platform": "windows-amd64"}
        with mock.patch.object(agent_updates.db, "get_build_request", return_value=build), \
                mock.patch.object(agent_updates.db, "endpoint_target_platform", return_value="linux-amd64"):
            with self.assertRaises(agent_updates.AgentBuildUnavailable):
                agent_updates.build_for_endpoint("build-1", {"id": "endpoint-1"})

    def test_missing_provider_fails_update_payload_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = pathlib.Path(temp) / "build-1"
            directory.mkdir(parents=True)
            with zipfile.ZipFile(directory / "agent-installer.zip", "w") as archive:
                archive.writestr("warden-agent.exe", b"agent-binary")
            build = {
                "id": "build-1", "status": "completed",
                "target_platform": "windows-amd64", "agent_version": "2.5.1",
                "sha256": hashlib.sha256(b"agent-binary").hexdigest(),
            }
            with mock.patch.object(agent_updates.config, "AGENT_DIST_DIR", pathlib.Path(temp)), \
                    mock.patch.object(agent_updates.db, "endpoint_target_platform", return_value="windows-amd64"), \
                    mock.patch.object(agent_updates.db, "get_latest_completed_build", return_value=build):
                with self.assertRaises(agent_updates.AgentBuildUnavailable):
                    agent_updates.update_payload({"id": "endpoint-1"})


if __name__ == "__main__":
    unittest.main()
