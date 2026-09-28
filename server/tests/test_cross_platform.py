import unittest

import db
from routes.endpoints import _endpoint_capabilities, _remote_session_capabilities, _valid_remote_user_path


class CrossPlatformTests(unittest.TestCase):
    def test_legacy_windows_agent_keeps_windows_capabilities(self):
        caps = _endpoint_capabilities({"platform": "windows", "capabilities": []})
        self.assertIn("PUSH_LOCAL_POLICY", caps)
        self.assertIn("SETUP_REMOTE_ACCESS", caps)

    def test_reported_capabilities_are_authoritative(self):
        caps = _endpoint_capabilities({
            "platform": "linux",
            "capabilities": ["COLLECT_SYSINFO", "SETUP_REMOTE_ACCESS"],
        })
        self.assertEqual(caps, {"COLLECT_SYSINFO", "SETUP_REMOTE_ACCESS"})
        self.assertNotIn("PUSH_LOCAL_POLICY", caps)

    def test_remote_session_removes_unavailable_posix_controls(self):
        caps = _remote_session_capabilities("full_control", "company_admin", {
            "platform": "linux",
            "capability_details": {
                "remote_input": False,
                "remote_clipboard": False,
                "remote_process_manager": True,
            },
        })
        self.assertTrue(caps["view"])
        self.assertFalse(caps["control"])
        self.assertFalse(caps["clipboard"])
        self.assertTrue(caps["process_manager"])

    def test_platform_specific_build_target_normalizes_architecture(self):
        self.assertEqual(db.endpoint_target_platform({"platform": "linux", "arch": "x86_64"}), "linux-amd64")
        self.assertEqual(db.endpoint_target_platform({"platform": "darwin", "arch": "arm64"}), "darwin-arm64")
        self.assertEqual(db.endpoint_target_platform({"platform": "windows", "arch": "ARM64"}), "windows-amd64")

    def test_remote_file_paths_follow_endpoint_platform(self):
        self.assertTrue(_valid_remote_user_path({"platform": "linux"}, "/home/alex/Documents/report.pdf"))
        self.assertTrue(_valid_remote_user_path({"platform": "darwin"}, "/Users/alex/Desktop/demo.txt"))
        self.assertTrue(_valid_remote_user_path({"platform": "darwin"}, "/Users/Shared/demo.txt"))
        self.assertTrue(_valid_remote_user_path({"platform": "windows"}, r"C:\Users\alex\Downloads\demo.txt"))
        self.assertFalse(_valid_remote_user_path({"platform": "linux"}, "/etc/shadow"))
        self.assertFalse(_valid_remote_user_path({"platform": "darwin"}, "/Library/Keychains/System.keychain"))


if __name__ == "__main__":
    unittest.main()
