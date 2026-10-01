import json
import pathlib
import sys
import unittest
from unittest import mock
from flask import Flask, g

SERVER_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

import db
from routes import agent_api
from services.timezones import windows_timezone


class WindowsTimezoneTests(unittest.TestCase):
    def test_worldwide_regions_and_aliases(self):
        examples = {
            "Asia/Kolkata": "India Standard Time",
            "Asia/Calcutta": "India Standard Time",
            "Asia/Kathmandu": "Nepal Standard Time",
            "Asia/Tokyo": "Tokyo Standard Time",
            "America/New_York": "Eastern Standard Time",
            "America/Phoenix": "US Mountain Standard Time",
            "America/Sao_Paulo": "E. South America Standard Time",
            "Europe/London": "GMT Standard Time",
            "Europe/Kyiv": "FLE Standard Time",
            "Europe/Kiev": "FLE Standard Time",
            "Africa/Johannesburg": "South Africa Standard Time",
            "Australia/Sydney": "AUS Eastern Standard Time",
            "Pacific/Auckland": "New Zealand Standard Time",
            "Etc/UTC": "UTC", "UTC": "UTC",
        }
        for iana, windows in examples.items():
            with self.subTest(iana=iana):
                self.assertEqual(windows_timezone(iana), windows)

    def test_every_vendored_mapping_and_windows_id(self):
        data = json.loads((SERVER_DIR / "services/data/windows_timezones.json").read_text())
        self.assertGreater(len(data["iana_to_windows"]), 500)
        for iana, windows in data["iana_to_windows"].items():
            with self.subTest(iana=iana):
                self.assertEqual(windows_timezone(iana), windows)
                self.assertEqual(windows_timezone(windows), windows)

    def test_existing_windows_ids_and_whitespace(self):
        self.assertEqual(windows_timezone(" India Standard Time "), "India Standard Time")
        self.assertEqual(windows_timezone("india standard time"), "India Standard Time")
        self.assertEqual(windows_timezone(" Asia/Kolkata "), "India Standard Time")

    def test_unknown_or_invalid_timezone_never_becomes_utc(self):
        for value in (None, 123, {}, "", " ", "Mars/Olympus", "Asia/Unknown",
                      "UTC\\n/s", "UTC\\x00", "UTC & shutdown", "x" * 256):
            with self.subTest(value=value):
                self.assertIsNone(windows_timezone(value))

    def heartbeat(self, timezone, platform="windows", branch=True, os_name=None):
        endpoint = {"id": "device-a", "company_id": "company-a",
                    "branch_id": "branch-a" if branch else None, "os_name": os_name}
        app = Flask(__name__)
        with mock.patch.object(db, "update_endpoint_heartbeat"), \
             mock.patch.object(db, "get_open_alert", return_value=None), \
             mock.patch.object(db, "get_company_by_id", return_value={"id": "company-a"}), \
             mock.patch.object(db, "get_branch", return_value={"timezone": timezone}) as get_branch, \
             app.test_request_context("/api/agent/heartbeat", method="POST",
                                      json={"platform": platform, "job_capacity": 0}):
            g.endpoint = endpoint
            result = agent_api.heartbeat.__wrapped__().get_json()
        return result, get_branch

    def test_windows_heartbeat_translates_iana_without_changing_database(self):
        for zone in ("Asia/Kolkata", "Asia/Calcutta", "America/New_York",
                     "Europe/London", "Australia/Sydney", "Pacific/Auckland"):
            with self.subTest(zone=zone):
                response, branch = self.heartbeat(zone)
                self.assertTrue(response["ok"])
                self.assertEqual(response["branch_timezone"], windows_timezone(zone))
                branch.assert_called_once_with("branch-a")

    def test_unknown_zone_keeps_heartbeat_healthy_and_preserves_device_timezone(self):
        response, _ = self.heartbeat("Asia/Unknown")
        self.assertTrue(response["ok"])
        self.assertIsNone(response["branch_timezone"])

    def test_non_windows_agents_do_not_receive_windows_timezone(self):
        for platform in ("linux", "darwin"):
            response, _ = self.heartbeat("Asia/Kolkata", platform=platform)
            self.assertIsNone(response["branch_timezone"])

    def test_legacy_windows_detection_and_missing_branch(self):
        response, _ = self.heartbeat("Asia/Kolkata", platform="", os_name="Windows 11 Pro")
        self.assertEqual(response["branch_timezone"], "India Standard Time")
        response, branch = self.heartbeat("Asia/Kolkata", branch=False)
        self.assertEqual(response["branch_timezone"], "UTC")
        branch.assert_not_called()

    def test_missing_branch_timezone_keeps_existing_utc_default(self):
        response, _ = self.heartbeat(None)
        self.assertEqual(response["branch_timezone"], "UTC")


if __name__ == "__main__":
    unittest.main()
