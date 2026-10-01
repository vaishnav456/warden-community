import copy
import inspect
import pathlib
import sys
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest import mock
from flask import Flask, g
from werkzeug.exceptions import NotFound

SERVER_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path: sys.path.insert(0, str(SERVER_DIR))
import db
from routes import endpoints
from services import bitlocker_status as status


class BitLockerLiveStatusTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
        self.endpoint = {"id": "device", "company_id": "tenant", "branch_id": "branch", "status": "online"}
        self.key = {"id": "key", "company_id": "tenant", "endpoint_id": "device",
                    "volume_mount": "C:", "protector_id": "{AE0802F2-7FC8-4049-A62D-7C4FD16627F8}",
                    "is_current": True, "last_reported_at": self.now.isoformat()}
        self.body = {"collected_at": self.now.isoformat(), "volumes": [{
            "mount_point": "C:", "protector_ids": [self.key["protector_id"]],
            "volume_status": "FullyEncrypted", "protection_status": "On", "encryption_percentage": 100}]}
        self.real_update = db.update_endpoint_recovery_status
        self.read = mock.patch.object(db, "get_endpoint_recovery_keys", return_value=[self.key]).start()
        self.update = mock.patch.object(db, "update_endpoint_recovery_status").start()
        self.addCleanup(mock.patch.stopall)

    def record(self):
        status.record_status(self.endpoint, self.body, now=self.now)

    def test_refresh_updates_metadata_only_without_reescrowing(self):
        with mock.patch.object(db, "escrow_endpoint_recovery_key") as escrow:
            self.record()
        self.update.assert_called_once_with("tenant", "device", "key", "FullyEncrypted", "On", 100, self.now.isoformat())
        escrow.assert_not_called()

    def test_wrong_tenant_endpoint_retired_and_unknown_protector_are_not_updated(self):
        for field, value in (("company_id", "other"), ("endpoint_id", "other"), ("is_current", False),
                             ("protector_id", "{00000000-0000-0000-0000-000000000000}")):
            with self.subTest(field=field):
                original = self.key[field]
                self.key[field] = value
                self.record()
                self.key[field] = original
        self.update.assert_not_called()

    def test_invalid_percentage_states_and_mounts_are_ignored(self):
        original = copy.deepcopy(self.body["volumes"][0])
        for field, value in (("encryption_percentage", -1), ("encryption_percentage", 101),
                             ("encryption_percentage", float("nan")), ("encryption_percentage", True),
                             ("volume_status", {}), ("volume_status", "unexpected"),
                             ("protection_status", []), ("mount_point", "../C:"),
                             ("protector_ids", "not-a-list")):
            with self.subTest(field=field):
                self.body["volumes"][0] = dict(original, **{field: value})
                self.record()
        self.update.assert_not_called()

    def test_absent_old_future_and_naive_timestamp_reports_are_ignored(self):
        for timestamp in (None, "invalid", "2026-10-01T12:00:00",
                          (self.now - timedelta(minutes=3)).isoformat(),
                          (self.now + timedelta(minutes=1)).isoformat()):
            self.body["collected_at"] = timestamp
            self.record()
        self.read.assert_not_called()
        self.update.assert_not_called()

    def test_patch_is_tenant_device_current_and_timestamp_fenced(self):
        with mock.patch.object(db, "_patch") as patch:
            self.real_update("tenant", "device", "key", "FullyEncrypted", "On", 100, self.now.isoformat())
        path, fields = patch.call_args.args
        for required in ("company_id=eq.tenant", "endpoint_id=eq.device", "is_current=eq.true", "last_reported_at=lt."):
            self.assertIn(required, path)
        self.assertEqual(set(fields), {"volume_status", "protection_status", "encryption_percentage", "last_reported_at"})

    def test_snapshot_label_is_used_for_offline_stale_or_retired_reading(self):
        now = datetime.now(timezone.utc)
        for case in ("fresh", "offline", "stale", "retired"):
            self.endpoint["status"] = "offline" if case == "offline" else "online"
            self.key["is_current"] = case != "retired"
            self.key["last_reported_at"] = (now - timedelta(minutes=3 if case == "stale" else 0)).isoformat()
            rows = status.display_status(self.endpoint)
            self.assertEqual(rows[0]["status_fresh"], case == "fresh")

    def test_display_filters_foreign_rows(self):
        self.key["company_id"] = "foreign"
        self.assertEqual(status.display_status(self.endpoint), [])

    def test_partial_is_scoped_no_store_and_does_not_reveal_password(self):
        app = Flask(__name__, template_folder=str(SERVER_DIR / "templates"))
        app.jinja_env.filters["timeago"] = lambda value: "just now"
        with mock.patch.object(db, "get_endpoint", return_value=self.endpoint), \
             mock.patch.object(endpoints, "require_branch_scope") as scope, \
             mock.patch.object(status, "display_status", return_value=[dict(self.key,
                 volume_status="FullyEncrypted", protection_status="On", encryption_percentage=100,
                 escrowed_at=self.now.isoformat(), status_fresh=True, recovery_password="SECRET")]), \
             app.test_request_context():
            g.company = {"id": "tenant"}
            app.context_processor(lambda: {"current_user": SimpleNamespace(role="company_admin"), "is_superadmin": False})
            response = inspect.unwrap(endpoints.bitlocker_status_partial)("device")
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertIn("FullyEncrypted", response.get_data(as_text=True))
        self.assertIn("Status reported", response.get_data(as_text=True))
        self.assertNotIn("SECRET", response.get_data(as_text=True))
        scope.assert_called_once_with("branch")

    def test_partial_rejects_foreign_tenant_before_reading_keys(self):
        app = Flask(__name__)
        with mock.patch.object(db, "get_endpoint", return_value=dict(self.endpoint, company_id="other")), app.test_request_context():
            g.company = {"id": "tenant"}
            with self.assertRaises(NotFound):
                inspect.unwrap(endpoints.bitlocker_status_partial)("device")
        self.read.assert_not_called()


if __name__ == "__main__": unittest.main()
