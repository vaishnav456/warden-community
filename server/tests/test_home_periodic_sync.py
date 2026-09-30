import pathlib
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock
from flask import Flask, g


SERVER_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

import db
from routes import agent_api
from services import home_sync


class HomePeriodicSyncTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)
        self.endpoint = {
            "id": "171e3fc0-169e-4b4a-8d96-c4c2febd4964",
            "company_id": "company-a", "branch_id": "branch-a",
            "platform": "windows", "interactive_user": r"DESKTOP\alice",
        }
        self.assignment = {
            "id": "assignment-a", "company_id": "company-a", "space_id": "space-a",
            "scope_type": "endpoint", "scope_value": self.endpoint["id"], "enabled": True,
        }
        self.space = {
            "id": "space-a", "company_id": "company-a", "enabled": True,
            "home_space_nodes": [{"home_storage_nodes": {
                "id": "node-a", "company_id": "company-a", "status": "online",
            }}],
        }
        self.jobs = self.patch("get_endpoint_home_sync_jobs", [])
        self.identity = self.patch("get_warden_identity_for_login", None)
        self.assignments = self.patch("get_home_assignments", [self.assignment])
        self.spaces = self.patch("get_home_spaces", [self.space])
        self.create = self.patch("create_system_job_once", {"id": "sync-job"})

    def patch(self, name, value):
        patcher = mock.patch.object(db, name, return_value=value)
        self.addCleanup(patcher.stop)
        return patcher.start()

    def sync(self, **kwargs):
        kwargs.setdefault("capabilities", ["SYNC_WARDEN_HOME"])
        kwargs.setdefault("now", self.now)
        return home_sync.queue_periodic_home_sync(self.endpoint, self.endpoint["interactive_user"], **kwargs)

    def job(self, status, age=300):
        return {
            "status": status,
            "created_at": (self.now - timedelta(hours=1)).isoformat(),
            "completed_at": (self.now - timedelta(seconds=age)).isoformat(),
        }

    def managed(self, status="active", **kwargs):
        return {
            "id": "identity-a", "company_id": "company-a", "username": "alice", "is_enabled": True,
            "warden_identity_assignments": [{"endpoint_id": self.endpoint["id"], "status": status}],
            **kwargs,
        }

    def test_unchanged_signed_in_user_is_synced_after_five_minutes(self):
        self.jobs.return_value = [self.job("completed", age=300)]
        self.assertEqual(self.sync(), {"id": "sync-job"})
        self.create.assert_called_once_with(
            "company-a", "branch-a", self.endpoint["id"], "SYNC_WARDEN_HOME",
            {"username": "alice", "refresh": True},
        )

    def test_interval_starts_at_completion_instead_of_creation(self):
        self.jobs.return_value = [self.job("completed", age=299)]
        self.assertIsNone(self.sync())
        self.create.assert_not_called()
        self.identity.assert_not_called()

    def test_pending_approved_and_running_jobs_are_not_duplicated(self):
        for status in ("pending", "approved", "running"):
            with self.subTest(status=status):
                self.jobs.return_value = [self.job(status, age=7200)]
                self.assertIsNone(self.sync())
        self.create.assert_not_called()

    def test_new_console_user_can_sync_without_waiting_for_previous_user(self):
        self.jobs.return_value = [self.job("completed", age=1)]
        result = home_sync.queue_periodic_home_sync(
            self.endpoint, r"DESKTOP\bob", capabilities=["SYNC_WARDEN_HOME"], now=self.now,
        )
        self.assertEqual(result, {"id": "sync-job"})
        self.assertEqual(self.create.call_args.args[-1], {"username": "bob", "refresh": True})

    def test_new_console_user_still_waits_for_running_job(self):
        self.jobs.return_value = [self.job("running", age=7200)]
        self.assertIsNone(home_sync.queue_periodic_home_sync(
            self.endpoint, "bob", capabilities=["SYNC_WARDEN_HOME"], now=self.now,
        ))
        self.create.assert_not_called()

    def test_retry_backoff_is_bounded_and_resets_after_success(self):
        for failures, delay in ((1, 300), (2, 600), (3, 1200), (4, 1800), (20, 1800)):
            with self.subTest(failures=failures):
                jobs = [self.job("failed", age=delay - 1)] * failures
                self.assertFalse(home_sync.home_sync_due(jobs, now=self.now))
                self.assertTrue(home_sync.home_sync_due(jobs, now=self.now + timedelta(seconds=1)))
        self.assertTrue(home_sync.home_sync_due(
            [self.job("completed"), self.job("failed")], now=self.now,
        ))

    def test_signed_out_or_unsupported_endpoints_do_not_schedule(self):
        for user in ("", None, "invalid username"):
            with self.subTest(user=user):
                self.endpoint["interactive_user"] = user
                self.assertIsNone(self.sync())
        self.endpoint["interactive_user"] = "alice"
        for capabilities in ([], ["OTHER"], "SYNC_WARDEN_HOME"):
            with self.subTest(capabilities=capabilities):
                self.assertIsNone(self.sync(capabilities=capabilities))
        self.assertIsNone(self.sync(capabilities=None, platform="linux"))
        self.endpoint["is_active"] = False
        self.assertIsNone(self.sync())
        self.jobs.assert_not_called()

    def test_legacy_windows_agent_can_schedule_without_capability_list(self):
        self.assertEqual(self.sync(capabilities=None), {"id": "sync-job"})

    def test_active_managed_identity_inherits_matching_branch_assignment(self):
        self.identity.return_value = self.managed()
        self.assignment.update(scope_type="branch", scope_value="branch-a")
        self.assertEqual(self.sync(), {"id": "sync-job"})

    def test_wrong_branch_and_other_endpoint_identity_assignment_are_rejected(self):
        self.identity.return_value = self.managed()
        self.assignment.update(scope_type="branch", scope_value="other-branch")
        self.assertIsNone(self.sync())
        self.assignment.update(scope_type="endpoint", scope_value=self.endpoint["id"])
        self.identity.return_value["warden_identity_assignments"][0]["endpoint_id"] = "other-device"
        self.assertIsNone(self.sync())
        self.create.assert_not_called()

    def test_disabled_or_pending_managed_identity_cannot_fall_back_to_direct_share(self):
        for identity in (self.managed("pending"), self.managed(is_enabled=False)):
            with self.subTest(identity=identity):
                self.identity.return_value = identity
                self.assertIsNone(self.sync())
        self.create.assert_not_called()
        self.assignments.assert_not_called()

    def test_direct_user_cannot_inherit_broader_or_different_endpoint_scope(self):
        for scope, value in (("tenant", ""), ("branch", "branch-a"), ("endpoint", "other-device")):
            with self.subTest(scope=scope):
                self.assignment.update(scope_type=scope, scope_value=value)
                self.assertIsNone(self.sync())
        self.create.assert_not_called()

    def test_revoked_assignment_is_rechecked_on_next_due_sync(self):
        self.assertEqual(self.sync(), {"id": "sync-job"})
        self.assignment["enabled"] = False
        self.assertIsNone(self.sync())
        self.create.assert_called_once()
        self.assertEqual(self.assignments.call_count, 2)

    def test_tenant_mismatches_are_rejected(self):
        node = self.space["home_space_nodes"][0]["home_storage_nodes"]
        for record in (self.assignment, self.space, node):
            with self.subTest(record=record):
                record["company_id"] = "another-company"
                self.assertIsNone(self.sync())
                record["company_id"] = "company-a"
        self.identity.return_value = self.managed(company_id="another-company")
        self.assertIsNone(self.sync())
        self.create.assert_not_called()

    def test_disabled_space_or_node_does_not_schedule(self):
        self.space["enabled"] = False
        self.assertIsNone(self.sync())
        self.space["enabled"] = True
        self.space["home_space_nodes"][0]["home_storage_nodes"]["status"] = "disabled"
        self.assertIsNone(self.sync())
        self.create.assert_not_called()

    def test_atomic_creation_can_decline_a_concurrent_sync(self):
        self.create.return_value = None
        self.assertIsNone(self.sync())
        self.create.assert_called_once()

    def heartbeat(self):
        update = self.patch("update_endpoint_heartbeat", None)
        self.patch("get_open_alert", None)
        self.patch("get_company_by_id", {"id": "company-a"})
        self.patch("get_branch", {"timezone": "UTC"})
        app = Flask(__name__)
        with app.test_request_context("/api/agent/heartbeat", method="POST", json={
            "interactive_user": self.endpoint["interactive_user"],
            "platform": "windows", "capabilities": ["SYNC_WARDEN_HOME"], "job_capacity": 0,
        }):
            g.endpoint = self.endpoint
            response = agent_api.heartbeat.__wrapped__()
        self.assertEqual(update.call_args.kwargs["interactive_user"], self.endpoint["interactive_user"])
        return response

    def test_heartbeat_schedules_unchanged_console_user(self):
        # With no sign-in transition, an ordinary heartbeat must still enter
        # the real scheduler and create a refresh after the interval.
        self.jobs.return_value = [{"status": "completed", "completed_at": "2000-01-01T00:00:00Z"}]
        self.assertTrue(self.heartbeat().get_json()["ok"])
        self.create.assert_called_once()
        self.assertEqual(self.create.call_args.args[-1], {"username": "alice", "refresh": True})

    def test_home_metadata_failure_does_not_break_heartbeat(self):
        self.jobs.side_effect = RuntimeError("Home metadata temporarily unavailable")
        with self.assertLogs(level="ERROR"):
            self.assertTrue(self.heartbeat().get_json()["ok"])
        self.create.assert_not_called()


class HomeSyncHistoryTests(unittest.TestCase):
    def test_checks_inflight_jobs_even_if_older_than_latest_finished_jobs(self):
        with mock.patch.object(db, "_get", return_value=[{"status": "running"}]) as get:
            self.assertEqual(db.get_endpoint_home_sync_jobs("tenant-a", "endpoint-a"), [{"status": "running"}])
        get.assert_called_once()
        query = get.call_args.args[0]
        self.assertIn("company_id=eq.tenant-a", query)
        self.assertIn("endpoint_id=eq.endpoint-a", query)
        self.assertIn("status=in.(pending,approved,running)", query)
        self.assertNotIn("payload", query)

    def test_finished_history_is_bounded_and_ordered_by_completion(self):
        with mock.patch.object(db, "_get", side_effect=[[], [{"status": "completed"}]]) as get:
            self.assertEqual(db.get_endpoint_home_sync_jobs("tenant-a", "endpoint-a"), [{"status": "completed"}])
        self.assertEqual(get.call_count, 2)
        self.assertIn("order=completed_at.desc.nullslast,created_at.desc&limit=4", get.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
