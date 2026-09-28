import pathlib
import sys
import unittest
from unittest import mock


SERVER_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

import db
import policy_settings
from routes.agent_api import (
    _integer_metric, _metric, _record_hostname_change, _record_policy_values,
)
import policy_settings


class JobLeaseTests(unittest.TestCase):
    def test_admx_catalog_exposes_only_machine_scope(self):
        admx = [meta for meta in policy_settings.POLICY_SETTINGS.values() if meta.get("admx")]
        self.assertTrue(all(meta.get("scope") == "machine" for meta in admx))
        self.assertIn("firewall_all_profiles_enabled", policy_settings.POLICY_SETTINGS)

    def test_pending_jobs_are_claimed_atomically_with_a_bounded_lease(self):
        with mock.patch.object(db, "_rpc", return_value=[]) as rpc:
            self.assertEqual(db.get_pending_jobs_for_endpoint("endpoint-1", limit=1000), [])
        rpc.assert_called_once_with("claim_jobs_for_endpoint", {
            "p_endpoint_id": "endpoint-1",
            "p_limit": 20,
            "p_lease_seconds": 900,
        })

    def test_bad_metrics_are_rejected_without_destroying_last_good_values(self):
        self.assertIsNone(_metric("not-a-number"))
        self.assertIsNone(_metric(float("nan")))
        self.assertIsNone(_metric(-1))
        self.assertEqual(_metric(150, maximum=100), 100)

    def test_integer_metrics_are_safe_for_integer_database_columns(self):
        self.assertEqual(_integer_metric(123), 123)
        self.assertEqual(_integer_metric("123"), 123)
        self.assertEqual(_integer_metric(123.9), 123)
        self.assertIsNone(_integer_metric("not-a-number"))

    def test_startup_policy_inventory_accepts_only_catalogued_keys(self):
        known_key = next(iter(policy_settings.POLICY_SETTINGS))
        endpoint = {
            "id": "endpoint-1", "company_id": "company-1",
            "branch_id": "branch-1",
        }
        with mock.patch.object(db, "record_policy_drift_check", return_value=[]) as record, \
             mock.patch.object(db, "log_endpoint_event"):
            _record_policy_values(endpoint, {known_key: True, "unknown_key": "ignored"}, "agent_startup")
        record.assert_called_once_with("endpoint-1", {known_key: True})

    def test_hostname_change_updates_mutable_name_and_is_audited(self):
        endpoint = {"id": "endpoint-1", "hostname": "OLD-PC"}
        with mock.patch.object(db, "update_endpoint_hostname") as update, \
             mock.patch.object(db, "log_endpoint_event") as event:
            self.assertTrue(_record_hostname_change(endpoint, "NEW-PC"))
        update.assert_called_once_with("endpoint-1", "NEW-PC")
        event.assert_called_once_with("endpoint-1", "hostname_changed", {
            "old_hostname": "OLD-PC", "new_hostname": "NEW-PC",
        })

    def test_hostname_reconciliation_ignores_same_or_invalid_names(self):
        endpoint = {"id": "endpoint-1", "hostname": "OFFICE-PC"}
        with mock.patch.object(db, "update_endpoint_hostname") as update:
            self.assertFalse(_record_hostname_change(endpoint, "office-pc"))
            self.assertFalse(_record_hostname_change(endpoint, "bad name!"))
        update.assert_not_called()

    def test_discovered_policy_is_stored_without_false_drift(self):
        known_key = next(
            key for key, meta in policy_settings.POLICY_SETTINGS.items()
            if not meta.get("readonly")
        )
        with mock.patch.object(db, "_rpc", return_value=[]) as rpc:
            self.assertEqual(db.record_policy_drift_check("endpoint-1", {known_key: True}), [])
        rpc.assert_called_once_with("record_endpoint_policy_observations", {
            "p_endpoint_id": "endpoint-1", "p_values": {known_key: True},
            "p_readonly_keys": [],
        })

    def test_unconfigured_policy_is_recorded_and_cleared_managed_value_drifts(self):
        known_key = next(
            key for key, meta in policy_settings.POLICY_SETTINGS.items()
            if not meta.get("readonly")
        )
        with mock.patch.object(db, "_rpc", return_value=[known_key]) as rpc:
            self.assertEqual(db.record_policy_drift_check("endpoint-1", {known_key: None}), [known_key])
        self.assertEqual(rpc.call_args.args[0], "record_endpoint_policy_observations")

    def test_deployment_summaries_use_one_bounded_database_call(self):
        raw = [{
            "id": "deployment-1", "pending": 2, "running": 1,
            "completed": 3, "failed": 1, "cancelled": 0,
        }]
        with mock.patch.object(db, "_rpc", return_value=raw) as rpc:
            rows = db.get_policy_deployments("company-1", limit=1000)
        rpc.assert_called_once_with("get_policy_deployment_summaries", {
            "p_company_id": "company-1", "p_limit": 100,
        })
        self.assertEqual(rows[0]["counts"]["completed"], 3)
        self.assertNotIn("completed", rows[0])

    def test_cancel_uses_compare_and_swap_against_job_claim(self):
        with mock.patch.object(db, "_company_for_job", return_value={"id": "company-1"}), \
             mock.patch.object(db, "encrypt_field", return_value="encrypted"), \
             mock.patch.object(db, "_patch", return_value=[]) as patch:
            self.assertFalse(db.cancel_job("job-1", "admin-1"))
        self.assertIn("status=in.(pending,approved)", patch.call_args.args[0])

    def test_result_side_effect_processing_is_compare_and_swap_claimed(self):
        with mock.patch.object(db, "_rpc", return_value=True) as rpc:
            self.assertTrue(db.claim_job_result_processing("job-1"))
        rpc.assert_called_once_with("claim_job_result_processing", {"p_job_id": "job-1"})

    def test_due_schedules_are_claimed_atomically(self):
        claimed = [{"id": "schedule-1"}]
        with mock.patch.object(db, "_rpc", return_value=claimed) as rpc:
            self.assertEqual(db.get_due_scheduled_jobs(), claimed)
        rpc.assert_called_once_with("claim_due_scheduled_jobs", {"p_limit": 100})

    def test_remote_session_creation_is_database_serialized(self):
        result = {"id": "session-1", "_created": True}
        with mock.patch.object(db, "_rpc", return_value=result) as rpc:
            self.assertEqual(
                db.create_remote_session("endpoint-1", "admin-1", "company-1"),
                result,
            )
        rpc.assert_called_once_with("create_or_get_remote_session", {
            "p_endpoint_id": "endpoint-1",
            "p_company_id": "company-1",
            "p_admin_id": "admin-1",
        })

if __name__ == "__main__":
    unittest.main()
