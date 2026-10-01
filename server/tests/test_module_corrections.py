import csv
import io
import pathlib
import unittest
from unittest import mock
from datetime import datetime, timezone, timedelta
from flask import Flask, g
import db
from middleware import auth
from services.compliance_state import active_policy, fingerprint, permits_sign_in, prepare_scan, scan_receipt
from services.device_health import age_seconds
from services import fleet_tools, fleet_reports


class ModuleCorrectionTests(unittest.TestCase):
    def test_returning_vulnerability_reopens_but_preserves_review_decisions(self):
        finding = dict(software=dict(id="software"), advisory=dict(id="advisory"), confidence="high", evidence={})
        for status in ["remediated", "accepted", "false_positive"]:
            row = dict(id="finding", software_id="software", advisory_id="advisory", status=status)
            with self.subTest(status=status), mock.patch.object(db, "_get", return_value=[row]), mock.patch.object(db, "_patch") as update:
                db.replace_vulnerability_findings("tenant", "ep", [finding])
                fields = update.call_args.args[1]
                if status == "remediated":
                    self.assertEqual(fields["status"], "open")
                    self.assertIsNone(fields["resolved_at"])
                else:
                    self.assertNotIn("status", fields)

    def test_old_agents_receive_server_bound_scan_receipts(self):
        ep = dict(id="ep", company_id="tenant")
        job = dict(type="COMPLIANCE_SCAN", status="running", endpoint_id="ep", company_id="tenant",
                   started_at=datetime.now(timezone.utc).isoformat(),
                   payload=dict(policy_id="p", policy_fingerprint="a"*64))
        with mock.patch.object(db, "get_job", return_value=job):
            self.assertEqual(scan_receipt(ep, "job"), ("p", "a"*64))
        for changes in [dict(status="completed"), dict(endpoint_id="foreign"), dict(company_id="foreign"),
                        dict(type="RUN_CMD"), dict(started_at=None)]:
            with self.subTest(changes=changes), mock.patch.object(db, "get_job", return_value=dict(job, **changes)):
                with self.assertRaises(ValueError):
                    scan_receipt(ep, "job")

    def test_access_generation_revokes_previously_issued_tokens(self):
        app = Flask(__name__)
        app.secret_key = "test"
        admin = dict(id="a", role="company_admin", company_id="tenant", is_active=True, access_token_version=2)
        token = auth.issue_access_token(admin)
        with app.test_request_context("/", headers={"Authorization": "Bearer " + token}), mock.patch.object(
            db, "get_admin_by_id", return_value=dict(admin, access_token_version=3)
        ):
            auth.load_current_user()
            self.assertIsNone(g.admin)

    def test_legacy_token_rejected_after_first_revocation(self):
        app = Flask(__name__)
        with app.test_request_context("/"), mock.patch.object(auth, "get_token_from_request", return_value="token"), mock.patch.object(
            auth, "decode_access_token", return_value=dict(sub="admin")
        ), mock.patch.object(db, "get_admin_by_id", return_value=dict(is_active=True, access_token_version=1)):
            auth.load_current_user()
            self.assertIsNone(g.admin)

    def test_revocation_uses_atomic_rpc(self):
        with mock.patch.object(db, "_rpc") as rpc:
            db.revoke_all_tokens_for_admin("admin")
            rpc.assert_called_once_with("revoke_admin_sessions", {"p_admin_id": "admin"})

    def test_inventory_update_is_transactional_and_does_not_delete_first(self):
        items = [dict(name="App", version="1", publisher="Vendor")]
        with mock.patch.object(db, "_rpc") as rpc, mock.patch.object(db, "_delete") as delete:
            db.replace_software_inventory("ep", items)
            rpc.assert_called_once_with("replace_software_inventory", dict(p_endpoint_id="ep", p_items=items))
            delete.assert_not_called()

    def test_future_clock_is_not_fresh_inventory(self):
        now = datetime.now(timezone.utc)
        future = (now + timedelta(days=7)).isoformat()
        self.assertLess(age_seconds(future, now), -300)
        endpoint = dict(id="ep", company_id="tenant", status="online", software_inventory_at=future)
        with mock.patch.object(db, "_rpc") as rpc:
            self.assertIsNone(fleet_tools.dispatch(dict(enabled=True), endpoint, dict(status="outdated"), now))
            rpc.assert_not_called()

    def test_compliance_requires_fresh_policy_bound_evidence(self):
        now = datetime.now(timezone.utc)
        ep = dict(id="ep", company_id="tenant", branch_id="b", platform="windows")
        policy = dict(id="p", company_id="tenant", checks=["firewall_enabled"], updated_at="2026-10-01T00:00:00Z")
        result = dict(endpoint_id="ep", company_id="tenant", overall_status="compliant",
                      scanned_at=now.isoformat(), policy_fingerprint=fingerprint(ep, policy))
        self.assertTrue(permits_sign_in(ep, result, [policy], now))
        for overrides in [dict(scanned_at=(now-timedelta(days=2)).isoformat()),
                          dict(scanned_at=(now+timedelta(seconds=1)).isoformat()),
                          dict(policy_fingerprint=None), dict(company_id="other"),
                          dict(endpoint_id="other"), dict(overall_status="error")]:
            with self.subTest(overrides=overrides):
                self.assertFalse(permits_sign_in(ep, dict(result, **overrides), [policy], now))
        self.assertFalse(permits_sign_in(ep, result, [dict(policy, checks=["bitlocker_enabled"])], now))
        self.assertFalse(permits_sign_in(ep, result, [dict(policy, updated_at="new")], now))

    def test_branch_policy_precedence_and_scheduled_scan_binding(self):
        ep = dict(id="ep", company_id="tenant", branch_id="b", platform="windows")
        policies = [dict(id="tenant-policy", company_id="tenant", checks=["firewall_enabled"]),
                    dict(id="branch-policy", company_id="tenant", branch_id="b", checks=["bitlocker_enabled"]),
                    dict(id="foreign", company_id="other", branch_id="b", checks=["firewall_enabled"])]
        self.assertEqual(active_policy(ep, policies)["id"], "branch-policy")
        with mock.patch.object(db, "get_endpoint", return_value=ep), mock.patch.object(db, "get_compliance_policies", return_value=policies):
            payload = prepare_scan("tenant", "ep", {})
            self.assertEqual(payload["checks"], ["bitlocker_enabled"])
            self.assertEqual(payload["policy_id"], "branch-policy")
            self.assertEqual(len(payload["policy_fingerprint"]), 64)

    def test_branch_report_keeps_branch_events_and_historical_scope(self):
        rows = [dict(id="branch-event", branch_id="b", action="branch_traffic_configured"),
                dict(id="moved-device-history", branch_id="b", endpoint_id="now-in-other-branch"),
                dict(id="foreign", branch_id="other", endpoint_id="now-in-this-branch")]
        with mock.patch.object(db, "_get", return_value=rows) as read, mock.patch.object(db, "get_endpoints") as current:
            result = fleet_reports.export("tenant", "audit", "b")
            self.assertIn("branch_id=eq.b", read.call_args.args[0])
            current.assert_not_called()
        self.assertIn("branch-event", result)
        self.assertIn("moved-device-history", result)
        self.assertNotIn("foreign", result)

    def test_windows_patch_checks_all_results_and_rejects_forced_restart(self):
        source = (pathlib.Path(__file__).parents[2]/"agent-go"/"commands.go").read_text()
        self.assertIn("$ready.Count -ne $selected.Count", source)
        self.assertIn("$result.GetUpdateResult($i)", source)
        self.assertIn("$r.ResultCode -ne 2", source)
        self.assertIn("$result.ResultCode -ne 2", source)
        self.assertIn('rebootMode != "never" && rebootMode != "notify"', source)


if __name__ == "__main__":
    unittest.main()
