import pathlib
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock
from flask import Flask, g
from jinja2 import Environment, FileSystemLoader
import db
from routes import dashboard
from services import dashboard_view as view

ROOT = pathlib.Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 2, tzinfo=timezone.utc)


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.ep = dict(id="e1", status="online", last_seen=NOW.isoformat(),
                       hostname="PC", display_name="Reception", agent_version="2.6.9")
        self.build = mock.patch.object(db, "get_latest_completed_build", return_value={"agent_version": "2.6.53"}).start()
        self.addCleanup(mock.patch.stopall)
        mock.patch('services.dashboard_fleet.snapshot', return_value=None).start()

    def context(self, query="", role="company_admin", branch=None):
        ctx = self.app.test_request_context("/dashboard" + query)
        ctx.push()
        self.addCleanup(ctx.pop)
        g.company = {"id": "c1"}
        g.admin = {"id": "a1", "role": role, "branch_id": branch}

    def test_branch_admin_cannot_override_scope(self):
        self.context("?branch_id=other", role="branch_admin", branch="b1")
        self.assertEqual(view.selected_branch(), "b1")

    def test_missing_branch_admin_scope_is_denied(self):
        self.context(role="branch_admin")
        with self.assertRaises(Exception) as caught:
            view.selected_branch()
        self.assertEqual(caught.exception.code, 403)

    def test_foreign_branch_is_denied(self):
        self.context("?branch_id=other")
        with mock.patch.object(db, "get_branch", return_value={"company_id": "other"}):
            with self.assertRaises(Exception) as caught:
                view.selected_branch()
        self.assertEqual(caught.exception.code, 404)

    def test_freshness_never_treats_missing_or_future_reports_as_live(self):
        for seen in (None, "bad", (NOW + timedelta(hours=1)).isoformat(), (NOW - timedelta(minutes=4)).isoformat()):
            self.assertFalse(view.report_online(dict(self.ep, last_seen=seen), NOW))
        self.assertTrue(view.report_online(self.ep, NOW))

    def test_version_comparison_is_numeric_not_lexical(self):
        row = view.prepare_endpoints([self.ep], now=NOW)[0]
        self.assertTrue(row["_agent_update"])
        self.assertFalse(view.prepare_endpoints([dict(self.ep, agent_version="2.6.100")], now=NOW)[0]["_agent_update"])

    def test_missing_build_and_version_are_unknown(self):
        self.build.return_value = None
        row = view.prepare_endpoints([dict(self.ep, agent_version=None)], now=NOW)[0]
        self.assertFalse(row["_agent_update"])
        self.assertTrue(row["_agent_unknown"])

    def test_stale_encryption_check_is_not_current(self):
        scan = dict(endpoint_id="e1", scanned_at=(NOW - timedelta(days=2)).isoformat(),
                    results=[dict(check="bitlocker_enabled", status="pass")])
        self.assertEqual(view.prepare_endpoints([self.ep], [scan], now=NOW)[0]["_encryption"], "unknown")

    def test_encryption_failure_is_visible_and_patches_are_reported(self):
        scan = dict(endpoint_id="e1", scanned_at=NOW.isoformat(), results=[dict(check="bitlocker_enabled", status="fail")])
        row = view.prepare_endpoints([self.ep], [scan], [{"endpoint_id": "e1"}], NOW)[0]
        self.assertEqual(row["_encryption"], "attention")
        self.assertTrue(row["_patch_attention"])

    def test_alert_grouping_keeps_devices_and_types_separate(self):
        alerts = [dict(id="1", endpoint_id="e1", type="offline", severity="warning"),
                  dict(id="2", endpoint_id="e1", type="offline", severity="critical"),
                  dict(id="3", endpoint_id="e2", type="offline", severity="warning"),
                  dict(id="4", endpoint_id="e1", type="disk", severity="warning")]
        grouped = view.group_alerts(alerts)
        self.assertEqual(len(grouped), 3)
        self.assertEqual(grouped[0]["repeats"], 2)
        self.assertEqual(grouped[0]["severity"], "critical")

    def test_scoped_links_preserve_branch_and_filter(self):
        self.assertEqual(view.scoped_url("/jobs", "b1", status="failed", window="24h"),
                         "/jobs?status=failed&window=24h&branch_id=b1")

    def test_exact_count_uses_metadata_not_row_page(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.headers = {"Content-Range": "*/1501"}
        with mock.patch.object(db.urllib.request, "urlopen", return_value=response) as send:
            self.assertEqual(db.dashboard_count("c1", "jobs", "b1", status="eq.failed"), 1501)
        req = send.call_args.args[0]
        self.assertEqual(req.get_method(), "HEAD")
        self.assertIn("company_id=eq.c1", req.full_url)
        self.assertIn("branch_id=eq.b1", req.full_url)

    def test_missing_exact_count_is_not_zero(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.headers = {}
        with mock.patch.object(db.urllib.request, "urlopen", return_value=response):
            with self.assertRaises(RuntimeError):
                db.dashboard_count("c1", "alerts")

    def test_dashboard_snapshot_scopes_all_queries(self):
        self.context("?branch_id=ignored", role="branch_admin", branch="b1")
        with mock.patch.object(db, "get_endpoints", return_value=[self.ep]) as endpoints, \
             mock.patch.object(db, "get_compliance_results_for_company", return_value=[]), \
             mock.patch.object(db, "get_patch_inventory", return_value=[]), \
             mock.patch.object(db, "get_alerts", return_value=[]) as alerts, \
             mock.patch.object(db, "get_jobs", return_value=[]) as jobs, \
             mock.patch.object(db, "get_branches", return_value=[dict(id="b1", name="Lab"), dict(id="b2", name="Other")]), \
             mock.patch.object(db, "dashboard_counts", return_value=dict(pending_escalations=0, open_alerts=0, critical_alerts=0, failed_jobs=0, pending_jobs=0, running_jobs=0)) as counts, \
             mock.patch.object(db, "get_notifications", return_value=[]), \
             mock.patch.object(db, "count_unread_notifications", return_value=0):
            data = dashboard._data()
        endpoints.assert_called_once_with("c1", branch_id="b1", sort_names=False)
        self.assertEqual(alerts.call_args.kwargs["branch_id"], "b1")
        self.assertEqual(jobs.call_args.kwargs["branch_id"], "b1")
        self.assertTrue(all(call.kwargs["branch_id"] == "b1" for call in counts.call_args_list))
        self.assertEqual(len(data["branches"]), 1)

    def test_partial_render_escapes_alert_names_and_keeps_filters(self):
        self.context()
        env = Environment(loader=FileSystemLoader(str(ROOT / "templates")), autoescape=True)
        env.filters["timeago"] = lambda value: "now"
        data = dict(endpoints=[], total_count=0, online_count=0, offline_count=0, stale_count=0,
                    critical_alerts=1, open_alerts=1, pending_escalations=0, failed_jobs=0,
                    pending_jobs=0, running_jobs=0, recent_jobs=[], refreshed_at=NOW, alert_sample=1,
                    recent_alerts=[dict(title="<script>alert(1)</script>", severity="critical", repeats=2,
                                       created_at=NOW, endpoint_id="e1", message="Details")],
                    scoped_url=lambda path, **kw: view.scoped_url(path, "b1", **kw), asset_v="test")
        html = env.get_template("partials/dashboard_content.html").render(**data)
        self.assertNotIn("<script>", html)
        self.assertIn("2 occurrences", html)
        self.assertIn("branch_id=b1", html)
        self.assertIn("<details", html)

    def test_storage_unavailable_does_not_crash_dashboard(self):
        self.context()
        with mock.patch("services.tenant_storage.usage", side_effect=OSError("Unavailable")), \
             mock.patch.object(dashboard, "render_template", return_value="Unavailable") as render:
            result = dashboard.storage_partial.__wrapped__.__wrapped__()
        self.assertEqual(result, "Unavailable")
        self.assertIsNone(render.call_args.kwargs["storage"])

    def test_storage_hidden_from_branch_admin(self):
        self.context(role="branch_admin", branch="b1")
        with self.assertRaises(Exception) as caught:
            dashboard.storage_partial.__wrapped__.__wrapped__()
        self.assertEqual(caught.exception.code, 403)
