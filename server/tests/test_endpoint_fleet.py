import unittest
import pathlib
from jinja2 import Environment, FileSystemLoader
from datetime import datetime, timedelta, timezone
from unittest import mock
from flask import Flask, g
import db
from routes import endpoints as routes
from services import endpoint_fleet as fleet

NOW = datetime(2026, 10, 2, tzinfo=timezone.utc)
ID = "11111111-1111-4111-8111-111111111111"


class FleetTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.ep = dict(id=ID, company_id="c", branch_id="b", hostname="PC", display_name="Reception",
                       status="online", last_seen=NOW.isoformat(), agent_version="2.6.53",
                       cpu_pct=0, ram_used_pct=None, disk_free_gb=5)
        mock.patch.object(db, "get_latest_completed_build", return_value={"agent_version": "2.6.54"}).start()
        self.addCleanup(mock.patch.stopall)

    def test_stale_online_status_matches_summary_and_filter(self):
        row = fleet.prepare([dict(self.ep, last_seen=(NOW-timedelta(minutes=4)).isoformat())], now=NOW)[0]
        result = fleet.listing([row], {"state": "online"})
        self.assertEqual(result["fleet_summary"]["online"], 0)
        self.assertEqual(result["total_matches"], 0)

    def test_unknown_evidence_never_claims_all_healthy(self):
        row = fleet.prepare([self.ep], now=NOW)[0]
        self.assertEqual(row["_encryption"], "unknown")
        self.assertTrue(row["_low_disk"])
        self.assertIn("Low disk (last report)", row["_signals"])

    def test_secondary_drive_low_space_and_capacity_rendered(self):
        details = {"local_drives": {"volumes": [
            dict(mount_point="C:", total_gb=500, free_gb=100),
            dict(mount_point="H:", total_gb=50, free_gb=2)]}}
        row = fleet.prepare([dict(self.ep, disk_free_gb=100, capability_details=details)], now=NOW)[0]
        self.assertTrue(row["_low_disk"])
        env = Environment(loader=FileSystemLoader(pathlib.Path(__file__).parents[1] / "templates"), autoescape=True)
        env.filters["timeago"] = lambda value: "just now"
        html = env.get_template("partials/endpoint_row.html").render(
            endpoint=row, current_user={"role":"company_admin"}, branch_names={})
        self.assertIn("H:", html)
        self.assertIn("48 GB used / 50 GB total", html)
        self.assertIn("100 GB free", html)

    def test_newest_compliance_scan_wins_even_if_input_reversed(self):
        checks = [dict(endpoint_id=ID, scanned_at=NOW.isoformat(), results=[dict(check="bitlocker_enabled", status="fail")]),
                  dict(endpoint_id=ID, scanned_at=(NOW-timedelta(hours=1)).isoformat(), results=[dict(check="bitlocker_enabled", status="pass")])]
        self.assertEqual(fleet.prepare([self.ep], checks, now=NOW)[0]["_encryption"], "attention")

    def test_failed_job_and_update_result_are_separate(self):
        jobs = [dict(id="j", endpoint_id=ID, status="failed", type="UNINSTALL_APP", created_at=NOW.isoformat()),
                dict(id="u", endpoint_id=ID, status="completed", type="UPDATE_AGENT", created_at=NOW.isoformat())]
        row = fleet.prepare([self.ep], jobs=jobs, now=NOW)[0]
        self.assertEqual(row["_failed_job"]["id"], "j")
        self.assertEqual(row["_update_job"]["id"], "u")

    def test_search_nickname_and_pagination_clamps_bad_values(self):
        rows = fleet.prepare([dict(self.ep, id=str(n), display_name="Reception "+str(n)) for n in range(60)], now=NOW)
        result = fleet.listing(rows, {"q":"Reception", "page":"999", "page_size":"25"})
        self.assertEqual((result["page"], result["page_count"], len(result["endpoints"])), (3,3,10))
        self.assertEqual(fleet.listing(rows, {"page":"bad","page_size":"-1"})["page_size"],25)

    def test_page_reader_continues_past_default_limit(self):
        with mock.patch.object(db,"_get",side_effect=[[{}]*500,[{}]]) as get:
            self.assertEqual(len(fleet.pages("endpoints?order=id.asc")),501)
        self.assertIn("offset=500",get.call_args.args[0])

    def context(self, body, role="company_admin"):
        ctx=self.app.test_request_context("/endpoints/bulk-dispatch",method="POST",json=body)
        ctx.push(); self.addCleanup(ctx.pop)
        g.company={"id":"c"}; g.admin={"id":"a","role":role,"branch_id":"b"}

    def run_bulk(self):
        fn=routes.bulk_dispatch
        while hasattr(fn,"__wrapped__"): fn=fn.__wrapped__
        return fn()

    def test_preview_has_no_jobs_and_keeps_branch_selection(self):
        self.context({"type":"COLLECT_SYSINFO","preview":True,"endpoint_ids":[ID],"target_mode":"selected"}, "branch_admin")
        decision=mock.Mock(allowed=True)
        with mock.patch("services.entitlements.check_job",return_value=decision), mock.patch.object(db,"get_endpoints_bulk",return_value=[self.ep]) as get, mock.patch.object(db,"create_job") as create:
            response=self.run_bulk()
        self.assertEqual(response.get_json()["targets"][0]["id"],ID)
        self.assertEqual(get.call_args.kwargs["endpoint_ids"],[ID])
        self.assertEqual(get.call_args.kwargs["branch_id"],"b")
        create.assert_not_called()

    def test_selected_empty_never_widens_to_branch(self):
        self.context({"type":"COLLECT_SYSINFO","endpoint_ids":[],"target_mode":"selected"})
        with mock.patch("services.entitlements.check_job",return_value=mock.Mock(allowed=True)), mock.patch.object(db,"get_endpoints_bulk") as get:
            self.assertEqual(self.run_bulk()[1],400)
            get.assert_not_called()

    def test_foreign_branch_target_rejected_before_dispatch(self):
        self.context({"type":"COLLECT_SYSINFO","endpoint_ids":[ID],"target_mode":"selected"}, "branch_admin")
        with mock.patch("services.entitlements.check_job",return_value=mock.Mock(allowed=True)), mock.patch.object(db,"get_endpoints_bulk",return_value=[dict(self.ep,branch_id="foreign")]),mock.patch.object(db,"create_job") as create:
            self.assertEqual(self.run_bulk()[1],409)
            create.assert_not_called()

    def test_unsupported_preview_does_not_promise_execution(self):
        self.context({"type":"COLLECT_SYSINFO","preview":True})
        with mock.patch("services.entitlements.check_job",return_value=mock.Mock(allowed=True)),mock.patch.object(db,"get_endpoints_bulk",return_value=[dict(self.ep,platform="linux",capabilities=[])]):
            self.assertFalse(self.run_bulk().get_json()["targets"][0]["supported"])

    def test_card_escapes_name_and_keeps_zero_telemetry(self):
        env = Environment(loader=FileSystemLoader(pathlib.Path(__file__).parents[1] / "templates"), autoescape=True)
        env.filters["timeago"] = lambda value: "just now"
        row = fleet.prepare([dict(self.ep, display_name="<script>alert(1)</script>")], now=NOW)[0]
        html = env.get_template("partials/endpoint_row.html").render(endpoint=row, current_user={"role":"company_admin"}, branch_names={"b":"Lab"})
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("0%", html)
        self.assertIn("Unknown", html)

    def test_refresh_response_is_small_private_and_preserves_scope(self):
        with self.app.test_request_context("/endpoints", headers={"X-Fleet-Refresh":"1"}):
            g.company={"id":"c"}; g.admin={"id":"a","role":"company_admin"}
            rows = fleet.prepare([self.ep], now=NOW)
            fn = routes.list_endpoints
            while hasattr(fn,"__wrapped__"): fn=fn.__wrapped__
            with mock.patch("services.endpoint_fleet.load",return_value=rows) as load, mock.patch.object(db,"get_branches",return_value=[]), mock.patch.object(routes,"render_template",return_value="<tr>fixture</tr>"):
                response=fn()
        load.assert_called_once_with({"id":"c"},None)
        self.assertIn("no-store",response.headers["Cache-Control"])
        self.assertIn("rows",response.get_json())
        self.assertNotIn("payload",response.get_json())
