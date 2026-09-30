import json
import pathlib
import sys
import unittest
from unittest import mock

from flask import Flask, g
from jinja2 import ChoiceLoader, DictLoader, Environment, FileSystemLoader
from werkzeug.exceptions import NotFound


SERVER_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from routes import home


def report(**updates):
    return {"kind": "warden_home_sync", "version": 1, "status": "completed",
            "uploaded": 1, "downloaded": 0, "unchanged": 0, "skipped": 0,
            "failed": 0, "uploaded_bytes": 5, "downloaded_bytes": 0,
            "files": [], **updates}


def undecorated(function):
    while hasattr(function, "__wrapped__"):
        function = function.__wrapped__
    return function


class HomeTransferStatusTests(unittest.TestCase):
    def view(self, output, status="completed"):
        return home._home_transfer_view({
            "id": "job-a", "endpoint_id": "endpoint-a", "status": status,
            "log_output": output, "created_at": "2026-09-30T01:00:00Z",
        }, {"endpoint-a": {"hostname": "Office PC"}})

    def test_legacy_completed_job_does_not_confirm_file_transfer(self):
        item = self.view("Warden Home synchronization completed")
        self.assertEqual(item["label"], "Completed · unverified")
        self.assertIsNone(item["report"])

    def test_receipts_distinguish_success_empty_and_unchanged(self):
        self.assertEqual(self.view(json.dumps(report()))["label"], "Succeeded")
        self.assertEqual(self.view(json.dumps(report(uploaded=0, uploaded_bytes=0)))["label"], "No files found")
        self.assertEqual(self.view(json.dumps(report(uploaded=0, uploaded_bytes=0, unchanged=2)))["label"], "Up to date")

    def test_partial_report_cannot_appear_successful_even_if_job_completed(self):
        for field in ("failed", "skipped"):
            item = self.view(json.dumps(report(**{field: 1})))
            self.assertEqual(item["label"], "Incomplete")
        self.assertEqual(self.view(json.dumps(report(failed=1)), "failed")["label"], "Failed")

    def test_empty_folder_receipts_count_as_success(self):
        item = self.view(json.dumps(report(uploaded=0, uploaded_bytes=0, folders_created=2)))
        self.assertEqual(item["label"], "Succeeded")
        self.assertEqual(item["report"]["folders_created"], 2)
        self.assertEqual(self.view(json.dumps(report()))["report"]["folders_created"], 0)

    def test_malformed_receipt_is_unverified(self):
        for output in ("{truncated", json.dumps(report(uploaded=True)), json.dumps(report(failed=-1))):
            self.assertEqual(self.view(output)["label"], "Completed · unverified")

    def test_status_queries_are_company_and_branch_scoped(self):
        with mock.patch.object(home.db, "_get", return_value=[]) as read, mock.patch.object(home.db, "get_company_by_id", return_value={}):
            home.db.get_home_sync_jobs("tenant-a", branch_id="branch-a", limit=20)
        query = read.call_args.args[0]
        self.assertIn("company_id=eq.tenant-a", query)
        self.assertIn("type=eq.SYNC_WARDEN_HOME", query)
        self.assertIn("branch_id=eq.branch-a", query)
        self.assertNotIn("payload", query)

    def test_manual_sync_rejects_other_company(self):
        app = Flask(__name__)
        with app.test_request_context("/storage/spaces/space-a/sync", method="POST"):
            g.company = {"id": "tenant-a"}
            with mock.patch.object(home.db, "get_home_space", return_value={"company_id": "tenant-b"}), mock.patch.object(home, "_queue_assigned_home_syncs") as queue:
                with self.assertRaises(NotFound):
                    undecorated(home.sync_space)("space-a")
                queue.assert_not_called()

    def test_manual_sync_requires_signed_in_assigned_user(self):
        app = Flask(__name__)
        endpoint = {"id": "endpoint-a", "company_id": "tenant-a", "platform": "windows", "interactive_user": None}
        with app.test_request_context():
            g.company = {"id": "tenant-a"}
            with mock.patch.object(home.db, "get_home_spaces", return_value=[]), mock.patch.object(home.db, "get_endpoints", return_value=[endpoint]), mock.patch.object(home, "resolve_home_access_context") as resolve, mock.patch.object(home.db, "create_system_job_once") as queue:
                self.assertEqual(home._queue_assigned_home_syncs("space-a"), 0)
                resolve.assert_not_called()
                queue.assert_not_called()

    def test_manual_sync_uses_fresh_authorization_and_atomic_queue(self):
        app = Flask(__name__)
        endpoint = {"id": "endpoint-a", "company_id": "tenant-a", "platform": "windows", "interactive_user": "PC\\alice", "branch_id": "branch-a"}
        principal = {"username": "alice", "id": "principal-a"}
        with app.test_request_context():
            g.company = {"id": "tenant-a"}
            with mock.patch.object(home.db, "get_home_spaces", return_value=[]), mock.patch.object(home.db, "get_endpoints", return_value=[endpoint]), mock.patch.object(home.db, "has_inflight_job", return_value=False), mock.patch.object(home, "resolve_home_access_context", return_value=(principal, [], False)) as resolve, mock.patch.object(home, "home_config_for", return_value=[{"id": "space-a"}]), mock.patch.object(home.db, "create_system_job_once", return_value={"id": "job-a"}) as queue:
                self.assertEqual(home._queue_assigned_home_syncs("space-a"), 1)
                resolve.assert_called_once_with(endpoint, "alice")
                queue.assert_called_once_with("tenant-a", "branch-a", "endpoint-a", "SYNC_WARDEN_HOME", {"username": "alice", "refresh": True})

    def test_transfer_template_renders_counts_and_escapes_file_errors(self):
        environment = Environment(loader=ChoiceLoader([
            DictLoader({"base.html": "{% block content %}{% endblock %}"}),
            FileSystemLoader(SERVER_DIR / "templates"),
        ]), autoescape=True)
        environment.filters["timeago"] = lambda value: value
        item = self.view(json.dumps(report(failed=1, files=[{
            "space": "Office", "path": "<script>bad</script>",
            "action": "download", "status": "failed", "error": "<script>bad</script>",
        }])), "failed")
        rendered = environment.get_template("home/index.html").render(
            transfers=[item], last_completed=None, spaces=[], nodes=[], assignments=[],
            endpoints=[], branches=[], identities=[], g={"admin": {"role": "company_admin"}}, csrf_token=lambda: "csrf",
            home_section="activity", url_for=lambda *args, **kwargs: "/static/css/home.css",
        )
        self.assertIn("Transfer activity", rendered)
        self.assertIn("1 uploaded (5 bytes)", rendered)
        self.assertIn("1 failed", rendered)
        self.assertIn("&lt;script&gt;bad&lt;/script&gt;", rendered)
        self.assertNotIn("<script>bad</script>", rendered)


if __name__ == "__main__":
    unittest.main()
