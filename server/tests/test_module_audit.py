import inspect
import pathlib
import sys
import unittest
from unittest import mock

from flask import Flask, g
from werkzeug.exceptions import Forbidden

SERVER = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER))

import db
from middleware.csrf import csrf_protect
from middleware.request_validation import validate_json_body
from routes import audit, build_service, compliance, enroll, escalations, home, schedule, status
from services import scheduler


class RequestEnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.secret_key = "test-only"

    def test_invalid_json_shapes_return_400(self):
        for body in ['[1]', 'null', 'false', '17', '"text"', '{"truncated":']:
            with self.subTest(body=body), self.app.test_request_context(
                "/api/agent/heartbeat", method="POST", data=body, content_type="application/json"
            ):
                response, code = validate_json_body()
                self.assertEqual(code, 400)
                self.assertIn("JSON object", response.get_json()["error"])

    def test_object_form_upload_and_bodyless_requests_remain_supported(self):
        for content_type, body in [
            ("application/json", "{}"), ("application/json", ""),
            ("application/x-www-form-urlencoded", "name=example"),
            ("application/octet-stream", "binary payload"),
        ]:
            with self.subTest(content_type=content_type, body=body), self.app.test_request_context(
                "/", method="POST", data=body, content_type=content_type
            ):
                self.assertIsNone(validate_json_body())

    def test_non_string_csrf_tokens_are_forbidden_not_server_errors(self):
        from flask import session
        for token in [123, ["token"], {"token": "value"}, True, "é"]:
            with self.subTest(token=token), self.app.test_request_context(
                "/settings", method="POST", json={"csrf_token": token}
            ):
                session["_csrf_token"] = "expected"
                with self.assertRaises(Forbidden):
                    csrf_protect()

    def test_compliance_rejects_non_string_fields(self):
        with self.app.test_request_context("/", method="POST", json={"name": 123}):
            g.company = {"id": "company-a"}
            response, code = inspect.unwrap(compliance.create_policy)()
            self.assertEqual(code, 400)


class UpdateAndEnrollmentTests(unittest.TestCase):
    def test_enrollment_rejects_malformed_fields_before_consuming_token(self):
        app = Flask(__name__)
        for field, value in [
            ("token", []), ("hostname", 1), ("csr_pem", {}),
            ("installation_id", False), ("enrollment_nonce", None),
            ("agent_version", "x" * 65), ("os_info", []),
        ]:
            with self.subTest(field=field), app.test_request_context(
                "/", method="POST", json={field: value}
            ), mock.patch.object(enroll, "check_rate_limit", return_value=True), mock.patch.object(
                enroll.db, "get_enrollment_token_by_hash"
            ) as lookup:
                response, code = enroll.enroll()
                self.assertEqual(code, 400)
                lookup.assert_not_called()

    def test_home_release_metadata_overrides_stale_environment(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            home.config, "HOME_NODE_DIST_DIR", pathlib.Path(directory)
        ), mock.patch.object(home.config, "HOME_NODE_VERSION", "1.0.0"):
            metadata = pathlib.Path(directory) / "version.txt"
            self.assertEqual(home._home_release_version(), "1.0.0")
            metadata.write_text("1.1.6\n", encoding="utf-8")
            self.assertEqual(home._home_release_version(), "1.1.6")
            metadata.write_text("not-a-version", encoding="utf-8")
            self.assertIsNone(home._home_release_version())
            metadata.write_bytes(b"\xff")
            self.assertIsNone(home._home_release_version())


class SavedApprovalSecurityTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.esc = {
            "id": "request-a", "company_id": "company-a", "branch_id": "branch-a",
            "endpoint_id": "endpoint-a", "windows_user": "alice",
            "status": "pending", "operation": "REBOOT", "payload": {},
        }

    def test_saved_branch_policy_follows_current_endpoint_branch(self):
        policy = {"scope": "any_user_this_branch", "branch_id": "branch-a"}
        for company, branch, expected in [
            ("company-a", "branch-a", policy),
            ("company-a", "branch-b", None),
            ("company-b", "branch-a", None),
        ]:
            with self.subTest(company=company, branch=branch), mock.patch.object(
                db, "_get", return_value=[policy]
            ), mock.patch.object(db, "get_endpoint", return_value={
                "company_id": company, "branch_id": branch
            }):
                self.assertEqual(db.find_matching_policy(
                    "company-a", "endpoint-a", "alice", "REBOOT", {}
                ), expected)

    def test_unknown_and_unbound_policies_fail_closed(self):
        for policy in [
            {"scope": "unexpected"}, {"scope": "this_user_all_endpoints"},
            {"scope": "any_user_this_endpoint"}, {"scope": "any_user_this_branch"},
            {"scope": "company_wide", "payload_match": ["invalid"]},
        ]:
            with self.subTest(policy=policy), mock.patch.object(db, "_get", return_value=[policy]), mock.patch.object(
                db, "get_endpoint", return_value=None
            ):
                self.assertIsNone(db.find_matching_policy(
                    "company-a", "endpoint-a", "alice", "REBOOT", {}
                ))

    def test_invalid_or_overbroad_policy_cannot_mutate_approval(self):
        for role, data, expected in [
            ("branch_admin", {"scope": "company_wide"}, 403),
            ("branch_admin", {"scope": "this_user_all_endpoints"}, 403),
            ("company_admin", {"scope": {}}, 400),
            ("company_admin", {"valid_days": 10**100}, 400),
            ("company_admin", {"valid_days": -1}, 400),
            ("company_admin", {"valid_days": True}, 400),
            ("company_admin", {"valid_days": 1.5}, 400),
            ("company_admin", {"note": []}, 400),
        ]:
            with self.subTest(role=role, data=data), self.app.test_request_context(
                "/", method="POST", json={"save_policy": True, **data}
            ), mock.patch.object(db, "get_escalation_request", return_value=self.esc), mock.patch.object(
                db, "approve_escalation"
            ) as approve:
                g.company = {"id": "company-a"}
                g.admin = {"id": "reviewer", "role": role, "branch_id": "branch-a"}
                response, code = inspect.unwrap(escalations.approve)("request-a")
                self.assertEqual(code, expected)
                approve.assert_not_called()

    def test_primary_approval_cannot_create_reusable_policy(self):
        with self.app.test_request_context(
            "/", method="POST", json={"save_policy": True}
        ), mock.patch.object(db, "get_escalation_request", return_value=self.esc), mock.patch.object(
            db, "approve_escalation", return_value=("token", {**self.esc, "status": "pending_secondary"})
        ), mock.patch.object(db, "create_saved_escalation") as save, mock.patch.object(
            db, "audit"
        ), mock.patch.object(db, "create_job") as job:
            g.company = {"id": "company-a"}
            g.admin = {"id": "reviewer", "role": "company_admin"}
            response = inspect.unwrap(escalations.approve)("request-a")
            self.assertEqual(response.get_json()["status"], "pending_secondary")
            save.assert_not_called()
            job.assert_not_called()


class ScheduleScopeTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.job = {
            "id": "schedule-a", "company_id": "company-a", "branch_id": "branch-a",
            "endpoint_id": "endpoint-a", "job_type": "COLLECT_SYSINFO",
            "payload": {}, "name": "Inventory",
        }

    def test_moved_or_foreign_endpoint_is_not_dispatched(self):
        for company, branch in [("company-a", "branch-b"), ("company-b", "branch-a"), (None, "branch-a")]:
            endpoint = {"id": "endpoint-a", "company_id": company, "branch_id": branch}
            with self.subTest(company=company, branch=branch), mock.patch.object(
                scheduler.db, "get_endpoint", return_value=endpoint
            ), mock.patch("services.entitlements.check_job", return_value=mock.Mock(allowed=True)), mock.patch.object(
                scheduler.db, "create_system_job_once"
            ) as create:
                scheduler._dispatch_job(self.job)
                create.assert_not_called()

    def test_single_offline_target_in_scope_can_still_be_queued(self):
        endpoint = {"id": "endpoint-a", "company_id": "company-a", "branch_id": "branch-a", "status": "offline"}
        with mock.patch.object(scheduler.db, "get_endpoint", return_value=endpoint):
            self.assertEqual(scheduler.scheduled_targets(self.job), [endpoint])

    def test_manual_run_uses_same_current_scope(self):
        endpoint = {"id": "endpoint-a", "company_id": "company-a", "branch_id": "branch-b"}
        with self.app.test_request_context("/", method="POST"):
            g.company = {"id": "company-a"}
            g.admin = {"id": "admin-a", "role": "branch_admin", "branch_id": "branch-a"}
            with mock.patch.object(db, "get_scheduled_job", return_value=self.job), mock.patch.object(
                db, "get_endpoint", return_value=endpoint
            ), mock.patch("services.entitlements.check_job", return_value=mock.Mock(allowed=True)), mock.patch.object(
                db, "create_job"
            ) as create, mock.patch.object(db, "audit"):
                result = inspect.unwrap(schedule.run_now)("schedule-a").get_json()
                self.assertEqual(result["dispatched"], 0)
                create.assert_not_called()

    def test_schedule_form_only_lists_admin_branch(self):
        with self.app.test_request_context("/schedule"):
            g.company = {"id": "company-a"}
            g.admin = {"role": "branch_admin", "branch_id": "branch-a"}
            with mock.patch.object(db, "get_scheduled_jobs", return_value=[]), mock.patch.object(
                db, "get_branches", return_value=[{"id": "branch-a"}, {"id": "branch-b"}]
            ), mock.patch.object(db, "get_endpoints", return_value=[]) as endpoints, mock.patch.object(
                schedule, "render_template", return_value="ok"
            ) as render:
                inspect.unwrap(schedule.index)()
                endpoints.assert_called_once_with("company-a", branch_id="branch-a")
                self.assertEqual(render.call_args.kwargs["branches"], [{"id": "branch-a"}])


class MonitoringScopeTests(unittest.TestCase):
    def test_branchless_admin_fails_closed(self):
        app = Flask(__name__)
        for view in [audit.log, status.index, status.partial, status.status_json, schedule.index]:
            with self.subTest(view=view.__name__), app.test_request_context("/"):
                g.company = {"id": "company-a"}
                g.admin = {"role": "branch_admin", "branch_id": None}
                with mock.patch.object(db, "get_scheduled_jobs", return_value=[]):
                    with self.assertRaises(Forbidden):
                        inspect.unwrap(view)()

    def test_status_json_requests_branch_scoped_counts(self):
        app = Flask(__name__)
        with app.test_request_context("/status/json"):
            g.company = {"id": "company-a"}
            g.admin = {"role": "branch_admin", "branch_id": "branch-a"}
            with mock.patch.object(db, "get_job_queue_stats", return_value={}) as jobs, mock.patch.object(
                db, "get_endpoint_summary", return_value={}
            ) as endpoints:
                inspect.unwrap(status.status_json)()
                jobs.assert_called_once_with("company-a", branch_id="branch-a")
                endpoints.assert_called_once_with("company-a", branch_id="branch-a")

    def test_database_summary_queries_include_branch(self):
        for function in [db.get_job_queue_stats, db.get_endpoint_summary]:
            with self.subTest(function=function.__name__), mock.patch.object(db, "_get", return_value=[]) as get:
                function("company-a", branch_id="branch-a")
                self.assertIn("company_id=eq.company-a", get.call_args.args[0])
                self.assertIn("branch_id=eq.branch-a", get.call_args.args[0])


class BuildFailureTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.claim = "11111111-1111-1111-1111-111111111111"

    def test_stale_or_missing_claim_cannot_fail_build(self):
        for state, header in [("completed", self.claim), ("building", ""), ("building", "22222222-2222-2222-2222-222222222222")]:
            with self.subTest(state=state, header=header), self.app.test_request_context(
                "/", method="POST", json={"error": "old failure"}, headers={"X-Build-Claim": header}
            ), mock.patch.object(db, "get_build_request", return_value={"status": state, "claim_token": self.claim}), mock.patch.object(
                db, "fail_claimed_build"
            ) as fail:
                _, code = inspect.unwrap(build_service.fail)("build-a")
                self.assertEqual(code, 409)
                fail.assert_not_called()

    def test_current_claim_reports_failure_with_atomic_compare(self):
        with self.app.test_request_context(
            "/", method="POST", json={"error": "compile failed"}, headers={"X-Build-Claim": self.claim}
        ), mock.patch.object(db, "get_build_request", return_value={"status": "building", "claim_token": self.claim}), mock.patch.object(
            db, "fail_claimed_build", return_value=True
        ) as fail:
            self.assertTrue(inspect.unwrap(build_service.fail)("build-a").get_json()["ok"])
            fail.assert_called_once_with("build-a", self.claim, "compile failed")

    def test_database_failure_is_claim_and_status_conditional(self):
        with mock.patch.object(db, "_patch", return_value=[]) as patch:
            self.assertFalse(db.fail_claimed_build("build-a", self.claim, "x" * 10000))
            query, data = patch.call_args.args
            self.assertIn("status=eq.building", query)
            self.assertIn("claim_token=eq." + self.claim, query)
            self.assertEqual(len(data["build_log"]), 4000)
            self.assertIsNone(data["lease_expires_at"])
