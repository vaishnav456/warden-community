import pathlib
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

from flask import Flask, g

SERVER_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

import db
from routes.agent_api import authenticate_warden_identity, refreshed_home_config, report_users
from routes.directory import (
    _csv_cell, create_local_user, create_warden_identity, export_csv, filter_directory_accounts,
    generate_endpoint_password, group_directory_accounts,
    reassign_warden_identity, repair_warden_identity, reset_warden_identity_password,
    setup_warden_identity_password,
)


class DirectoryTests(unittest.TestCase):
    def test_warden_agent_auth_returns_bounded_offline_grant_without_hash(self):
        app = Flask(__name__)
        identity = {
            "id": "i1", "username": "jane-a1b2c3",
            "login_email": "jane@example.com", "display_name": "Jane",
            "password_hash": "bcrypt-hash", "password_version": 4,
            "session_version": 2, "offline_access_hours": 12,
            "is_enabled": True, "conditional_access": {},
            "warden_identity_assignments": [{"status": "active"}],
        }
        with app.test_request_context("/api/agent/identity/authenticate", method="POST",
                                      json={"username": "jane@example.com", "password": "Secret!123456"}):
            g.endpoint = {"id": "e1", "company_id": "c1"}
            with mock.patch.object(db, "get_warden_identity_for_login", return_value=identity), \
                 mock.patch.object(db, "record_warden_login_success") as success, \
                 mock.patch.object(db, "log_warden_identity_login") as log_login, \
                 mock.patch.object(db, "get_home_spaces", return_value=[]), \
                 mock.patch.object(db, "get_home_assignments", return_value=[]), \
                 mock.patch("routes.agent_api.check_rate_limit", return_value=True), \
                 mock.patch("routes.auth._check_password", return_value=True):
                response = authenticate_warden_identity.__wrapped__()
        body = response.get_json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["session_version"], 2)
        self.assertIsNotNone(body["offline_valid_until"])
        self.assertNotIn("password_hash", body)
        self.assertEqual(body["home"], [])
        self.assertEqual(body["username"], "jane-a1b2c3")
        success.assert_called_once_with("i1")
        log_login.assert_called_once()

    def test_warden_agent_auth_fails_closed_for_inactive_assignment(self):
        app = Flask(__name__)
        identity = {
            "id": "i1", "username": "jane", "is_enabled": True,
            "warden_identity_assignments": [{"status": "pending"}],
        }
        with app.test_request_context("/api/agent/identity/authenticate", method="POST",
                                      json={"username": "jane", "password": "Secret!123456"}):
            g.endpoint = {"id": "e1", "company_id": "c1"}
            with mock.patch.object(db, "get_warden_identity_for_login", return_value=identity), \
                 mock.patch.object(db, "log_warden_identity_login"), \
                 mock.patch("routes.agent_api.check_rate_limit", return_value=True):
                response, status = authenticate_warden_identity.__wrapped__()
        self.assertEqual(status, 403)
        self.assertEqual(response.get_json()["error"], "not_assigned")

    def test_warden_agent_auth_blocks_initial_password_setup(self):
        app = Flask(__name__)
        identity = {
            "id": "i1", "username": "jane", "is_enabled": True,
            "password_setup_required": True,
            "warden_identity_assignments": [{"status": "active"}],
        }
        with app.test_request_context("/api/agent/identity/authenticate", method="POST",
                                      json={"username": "jane", "password": "Secret!123456"}):
            g.endpoint = {"id": "e1", "company_id": "c1"}
            with mock.patch.object(db, "get_warden_identity_for_login", return_value=identity), \
                 mock.patch.object(db, "log_warden_identity_login"), \
                 mock.patch("routes.agent_api.check_rate_limit", return_value=True), \
                 mock.patch("routes.auth._check_password") as check_password:
                response, status = authenticate_warden_identity.__wrapped__()
        self.assertEqual(status, 403)
        self.assertEqual(response.get_json()["error"], "password_setup_required")
        check_password.assert_not_called()

    def test_home_config_refresh_accepts_enabled_identity_with_active_assignment(self):
        app = Flask(__name__)
        identity = {
            "id": "i1", "username": "jane", "is_enabled": True,
            "warden_identity_assignments": [{"status": "active"}],
        }
        with app.test_request_context("/api/agent/home-config", method="POST",
                                      json={"username": "jane"}):
            g.endpoint = {"id": "e1", "company_id": "c1"}
            with mock.patch.object(db, "get_warden_identity_for_login", return_value=identity), \
                 mock.patch.object(db, "get_home_spaces", return_value=[]), \
                 mock.patch.object(db, "get_home_assignments", return_value=[]):
                response = refreshed_home_config.__wrapped__()
        self.assertTrue(response.get_json()["ok"])
        self.assertEqual(response.get_json()["home"], [])

    def test_home_config_refresh_rejects_inactive_assignment(self):
        app = Flask(__name__)
        identity = {
            "id": "i1", "username": "jane", "is_enabled": True,
            "warden_identity_assignments": [{"status": "pending"}],
        }
        with app.test_request_context("/api/agent/home-config", method="POST",
                                      json={"username": "jane"}):
            g.endpoint = {"id": "e1", "company_id": "c1"}
            with mock.patch.object(db, "get_warden_identity_for_login", return_value=identity):
                with self.assertRaises(Exception) as caught:
                    refreshed_home_config.__wrapped__()
        self.assertEqual(getattr(caught.exception, "code", None), 404)

    def test_same_sid_is_grouped_across_endpoints(self):
        rows = [
            {
                "id": "a1", "endpoint_id": "e1", "username": "jane",
                "sid": "S-1-5-21-1-1001", "account_type": "domain",
                "principal_name": "CORP\\jane", "is_enabled": True,
                "is_admin": False, "last_synced": "2026-09-25T01:00:00Z",
                "endpoints": {"id": "e1", "hostname": "PC-1", "status": "online"},
            },
            {
                "id": "a2", "endpoint_id": "e2", "username": "jane.smith",
                "sid": "S-1-5-21-1-1001", "account_type": "domain",
                "principal_name": "CORP\\jane.smith", "is_enabled": True,
                "is_admin": True, "last_synced": "2026-09-25T02:00:00Z",
                "endpoints": {"id": "e2", "hostname": "PC-2", "status": "offline"},
            },
        ]
        identities = group_directory_accounts(rows)
        self.assertEqual(len(identities), 1)
        self.assertEqual(len(identities[0]["accounts"]), 2)
        self.assertTrue(identities[0]["is_admin"])
        self.assertEqual(identities[0]["last_synced"], "2026-09-25T02:00:00Z")

    def test_local_accounts_without_sid_never_merge_across_endpoints(self):
        rows = [
            {"endpoint_id": "e1", "username": "Administrator", "account_type": "local",
             "endpoints": {"id": "e1", "hostname": "PC-1"}},
            {"endpoint_id": "e2", "username": "Administrator", "account_type": "local",
             "endpoints": {"id": "e2", "hostname": "PC-2"}},
        ]
        self.assertEqual(len(group_directory_accounts(rows)), 2)

    def test_filters_and_risk_sort_are_predictable(self):
        identities = [
            {"display_name": "Alice", "principal_name": "Alice", "username": "alice",
             "sid": "1", "domain_name": "", "account_type": "local", "is_admin": False,
             "all_enabled": True, "last_synced": None, "accounts": [{"hostname": "PC-1"}]},
            {"display_name": "Bob", "principal_name": "Bob", "username": "bob",
             "sid": "2", "domain_name": "", "account_type": "domain", "is_admin": True,
             "all_enabled": False, "last_synced": None, "accounts": [{"hostname": "PC-2"}]},
        ]
        filtered = filter_directory_accounts(identities, access="admin", sort="access")
        self.assertEqual([item["username"] for item in filtered], ["bob"])
        self.assertEqual(filter_directory_accounts(identities, query="pc-1")[0]["username"], "alice")

    def test_csv_cells_neutralize_spreadsheet_formulas(self):
        self.assertEqual(_csv_cell("=HYPERLINK('bad')"), "'=HYPERLINK('bad')")
        self.assertEqual(_csv_cell("normal"), "normal")

    def test_company_directory_uses_one_organization_and_branch_scoped_query(self):
        with mock.patch.object(db, "_get", return_value=[]) as get:
            self.assertEqual(db.get_company_windows_users("company-1", "branch-1"), [])
        path = get.call_args.args[0]
        self.assertIn("endpoints!inner", path)
        self.assertIn("endpoints.company_id=eq.company-1", path)
        self.assertIn("endpoints.branch_id=eq.branch-1", path)
        self.assertIn("endpoints.is_active=eq.true", path)
        self.assertIn("present=eq.true", path)

    def test_agent_inventory_is_validated_and_replaced_atomically(self):
        app = Flask(__name__)
        body = {"users": [{
            "username": "jane", "display_name": "Jane Doe",
            "sid": "S-1-5-21-1-1001", "principal_name": "CORP\\jane",
            "account_type": "domain", "domain_name": "CORP",
            "is_admin": True, "is_enabled": True,
        }]}
        with app.test_request_context(json=body):
            g.endpoint = {"id": "endpoint-1"}
            with mock.patch.object(db, "replace_windows_users", return_value=1) as replace:
                response = report_users.__wrapped__()
        self.assertEqual(response.get_json(), {"ok": True, "count": 1})
        users = replace.call_args.args[1]
        self.assertEqual(users[0]["sid"], "S-1-5-21-1-1001")
        self.assertEqual(users[0]["account_type"], "domain")

    def test_agent_inventory_rejects_duplicate_or_malformed_accounts(self):
        app = Flask(__name__)
        for body, error in [
            ({"users": [{"username": "Jane"}, {"username": "jane"}]}, "duplicate_username"),
            ({"users": [{"username": "jane", "sid": "not-a-sid"}]}, "invalid_sid"),
            ({"users": [{"username": "jane", "is_admin": "false"}]}, "invalid_account_flags"),
            ({"users": "not-a-list"}, "invalid_users"),
        ]:
            with self.subTest(error=error), app.test_request_context(json=body):
                g.endpoint = {"id": "endpoint-1"}
                response, status = report_users.__wrapped__()
                self.assertEqual(status, 400)
                self.assertEqual(response.get_json()["error"], error)

    def test_csv_export_uses_organization_scoped_rows_and_safe_filename(self):
        app = Flask(__name__)
        row = {
            "id": "a1", "endpoint_id": "e1", "username": "=danger",
            "display_name": "Jane", "sid": "S-1-5-21-1-1001",
            "account_type": "local", "is_enabled": True, "is_admin": False,
            "last_synced": "2026-09-25T01:00:00Z",
            "endpoints": {"id": "e1", "hostname": "PC-1", "status": "online"},
        }
        with app.test_request_context("/directory/export.csv"):
            g.company = {"id": "company-1", "slug": "tenant-one"}
            g.admin = {"id": "admin-1", "role": "company_admin"}
            with mock.patch.object(db, "get_branches", return_value=[]), \
                 mock.patch.object(db, "get_company_windows_users", return_value=[row]) as users, \
                 mock.patch.object(db, "audit") as audit:
                response = export_csv.__wrapped__.__wrapped__()
        users.assert_called_once_with("company-1", branch_id=None)
        audit.assert_called_once()
        self.assertIn("warden-directory-tenant-one.csv", response.headers["Content-Disposition"])
        self.assertIn("'=danger", response.get_data(as_text=True))

    def test_generated_endpoint_password_meets_complexity_and_is_random(self):
        passwords = {generate_endpoint_password() for _ in range(20)}
        self.assertEqual(len(passwords), 20)
        for password in passwords:
            self.assertGreaterEqual(len(password), 20)
            self.assertTrue(any(c.isupper() for c in password))
            self.assertTrue(any(c.islower() for c in password))
            self.assertTrue(any(c.isdigit() for c in password))
            self.assertTrue(any(not c.isalnum() for c in password))

    def test_directory_assignment_uses_unique_passwords_and_preserves_existing(self):
        app = Flask(__name__)
        body = {
            "username": "jane", "full_name": "Jane Doe",
            "endpoint_ids": ["e2", "e3"],
            "is_admin": False, "must_change_password": False,
            "delete_unselected": True,
        }
        endpoints = [
            {"id": "e1", "hostname": "PC-1", "branch_id": "b1", "status": "online"},
            {"id": "e2", "hostname": "PC-2", "branch_id": "b1", "status": "online"},
            {"id": "e3", "hostname": "PC-3", "branch_id": "b1", "status": "offline"},
        ]
        inventory = [
            {"endpoint_id": "e1", "username": "jane", "account_type": "local", "is_enabled": True},
            {"endpoint_id": "e2", "username": "Jane", "account_type": "local", "is_enabled": False},
        ]
        counter = iter(range(1, 10))

        def make_job(*args, **kwargs):
            return {"id": f"job-{next(counter)}"}

        def make_escalation(*args, **kwargs):
            return {"id": "escalation-1"}

        with app.test_request_context("/directory/users", method="POST", json=body):
            g.company = {"id": "company-1"}
            g.admin = {"id": "admin-1", "role": "company_admin", "branch_id": None}
            with mock.patch.object(db, "get_endpoints", return_value=endpoints), \
                 mock.patch.object(db, "get_branches", return_value=[{"id": "b1", "name": "Main"}]), \
                 mock.patch.object(db, "get_company_windows_users", return_value=inventory), \
                 mock.patch.object(db, "create_job", side_effect=make_job) as create_job, \
                 mock.patch.object(db, "create_escalation_request", side_effect=make_escalation) as create_escalation, \
                 mock.patch.object(db, "audit") as audit, \
                 mock.patch("routes.directory.generate_endpoint_password", return_value="Unique-PC3-Password!9"), \
                 mock.patch("services.entitlements.check_job", return_value=SimpleNamespace(allowed=True)):
                response, status = create_local_user.__wrapped__.__wrapped__.__wrapped__()

        self.assertEqual(status, 201)
        self.assertEqual(response.get_json()["affected_count"], 3)
        self.assertEqual(response.get_json()["assigned_count"], 2)
        calls = create_job.call_args_list
        self.assertEqual([call.args[3] for call in calls], [
            "ENABLE_USER", "CREATE_USER",
        ])
        create_payload = calls[1].args[4]
        self.assertEqual(create_payload["password"], "Unique-PC3-Password!9")
        self.assertTrue(create_payload["must_change_password"])
        self.assertEqual(create_escalation.call_args.kwargs["operation"], "DELETE_USER")
        self.assertEqual(create_escalation.call_args.kwargs["endpoint_id"], "e1")
        self.assertTrue(create_escalation.call_args.kwargs["requires_dual"])
        self.assertEqual(response.get_json()["escalations"][0]["status"], "pending_approval")
        self.assertEqual(response.get_json()["unchanged_count"], 1)
        self.assertEqual(response.get_json()["one_time_credentials"][0]["endpoint_id"], "e3")
        self.assertNotIn("password", audit.call_args.args[3])

    def test_explicit_rotation_generates_a_different_password_per_endpoint(self):
        app = Flask(__name__)
        body = {
            "username": "jane", "endpoint_ids": ["e1", "e2"],
            "is_admin": False, "delete_unselected": False, "rotate_passwords": True,
        }
        endpoints = [
            {"id": "e1", "hostname": "PC-1", "branch_id": "b1", "status": "online"},
            {"id": "e2", "hostname": "PC-2", "branch_id": "b1", "status": "online"},
        ]
        inventory = [
            {"endpoint_id": "e1", "username": "jane", "account_type": "local", "is_enabled": True},
            {"endpoint_id": "e2", "username": "jane", "account_type": "local", "is_enabled": True},
        ]
        with app.test_request_context("/directory/users", method="POST", json=body):
            g.company = {"id": "company-1"}
            g.admin = {"id": "admin-1", "role": "company_admin", "branch_id": None}
            with mock.patch.object(db, "get_endpoints", return_value=endpoints), \
                 mock.patch.object(db, "get_branches", return_value=[{"id": "b1", "name": "Main"}]), \
                 mock.patch.object(db, "get_company_windows_users", return_value=inventory), \
                 mock.patch.object(db, "create_job", side_effect=[{"id": "j1"}, {"id": "j2"}]) as create_job, \
                 mock.patch.object(db, "audit"), \
                 mock.patch("routes.directory.generate_endpoint_password", side_effect=["Per-PC-1-Password!", "Per-PC-2-Password!"]), \
                 mock.patch("services.entitlements.check_job", return_value=SimpleNamespace(allowed=True)):
                response, status = create_local_user.__wrapped__.__wrapped__.__wrapped__()
        self.assertEqual(status, 201)
        payloads = [call.args[4] for call in create_job.call_args_list]
        self.assertEqual([p["new_password"] for p in payloads], [
            "Per-PC-1-Password!", "Per-PC-2-Password!",
        ])
        self.assertEqual(len(response.get_json()["one_time_credentials"]), 2)
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_directory_assignment_rejects_out_of_scope_endpoint(self):
        app = Flask(__name__)
        body = {
            "username": "jane", "password": "Strong-Shared-Password!",
            "endpoint_ids": ["outside"], "is_admin": False,
            "must_change_password": True, "delete_unselected": False,
        }
        with app.test_request_context("/directory/users", method="POST", json=body):
            g.company = {"id": "company-1"}
            g.admin = {"id": "admin-1", "role": "branch_admin", "branch_id": "b1"}
            with mock.patch.object(db, "get_endpoints", return_value=[]), \
                 mock.patch.object(db, "get_branches", return_value=[]), \
                 mock.patch.object(db, "create_job") as create_job:
                response, status = create_local_user.__wrapped__.__wrapped__.__wrapped__()
        self.assertEqual(status, 404)
        self.assertEqual(response.get_json()["error"], "endpoint_not_found")
        create_job.assert_not_called()

    def test_warden_identity_creation_uses_one_atomic_database_operation(self):
        app = Flask(__name__)
        body = {
            "login_email": "jane.doe@example.com", "display_name": "Jane Doe",
            "password": "Strong-Warden-Password!9",
            "endpoint_ids": ["e1", "e2"], "is_admin": False,
        }
        endpoints = [
            {"id": "e1", "hostname": "PC-1", "branch_id": "b1", "platform": "windows", "capabilities": ["PROVISION_WARDEN_IDENTITY", "WARDEN_SHADOW_CREDENTIAL", "WARDEN_SIGNIN"]},
            {"id": "e2", "hostname": "PC-2", "branch_id": "b1", "platform": "windows", "capabilities": ["PROVISION_WARDEN_IDENTITY", "WARDEN_SHADOW_CREDENTIAL", "WARDEN_SIGNIN"]},
        ]
        with app.test_request_context("/directory/identities", method="POST", json=body):
            g.company = {"id": "company-1"}
            g.admin = {"id": "admin-1", "role": "company_admin", "branch_id": None}
            with mock.patch.object(db, "get_endpoints", return_value=endpoints), \
                 mock.patch.object(db, "get_branches", return_value=[{"id": "b1", "name": "Main"}]), \
                 mock.patch.object(db, "get_company_windows_users", return_value=[]), \
                 mock.patch.object(db, "create_warden_identity_with_setup_and_jobs",
                                   return_value={"identity_id": "i1", "queued": 2}) as create_atomic, \
                 mock.patch.object(db, "audit") as audit, \
                 mock.patch("routes.directory.url_for", return_value="https://warden.test/identity/setup/token"), \
                 mock.patch("routes.auth._hash_password", return_value="bcrypt-hash"):
                response, status = create_warden_identity.__wrapped__.__wrapped__.__wrapped__()
        self.assertEqual(status, 201)
        self.assertEqual(response.get_json()["queued_count"], 2)
        self.assertEqual(create_atomic.call_count, 1)
        args = create_atomic.call_args.args
        self.assertRegex(args[1], r"^jane\.doe-[0-9a-f]{6}$")
        self.assertEqual(args[2], "jane.doe@example.com")
        self.assertEqual(args[7], ["e1", "e2"])
        self.assertNotIn("password", args[8])
        self.assertEqual(args[8]["credential_mode"], "managed_shadow_v1")
        self.assertNotIn("password", audit.call_args.args[3])
        self.assertIn("/identity/setup/", response.get_json()["setup_url"])
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_warden_password_reset_link_keeps_current_password_active(self):
        app = Flask(__name__)
        identity = {"id": "i1", "username": "jane"}
        with app.test_request_context("/directory/identities/i1/password", method="POST", json={}):
            g.company = {"id": "company-1"}
            g.admin = {"id": "admin-1", "role": "company_admin"}
            with mock.patch.object(db, "get_warden_identity", return_value=identity), \
                 mock.patch.object(db, "update_warden_identity") as update_identity, \
                 mock.patch.object(db, "audit"), \
                 mock.patch("routes.directory.url_for", return_value="https://warden.test/identity/setup/token"):
                response = reset_warden_identity_password.__wrapped__.__wrapped__.__wrapped__("i1")
        self.assertTrue(response.get_json()["ok"])
        self.assertIn("/identity/setup/", response.get_json()["setup_url"])
        self.assertFalse(update_identity.call_args.args[2]["password_setup_required"])
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_warden_password_setup_link_renders_as_secure_response(self):
        app = Flask(__name__)
        identity = {
            "id": "i1", "username": "jane", "display_name": "Jane",
            "password_setup_expires_at": "2099-09-26T00:00:00+00:00",
        }
        token = "a" * 43
        with app.test_request_context(f"/identity/setup/{token}"):
            with mock.patch.object(db, "get_warden_identity_for_password_setup", return_value=identity), \
                 mock.patch("routes.directory.render_template", return_value="<html>setup</html>"):
                response = setup_warden_identity_password(token)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_data(as_text=True), "<html>setup</html>")
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")

    def test_warden_password_setup_submission_completes_identity(self):
        app = Flask(__name__)
        identity = {
            "id": "i1", "username": "jane", "display_name": "Jane",
            "password_setup_expires_at": "2099-09-26T00:00:00+00:00",
        }
        token = "b" * 43
        with app.test_request_context(
            f"/identity/setup/{token}", method="POST",
            data={"password": "Strong-Warden-Password!9", "password_confirm": "Strong-Warden-Password!9"},
        ):
            with mock.patch.object(db, "get_warden_identity_for_password_setup", return_value=identity), \
                 mock.patch.object(db, "complete_warden_identity_password_setup", return_value={"id": "i1"}) as complete, \
                 mock.patch("routes.directory.check_rate_limit", return_value=True), \
                 mock.patch("routes.auth._hash_password", return_value="bcrypt-hash"), \
                 mock.patch("routes.directory.render_template", return_value="<html>complete</html>"):
                response = setup_warden_identity_password(token)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        complete.assert_called_once_with(mock.ANY, "bcrypt-hash")

    def test_warden_identity_accepts_agent_without_optional_signin_provider(self):
        app = Flask(__name__)
        body = {
            "username": "jane", "display_name": "Jane Doe",
            "password": "Strong-Warden-Password!9",
            "endpoint_ids": ["e1"], "is_admin": False,
        }
        legacy_endpoint = {
            "id": "e1", "hostname": "PC-1", "branch_id": "b1",
            "platform": "windows", "capabilities": ["PROVISION_WARDEN_IDENTITY", "WARDEN_SHADOW_CREDENTIAL"],
        }
        with app.test_request_context("/directory/identities", method="POST", json=body):
            g.company = {"id": "company-1"}
            g.admin = {"id": "admin-1", "role": "company_admin", "branch_id": None}
            with mock.patch.object(db, "get_endpoints", return_value=[legacy_endpoint]), \
                 mock.patch.object(db, "get_branches", return_value=[{"id": "b1", "name": "Main"}]), \
                 mock.patch.object(db, "get_company_windows_users", return_value=[]), \
                 mock.patch.object(db, "create_warden_identity_with_setup_and_jobs",
                                   return_value={"identity_id": "i1", "queued": 1}) as create_atomic, \
                 mock.patch.object(db, "audit"), \
                 mock.patch("routes.directory.url_for", return_value="https://warden.test/identity/setup/token"), \
                 mock.patch("routes.auth._hash_password", return_value="bcrypt-hash"):
                response, status = create_warden_identity.__wrapped__.__wrapped__.__wrapped__()
        self.assertEqual(status, 201)
        self.assertEqual(response.get_json()["queued_count"], 1)
        create_atomic.assert_called_once()

    def test_warden_identity_never_takes_over_existing_local_account(self):
        app = Flask(__name__)
        body = {
            "username": "jane", "display_name": "Jane",
            "password": "Strong-Warden-Password!9",
            "endpoint_ids": ["e1"], "is_admin": False,
        }
        with app.test_request_context("/directory/identities", method="POST", json=body):
            g.company = {"id": "company-1"}
            g.admin = {"id": "admin-1", "role": "company_admin", "branch_id": None}
            with mock.patch.object(db, "get_endpoints", return_value=[
                    {"id": "e1", "hostname": "PC-1", "branch_id": "b1", "platform": "windows", "capabilities": ["PROVISION_WARDEN_IDENTITY", "WARDEN_SHADOW_CREDENTIAL", "WARDEN_SIGNIN"]}]), \
                 mock.patch.object(db, "get_branches", return_value=[{"id": "b1", "name": "Main"}]), \
                 mock.patch.object(db, "get_company_windows_users", return_value=[
                    {"endpoint_id": "e1", "username": "Jane", "account_type": "local"}]), \
                 mock.patch.object(db, "create_warden_identity_with_setup_and_jobs") as create_atomic:
                response, status = create_warden_identity.__wrapped__.__wrapped__.__wrapped__()
        self.assertEqual(status, 409)
        self.assertEqual(response.get_json()["error"], "local_account_conflict")
        create_atomic.assert_not_called()

    def test_warden_reassignment_does_not_require_user_password_and_is_atomic(self):
        app = Flask(__name__)
        body = {"endpoint_ids": ["e2"]}
        identity = {
            "id": "i1", "username": "jane", "display_name": "Jane",
            "password_hash": "bcrypt-hash", "password_version": 3,
            "is_admin": False,
        }
        endpoint = {"id": "e2", "hostname": "PC-2", "branch_id": "b1",
                    "platform": "windows", "capabilities": ["PROVISION_WARDEN_IDENTITY", "WARDEN_SHADOW_CREDENTIAL", "WARDEN_SIGNIN"]}
        with app.test_request_context("/directory/identities/i1/assignments", method="POST", json=body):
            g.company = {"id": "company-1"}
            g.admin = {"id": "admin-1", "role": "company_admin", "branch_id": None}
            with mock.patch.object(db, "get_warden_identity", return_value=identity), \
                 mock.patch.object(db, "get_endpoints", return_value=[endpoint]), \
                 mock.patch.object(db, "get_branches", return_value=[{"id": "b1", "name": "Main"}]), \
                 mock.patch.object(db, "reassign_warden_identity",
                                   return_value={"provisioned": 1, "revoked": 1}) as reassign, \
                 mock.patch.object(db, "audit") as audit:
                response = reassign_warden_identity.__wrapped__.__wrapped__.__wrapped__("i1")
        self.assertEqual(response.get_json()["provisioned"], 1)
        self.assertEqual(reassign.call_count, 1)
        self.assertEqual(reassign.call_args.args[2], ["e2"])
        self.assertNotIn("password", reassign.call_args.args[4])
        self.assertEqual(reassign.call_args.args[4]["credential_mode"], "managed_shadow_v1")
        self.assertNotIn("password", audit.call_args.args[3])

    def test_warden_identity_repair_is_explicit_and_assignment_scoped(self):
        app = Flask(__name__)
        identity = {
            "id": "i1", "username": "jane", "display_name": "Jane",
            "password_version": 3, "is_admin": False, "profile_photo": None,
        }
        expanded = {**identity, "warden_identity_assignments": [
            {"endpoint_id": "e1", "status": "active"},
            {"endpoint_id": "outside", "status": "active"},
        ]}
        endpoint = {"id": "e1", "hostname": "PC-1", "branch_id": "b1"}
        with app.test_request_context("/directory/identities/i1/repair", method="POST"):
            g.company = {"id": "company-1"}
            g.admin = {"id": "admin-1", "role": "company_admin", "branch_id": None}
            with mock.patch.object(db, "get_warden_identity", return_value=identity), \
                 mock.patch.object(db, "get_warden_identities", return_value=[expanded]), \
                 mock.patch.object(db, "get_endpoints", return_value=[endpoint]), \
                 mock.patch.object(db, "get_branches", return_value=[]), \
                 mock.patch.object(db, "create_job", return_value={"id": "job-1"}) as create_job, \
                 mock.patch.object(db, "upsert_warden_identity_assignment") as upsert, \
                 mock.patch.object(db, "audit"):
                response = repair_warden_identity.__wrapped__.__wrapped__.__wrapped__("i1")
        self.assertEqual(response.get_json()["queued_count"], 1)
        payload = create_job.call_args.args[4]
        self.assertTrue(payload["recover_existing"])
        self.assertEqual(payload["credential_mode"], "managed_shadow_v1")
        self.assertNotIn("password", payload)
        upsert.assert_called_once_with("i1", "e1", "pending", 3, "job-1")


if __name__ == "__main__":
    unittest.main()
