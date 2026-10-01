import inspect
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
from routes import users
from services import entitlements


class AdminCreationResponseTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.register_blueprint(users.bp)
        self.form = {"email": "person@example.invalid", "full_name": "Test Person",
                     "role": "company_admin", "password": "test-password-only",
                     "confirm_password": "test-password-only"}
        self.patch(users, "_hash_password", "hashed-test-password")
        self.patch(entitlements, "check_capacity", SimpleNamespace(allowed=True))
        self.existing = self.patch(db, "get_admin_by_email", None)
        self.create_admin = self.patch(db, "create_admin_user", {"id": "new-admin"})
        self.audit = self.patch(db, "audit", None)

    def patch(self, obj, name, value):
        patcher = mock.patch.object(obj, name, return_value=value)
        self.addCleanup(patcher.stop)
        return patcher.start()

    def request(self, headers=None):
        with self.app.test_request_context("/users/create", method="POST",
                                           data=self.form, headers=headers or {}):
            g.company = {"id": "tenant-a"}
            g.admin = {"id": "creator-a", "role": "company_admin"}
            return self.app.make_response(inspect.unwrap(users.create)())

    def test_fetch_create_returns_json_not_redirected_html(self):
        response = self.request({"Accept": "application/json"})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.get_json(), {"ok": True})
        self.assertNotIn("Location", response.headers)
        self.assertNotIn("password", response.get_data(as_text=True))
        self.create_admin.assert_called_once()
        self.audit.assert_called_once()

    def test_normal_form_keeps_redirect(self):
        response = self.request({"Accept": "text/html"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/users")

    def test_missing_accept_header_keeps_redirect(self):
        self.assertEqual(self.request().status_code, 302)

    def test_htmx_keeps_html_partial(self):
        self.patch(db, "get_admins_for_company", [])
        self.patch(db, "get_branches", [])
        with mock.patch.object(users, "render_template", return_value="<tr>user</tr>") as render:
            response = self.request({"HX-Request": "true"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_data(as_text=True), "<tr>user</tr>")
        render.assert_called_once()

    def test_duplicate_returns_json_without_creating_again(self):
        self.existing.return_value = {"id": "already-created"}
        response = self.request({"Accept": "application/json"})
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.get_json()["error"], "Email already in use")
        self.create_admin.assert_not_called()
        self.audit.assert_not_called()

    def test_password_validation_remains_json_error(self):
        self.form["confirm_password"] = "different-test-password"
        response = self.request({"Accept": "application/json"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "Passwords do not match")
        self.create_admin.assert_not_called()


if __name__ == "__main__":
    unittest.main()
