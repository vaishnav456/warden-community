import pathlib
import sys
import unittest
from unittest import mock

import jwt
from flask import Flask, g, request
from werkzeug.exceptions import Forbidden
from werkzeug.routing import Rule


SERVER_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from middleware import auth


class PlatformMfaBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)

    @staticmethod
    def _protected():
        return "protected"

    def _context(self, path="/tenant", endpoint="dashboard.index", headers=None):
        context = self.app.test_request_context(path, headers=headers or {})
        context.push()
        request.url_rule = Rule(path, endpoint=endpoint)
        g.admin = {"id": "admin-1", "mfa_enabled": False}
        g.is_superadmin = True
        self.addCleanup(context.pop)

    def test_unenrolled_platform_admin_is_redirected_from_tenant_route(self):
        self._context()
        protected = auth.login_required(self._protected)
        with mock.patch.object(auth, "url_for", return_value="/setup-mfa"):
            response = protected()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/setup-mfa")

    def test_unenrolled_platform_admin_json_request_fails_closed(self):
        self._context(headers={"Accept": "application/json"})
        protected = auth.login_required(self._protected)
        with self.assertRaises(Forbidden):
            protected()

    def test_mfa_setup_remains_reachable(self):
        self._context(path="/setup-mfa", endpoint="auth.setup_mfa")
        protected = auth.login_required(self._protected)
        self.assertEqual(protected(), "protected")

    def test_enrolled_platform_admin_and_tenant_admin_are_not_blocked(self):
        self._context()
        protected = auth.login_required(self._protected)
        g.admin["mfa_enabled"] = True
        self.assertEqual(protected(), "protected")
        g.admin["mfa_enabled"] = False
        g.is_superadmin = False
        self.assertEqual(protected(), "protected")

    def test_stale_superadmin_claim_cannot_override_current_database_role(self):
        with self.app.test_request_context("/"):
            with mock.patch.object(auth, "get_token_from_request", return_value="token"), \
                 mock.patch.object(auth, "decode_access_token", return_value={
                     "sub": "admin-1", "superadmin": True,
                 }), \
                 mock.patch.object(auth.db, "get_admin_by_id", return_value={
                     "id": "admin-1", "email": "former-platform@example.com",
                     "role": "company_admin", "company_id": "company-1",
                     "is_active": True,
                 }), \
                 mock.patch.object(auth.db, "get_company_by_id", return_value={
                     "id": "company-1",
                 }):
                auth.load_current_user()
            self.assertFalse(g.is_superadmin)

    def test_access_token_platform_claim_comes_only_from_database_role(self):
        token = auth.issue_access_token({
            "id": "admin-1", "email": "configured@example.com",
            "role": "company_admin", "company_id": "company-1",
        })
        claims = jwt.decode(token, auth.config.SECRET_KEY, algorithms=["HS256"])
        self.assertFalse(claims["superadmin"])


if __name__ == "__main__":
    unittest.main()
