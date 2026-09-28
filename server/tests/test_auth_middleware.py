import pathlib
import sys
import unittest
from unittest import mock

import jwt
from flask import Flask, g


SERVER_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from middleware import auth


class SingleOrganizationAuthTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)

    def test_current_user_is_bound_to_the_single_organization(self):
        company = {"id": "company-1", "wrapped_dek": "wrapped"}
        admin = {
            "id": "admin-1", "role": "company_admin",
            "company_id": "company-1", "is_active": True,
        }
        with self.app.test_request_context("/"):
            with mock.patch.object(auth, "get_token_from_request", return_value="token"), \
                 mock.patch.object(auth, "decode_access_token", return_value={"sub": "admin-1"}), \
                 mock.patch.object(auth.db, "get_admin_by_id", return_value=admin), \
                 mock.patch.object(auth.db, "get_single_company", return_value=company), \
                 mock.patch.object(auth.db, "ensure_company_encryption", return_value=company):
                auth.load_current_user()
            self.assertEqual(g.admin["id"], "admin-1")
            self.assertEqual(g.company["id"], "company-1")

    def test_account_from_another_organization_fails_closed(self):
        admin = {
            "id": "admin-1", "role": "company_admin",
            "company_id": "other-company", "is_active": True,
        }
        with self.app.test_request_context("/"):
            with mock.patch.object(auth, "get_token_from_request", return_value="token"), \
                 mock.patch.object(auth, "decode_access_token", return_value={"sub": "admin-1"}), \
                 mock.patch.object(auth.db, "get_admin_by_id", return_value=admin), \
                 mock.patch.object(auth.db, "get_single_company", return_value={"id": "company-1"}):
                auth.load_current_user()
            self.assertIsNone(g.admin)
            self.assertIsNone(g.company)

    def test_unsupported_platform_account_fails_closed(self):
        admin = {
            "id": "admin-1", "role": "platform_admin",
            "company_id": None, "is_active": True,
        }
        with self.app.test_request_context("/"):
            with mock.patch.object(auth, "get_token_from_request", return_value="token"), \
                 mock.patch.object(auth, "decode_access_token", return_value={"sub": "admin-1"}), \
                 mock.patch.object(auth.db, "get_admin_by_id", return_value=admin):
                auth.load_current_user()
            self.assertIsNone(g.admin)

    def test_access_token_contains_no_platform_or_routing_claim(self):
        token = auth.issue_access_token({
            "id": "admin-1", "role": "company_admin", "company_id": "company-1",
        })
        claims = jwt.decode(token, auth.config.SECRET_KEY, algorithms=["HS256"])
        self.assertNotIn("platform_admin", claims)
        self.assertNotIn("company_slug", claims)
        self.assertEqual(claims["company_id"], "company-1")


if __name__ == "__main__":
    unittest.main()
