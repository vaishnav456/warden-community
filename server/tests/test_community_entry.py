import unittest

from flask import Blueprint, Flask, g
from routes.dashboard import bp as dashboard_bp


class CommunityEntryTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.admin = None
        authentication = Blueprint("auth", __name__)

        @authentication.route("/login")
        def login():
            return "Sign in"

        @self.app.before_request
        def context():
            g.admin = self.admin
            g.company = None

        self.app.register_blueprint(authentication)
        self.app.register_blueprint(dashboard_bp)
        self.client = self.app.test_client()

    def test_signed_out_root_opens_local_login(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login")
        self.assertEqual(self.client.get("/", follow_redirects=True).data, b"Sign in")

    def test_signed_in_root_opens_dashboard(self):
        self.admin = {"id": "admin-1", "role": "company_admin"}
        response = self.client.get("/")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/dashboard")

    def test_entry_does_not_redirect_to_hosted_marketing_or_arbitrary_next(self):
        response = self.client.get("/?next=https://example.invalid/")
        self.assertEqual(response.headers["Location"], "/login")
        self.admin = {"id": "admin-1", "role": "company_admin"}
        response = self.client.get("/?next=https://example.invalid/")
        self.assertEqual(response.headers["Location"], "/dashboard")

    def test_dashboard_still_requires_authentication(self):
        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login")
