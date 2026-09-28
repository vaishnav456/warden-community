import pathlib
import sys
import unittest
from unittest import mock

from flask import Flask, g


SERVER_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from routes import settings


def _undecorated(view):
    while hasattr(view, "__wrapped__"):
        view = view.__wrapped__
    return view


class SettingsPageTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)

    def test_tokens_defaults_legacy_build_platform_without_name_error(self):
        build = {
            "id": "build-1", "branch_id": None, "config_json": {},
            "status": "completed", "created_at": "2026-09-25T00:00:00+00:00",
        }
        with self.app.test_request_context("/settings/tokens"):
            g.company = {"id": "company-1"}
            g.admin = {"id": "admin-1"}
            with mock.patch.object(settings.db, "get_branches", return_value=[]), \
                 mock.patch.object(settings.db, "get_enrollment_tokens", return_value=[]), \
                 mock.patch.object(settings.db, "get_enrollment_profiles", return_value=[]), \
                 mock.patch.object(settings.db, "get_build_requests", return_value=[build]), \
                 mock.patch.object(settings.db, "get_policy_templates", return_value=[]), \
                 mock.patch.object(settings.db, "get_app_library", return_value=[]), \
                 mock.patch.object(settings, "render_template", return_value="ok") as render:
                self.assertEqual(_undecorated(settings.tokens)(), "ok")
        self.assertEqual(render.call_args.kwargs["tokens"][0]["target_platform"], "windows-amd64")

    def test_builds_supplies_target_platform_to_template(self):
        build = {
            "id": "build-1", "branch_id": None, "status": "completed",
            "created_at": "2026-09-25T00:00:00+00:00",
            "completed_at": "2026-09-25T00:00:10+00:00",
        }
        with self.app.test_request_context("/settings/builds"):
            g.company = {"id": "company-1"}
            g.admin = {"id": "admin-1"}
            with mock.patch.object(settings.db, "get_branches", return_value=[]), \
                 mock.patch.object(settings.db, "get_build_requests", return_value=[build]), \
                 mock.patch.object(settings.db, "get_latest_completed_build", return_value=None), \
                 mock.patch.object(settings, "render_template", return_value="ok") as render:
                self.assertEqual(_undecorated(settings.builds)(), "ok")
        self.assertEqual(render.call_args.kwargs["recent_builds"][0]["target_platform"], "windows-amd64")

    def test_policy_templates_renders_page_with_policy_catalog(self):
        with self.app.test_request_context("/settings/policy-templates"):
            g.company = {"id": "company-1"}
            g.admin = {"id": "admin-1", "role": "company_admin"}
            g.is_superadmin = False
            with mock.patch.object(settings.db, "get_policy_templates", return_value=[]), \
                 mock.patch.object(settings.db, "get_policy_deployments", return_value=[]), \
                 mock.patch.object(settings.db, "get_branches", return_value=[]), \
                 mock.patch.object(settings.db, "get_endpoints", return_value=[]), \
                 mock.patch.object(settings, "render_template", return_value="ok") as render:
                self.assertEqual(_undecorated(settings.policy_templates)(), "ok")

        self.assertEqual(render.call_args.args[0], "settings/policy_templates.html")
        self.assertTrue(render.call_args.kwargs["can_manage_templates"])
        self.assertNotIn("windows_firewall_rules", render.call_args.kwargs["catalog"])


if __name__ == "__main__":
    unittest.main()
