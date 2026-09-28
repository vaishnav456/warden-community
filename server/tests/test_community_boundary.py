import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SERVER = ROOT / "server"


class CommunityBoundaryTests(unittest.TestCase):
    def test_saas_control_plane_is_absent(self):
        self.assertFalse((SERVER / "routes" / "superadmin.py").exists())
        self.assertFalse((SERVER / "templates" / "superadmin").exists())
        for removed in (
            "2026-08-03-superadmin-saas.sql",
            "2026-09-27-platform-control-plane.sql",
        ):
            self.assertFalse((ROOT / "migrations" / removed).exists())

    def test_schema_physically_allows_only_one_organization(self):
        schema = (ROOT / "db-init" / "02-schema.sql").read_text(encoding="utf-8")
        self.assertIn(
            "singleton       BOOLEAN NOT NULL DEFAULT TRUE UNIQUE CHECK (singleton)",
            schema,
        )
        self.assertIn(
            "CHECK (role IN ('company_admin', 'branch_admin', 'technician'))",
            schema,
        )
        for removed_table in (
            "tenant_access_grants",
            "platform_feature_flags",
            "platform_feature_overrides",
            "subscriptions",
            "plans",
        ):
            self.assertNotIn(f"CREATE TABLE endpt.{removed_table}", schema)

    def test_server_has_no_platform_admin_route_or_role(self):
        app = (SERVER / "app.py").read_text(encoding="utf-8")
        auth = (SERVER / "middleware" / "auth.py").read_text(encoding="utf-8")
        self.assertNotIn("superadmin", app)
        self.assertNotIn("superadmin", auth)
        self.assertIn("db.get_single_company()", auth)


if __name__ == "__main__":
    unittest.main()
