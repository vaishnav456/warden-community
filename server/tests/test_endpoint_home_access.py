import pathlib
import sys
import unittest


SERVER_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from routes.agent_api import _endpoint_storage_principal


ENDPOINT_ID = "171e3fc0-169e-4b4a-8d96-c4c2febd4964"


class EndpointHomeAccessTests(unittest.TestCase):
    def setUp(self):
        self.endpoint = {
            "id": ENDPOINT_ID,
            "interactive_user": r"DESKTOP-OPH9VC5\vaishnav",
        }
        self.direct = {
            "id": "assignment-a",
            "scope_type": "endpoint",
            "scope_value": ENDPOINT_ID,
            "enabled": True,
        }

    def test_direct_endpoint_share_does_not_require_directory_identity(self):
        principal, assignments = _endpoint_storage_principal(
            self.endpoint, "vaishnav", [self.direct],
        )
        self.assertEqual(principal["username"], "vaishnav")
        self.assertEqual(len(principal["id"]), 36)
        self.assertEqual(assignments, [self.direct])

    def test_direct_share_is_bound_to_current_interactive_user(self):
        principal, assignments = _endpoint_storage_principal(
            self.endpoint, "another-user", [self.direct],
        )
        self.assertIsNone(principal)
        self.assertEqual(assignments, [])

    def test_direct_principal_cannot_inherit_organization_or_branch_shares(self):
        broader = [
            {"scope_type": "tenant", "scope_value": None, "enabled": True},
            {"scope_type": "branch", "scope_value": "branch-a", "enabled": True},
        ]
        principal, assignments = _endpoint_storage_principal(
            self.endpoint, "vaishnav", broader,
        )
        self.assertIsNone(principal)
        self.assertEqual(assignments, [])

    def test_disabled_direct_assignment_is_rejected(self):
        principal, assignments = _endpoint_storage_principal(
            self.endpoint, "vaishnav", [{**self.direct, "enabled": False}],
        )
        self.assertIsNone(principal)
        self.assertEqual(assignments, [])

if __name__ == "__main__":
    unittest.main()
