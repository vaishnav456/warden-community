import pathlib
import sys
import unittest
from unittest.mock import patch

SERVER_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from services import entitlements


def subscription(state="active", endpoint_limit=2, features=None):
    return {
        "status": "active",
        "lifecycle_state": state,
        "plans": {
            "code": "test", "name": "Test", "endpoint_limit": endpoint_limit,
            "admin_limit": 3, "branch_limit": 4, "features": features or {},
        },
    }


class EntitlementTests(unittest.TestCase):
    @patch.object(entitlements.db, "get_active_entitlement_overrides", return_value=[])
    @patch.object(entitlements.db, "get_company_subscription")
    def test_read_only_blocks_mutation(self, get_subscription, _overrides):
        get_subscription.return_value = subscription(state="read_only")
        decision = entitlements.check_mutation("tenant")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "tenant_read_only")

    @patch.object(entitlements.db, "get_company_usage", return_value={"endpoints": 2})
    @patch.object(entitlements.db, "get_active_entitlement_overrides", return_value=[])
    @patch.object(entitlements.db, "get_company_subscription")
    def test_capacity_blocks_at_limit(self, get_subscription, _overrides, _usage):
        get_subscription.return_value = subscription(endpoint_limit=2)
        decision = entitlements.check_capacity("tenant", "endpoints")
        self.assertFalse(decision.allowed)
        self.assertEqual((decision.used, decision.limit), (2, 2))

    @patch.object(entitlements.db, "get_active_entitlement_overrides")
    @patch.object(entitlements.db, "get_company_subscription")
    def test_override_changes_capacity(self, get_subscription, get_overrides):
        get_subscription.return_value = subscription(endpoint_limit=2)
        get_overrides.return_value = [{"entitlement_key": "endpoints", "value": 5}]
        self.assertEqual(entitlements.access("tenant")["limits"]["endpoints"], 5)

    @patch.object(entitlements.db, "get_active_entitlement_overrides", return_value=[])
    @patch.object(entitlements.db, "get_company_subscription")
    def test_disabled_feature_blocks_remote_job(self, get_subscription, _overrides):
        get_subscription.return_value = subscription(features={"remote_control": False})
        decision = entitlements.check_job("tenant", "SETUP_REMOTE_ACCESS")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "feature_not_entitled")


if __name__ == "__main__":
    unittest.main()
