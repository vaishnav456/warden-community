import pathlib
import sys
import unittest

SERVER_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from services import entitlements


class CommunityFeatureTests(unittest.TestCase):
    def test_community_access_has_no_commercial_capacity_limits(self):
        access = entitlements.access("organization")
        self.assertEqual(access["plan_code"], "community")
        self.assertIsNone(access["limits"]["endpoints"])
        self.assertTrue(entitlements.check_capacity("organization", "endpoints").allowed)

    def test_features_jobs_and_mutations_are_not_subscription_gated(self):
        self.assertTrue(entitlements.check_mutation("organization").allowed)
        self.assertTrue(entitlements.check_feature("organization", "remote_control").allowed)
        self.assertTrue(entitlements.check_job("organization", "SETUP_REMOTE_ACCESS").allowed)

    def test_no_cross_organization_rollout_cohort_is_required(self):
        self.assertTrue(entitlements.platform_feature_enabled("organization", "linux_agent"))
        self.assertEqual(entitlements.effective_platform_features("organization"), {})


if __name__ == "__main__":
    unittest.main()
