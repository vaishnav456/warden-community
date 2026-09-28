import unittest

from routes.compliance import _checks_for_endpoint, _validated_checks


class ComplianceContractTests(unittest.TestCase):
    def test_unknown_checks_are_rejected(self):
        self.assertIsNone(_validated_checks(["made_up_check"]))

    def test_platform_checks_are_filtered(self):
        policy = {"checks": ["firewall_enabled", "bitlocker_enabled", "disk_encryption_enabled"]}
        self.assertEqual(
            _checks_for_endpoint({"platform": "linux"}, policy),
            ["firewall_enabled"],
        )
        self.assertEqual(
            _checks_for_endpoint({"platform": "darwin"}, policy),
            ["firewall_enabled", "disk_encryption_enabled"],
        )


if __name__ == "__main__":
    unittest.main()
