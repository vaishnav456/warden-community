import pathlib
import sys
import unittest
from unittest import mock


SERVER_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

import db
from routes.enroll import (
    _normalise_hardware_id, _profile_rejection, desired_managed_hostname,
    queue_managed_identity_recovery, recovery_admin_payload,
)


class EnrollmentProfileTests(unittest.TestCase):
    def setUp(self):
        self.profile = {
            "id": "profile-1",
            "is_active": True,
            "hostname_pattern": "MUM-LT-*",
            "domain_suffix": "corp.example.com",
            "require_pre_registration": True,
        }
        self.claim = {
            "profile_id": "profile-1",
            "expected_hostname": "MUM-LT-001",
            "status": "pending",
        }

    def test_profile_accepts_matching_pre_registered_device(self):
        result = _profile_rejection(
            self.profile, "MUM-LT-001", "hardware-1",
            {"domain": "west.corp.example.com"}, self.claim,
        )
        self.assertIsNone(result)

    def test_profile_rejects_unregistered_device(self):
        self.assertEqual(
            _profile_rejection(
                self.profile, "MUM-LT-001", "hardware-1",
                {"domain": "corp.example.com"}, None,
            ),
            "device_not_pre_registered",
        )

    def test_profile_accepts_autopilot_serial_claim_before_hardware_is_known(self):
        claim = dict(self.claim)
        claim["serial_number"] = "SERIAL-1"
        self.assertIsNone(_profile_rejection(
            self.profile, "MUM-LT-001", "",
            {"domain": "corp.example.com", "serial_number": "SERIAL-1"}, claim,
        ))

    def test_profile_treats_hostname_and_domain_as_post_enrollment_state(self):
        self.assertIsNone(
            _profile_rejection(
                self.profile, "DESKTOP-NEW", "hardware-1",
                {}, self.claim,
            )
        )

    def test_managed_hostname_is_stable_and_windows_safe(self):
        profile = dict(self.profile, hostname_pattern="MUM-LP-OFFCE-*")
        first = desired_managed_hostname(profile, None, "hardware-1", "install-1")
        second = desired_managed_hostname(profile, None, "hardware-1", "install-2")
        self.assertEqual(first, second)
        self.assertLessEqual(len(first), 15)
        self.assertRegex(first, r"^[A-Z0-9-]+$")

    def test_pre_registered_expected_hostname_becomes_desired_name(self):
        self.assertEqual(
            desired_managed_hostname(self.profile, self.claim, "hardware-1", "install-1"),
            "MUM-LT-001",
        )

    def test_invalid_vendor_hardware_ids_are_not_used_for_reclaim(self):
        self.assertEqual(_normalise_hardware_id("DEFAULT STRING"), "")
        self.assertEqual(
            _normalise_hardware_id("4C4C4544-0038-ABCD"),
            "4c4c4544-0038-abcd",
        )

    @mock.patch.object(db, "_get")
    @mock.patch.object(db, "get_company_by_id")
    @mock.patch.object(db, "blind_index", return_value="blind-hardware")
    @mock.patch.object(db, "_decrypt_endpoint", side_effect=lambda row, company=None: row)
    def test_hardware_recovery_is_organization_scoped_and_case_insensitive(
        self, decrypt, blind, get_company, get,
    ):
        company = {"id": "company-1"}
        get_company.return_value = company
        get.return_value = [{"id": "endpoint-1"}]
        self.assertEqual(
            db.get_endpoint_by_hardware_id("company-1", "abcd")["id"],
            "endpoint-1",
        )
        query = get.call_args.args[0]
        self.assertIn("company_id=eq.company-1", query)
        self.assertIn("hardware_id_hash=eq.blind-hardware", query)
        blind.assert_called_once_with(company, "abcd", "endpoint.hardware-id")

    @mock.patch.object(db, "_post")
    @mock.patch.object(db, "decrypt_field", side_effect=lambda company, value, purpose="generic": value)
    @mock.patch.object(db, "encrypt_field", return_value={"ciphertext": "encrypted"})
    @mock.patch.object(db, "get_company_by_id", return_value={"id": "company-1"})
    def test_lockdown_recovery_secret_is_organization_encrypted(self, company, encrypt, decrypt, post):
        post.return_value = [{
            "id": "profile-1", "company_id": "company-1",
            "lockdown_config": {"ciphertext": "encrypted"},
        }]
        db.create_enrollment_profile(
            "company-1", "branch-1", "Default", "manual", "", "",
            False, True, "admin-1", warden_only_mode=True,
            lockdown_config={
                "recovery_admin_username": "WardenRecovery",
                "recovery_admin_password": "Secret-Password-123!",
            },
        )
        encrypt.assert_called_once()
        sent = post.call_args.args[1]
        self.assertEqual(sent["lockdown_config"], {"ciphertext": "encrypted"})
        self.assertNotIn("Secret-Password-123!", repr(sent))

    def test_warden_only_profile_stages_admin_without_locking_users(self):
        payload = recovery_admin_payload({
            "warden_only_mode": True,
            "lockdown_config": {
                "recovery_admin_username": "WardenRecovery",
                "recovery_admin_password": "Secret-Password-123!",
            },
        })
        self.assertEqual(payload["username"], "WardenRecovery")
        self.assertTrue(payload["is_admin"])
        self.assertEqual(payload["purpose"], "warden_recovery")
        self.assertNotIn("allowed_users", payload)

    def test_non_lockdown_profile_does_not_stage_recovery_admin(self):
        self.assertIsNone(recovery_admin_payload({"warden_only_mode": False}))

    def test_reenrollment_recovers_only_active_managed_identities(self):
        active = {
            "id": "i1", "username": "jane", "display_name": "Jane",
            "is_enabled": True, "password_version": 2,
            "warden_identity_assignments": [{"endpoint_id": "e1", "status": "active"}],
        }
        disabled = {
            "id": "i2", "username": "blocked", "is_enabled": False,
            "warden_identity_assignments": [{"endpoint_id": "e1", "status": "active"}],
        }
        detail = {**active, "is_admin": False, "profile_photo": None}
        with mock.patch.object(db, "get_warden_identities", return_value=[active, disabled]), \
             mock.patch.object(db, "get_warden_identity", return_value=detail), \
             mock.patch.object(db, "create_job", return_value={"id": "job-1"}) as create_job, \
             mock.patch.object(db, "upsert_warden_identity_assignment") as upsert:
            queued = queue_managed_identity_recovery("c1", "b1", "e1")
        self.assertEqual(queued, 1)
        payload = create_job.call_args.args[4]
        self.assertTrue(payload["recover_existing"])
        self.assertNotIn("password", payload)
        upsert.assert_called_once_with("i1", "e1", "pending", 2, "job-1")


if __name__ == "__main__":
    unittest.main()
