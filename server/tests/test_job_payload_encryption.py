import base64
import os
import pathlib
import sys
import unittest
from unittest import mock

SERVER_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

import config
import db
from cryptography.exceptions import InvalidTag
from services import tenant_crypto


class JobPayloadPurposeTests(unittest.TestCase):
    def setUp(self):
        tenant_crypto._dek_cache.clear()
        self.config_patch = mock.patch.object(
            config, "TENANT_MASTER_KEK_B64",
            base64.b64encode(os.urandom(32)).decode(),
        )
        self.config_patch.start()
        provisioned = tenant_crypto.provision_managed("tenant-a")
        self.company = {
            "id": "tenant-a",
            "encryption_mode": "managed",
            **provisioned,
        }

    def tearDown(self):
        self.config_patch.stop()
        tenant_crypto._dek_cache.clear()

    def test_every_job_writer_uses_the_job_payload_encryption_purpose(self):
        payload = {"username": "regression-user", "is_admin": False}
        revoke_payload = {"username": "regression-user", "action": "revoke"}
        cases = [
            ("create_job", lambda: db.create_job(
                "tenant-a", "branch-a", "endpoint-a", "CREATE_USER", payload,
                "admin-a",
            ), "post", ["payload"], [payload]),
            ("create_system_job_once", lambda: db.create_system_job_once(
                "tenant-a", "branch-a", "endpoint-a", "COLLECT_USERS", payload,
            ), "rpc", ["p_encrypted_payload"], [payload]),
            ("create_policy_deployment", lambda: db.create_policy_deployment(
                "tenant-a", "branch-a", {"id": "policy-a", "name": "Policy"},
                payload, "admin-a",
            ), "rpc", ["p_encrypted_payload"], [payload]),
            ("create_warden_identity_with_jobs", lambda: db.create_warden_identity_with_jobs(
                self.company, "regression-user", "Regression User", "hash", False,
                "admin-a", ["endpoint-a"], payload,
            ), "rpc", ["p_encrypted_payload"], [payload]),
            ("create_warden_identity_with_setup_and_jobs", lambda: db.create_warden_identity_with_setup_and_jobs(
                self.company, "regression-user", "user@example.test", "Regression User",
                "hash", False, "admin-a", ["endpoint-a"], payload, "a" * 64,
                "2030-01-01T00:00:00+00:00",
            ), "rpc", ["p_encrypted_payload"], [payload]),
            ("rotate_warden_identity_password", lambda: db.rotate_warden_identity_password(
                self.company, "identity-a", "hash", "admin-a", payload,
            ), "rpc", ["p_encrypted_payload"], [payload]),
            ("set_warden_identity_enabled", lambda: db.set_warden_identity_enabled(
                self.company, "identity-a", True, "admin-a", payload,
            ), "rpc", ["p_encrypted_payload"], [payload]),
            ("reassign_warden_identity", lambda: db.reassign_warden_identity(
                self.company, "identity-a", ["endpoint-a"], "admin-a", payload,
                revoke_payload,
            ), "rpc", ["p_provision_payload", "p_revoke_payload"],
             [payload, revoke_payload]),
            ("create_patch_deployment", lambda: db.create_patch_deployment(
                self.company, {"id": "patch-a"}, ["endpoint-a"], [], payload,
                "admin-a",
            ), "rpc", ["p_encrypted_payload"], [payload]),
        ]

        for name, invoke, transport, fields, expected_values in cases:
            with self.subTest(writer=name):
                with (
                    mock.patch.object(db, "get_company_by_id", return_value=self.company),
                    mock.patch.object(db, "_post", return_value=[]) as post,
                    mock.patch.object(db, "_rpc", return_value=[]) as rpc,
                ):
                    invoke()

                if transport == "post":
                    self.assertTrue(post.called)
                    stored = post.call_args.args[1]
                else:
                    self.assertTrue(rpc.called)
                    stored = rpc.call_args.args[1]
                for field, expected in zip(fields, expected_values):
                    ciphertext = stored[field]
                    self.assertTrue(ciphertext.startswith("v2:"))
                    self.assertEqual(
                        db.decrypt_field(self.company, ciphertext, "job.payload"),
                        expected,
                    )
                    with self.assertRaises(InvalidTag):
                        db.decrypt_field(self.company, ciphertext, "generic")


if __name__ == "__main__":
    unittest.main()
