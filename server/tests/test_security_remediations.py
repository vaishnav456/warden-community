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
from services import tenant_crypto


class TenantEncryptionBindingTests(unittest.TestCase):
    def setUp(self):
        tenant_crypto._dek_cache.clear()
        self.master = base64.b64encode(os.urandom(32)).decode()
        self.config_patch = mock.patch.object(config, "TENANT_MASTER_KEK_B64", self.master)
        self.config_patch.start()

    def tearDown(self):
        self.config_patch.stop()
        tenant_crypto._dek_cache.clear()

    def test_ciphertext_is_bound_to_tenant_and_field(self):
        provisioned = tenant_crypto.provision_managed("tenant-a")
        ciphertext = tenant_crypto.encrypt_value(
            "tenant-a", "managed", provisioned["wrapped_dek"],
            {"secret": True}, "integration.config",
        )
        self.assertTrue(ciphertext.startswith("v2:"))
        with self.assertRaises(Exception):
            tenant_crypto.decrypt_value(
                "tenant-a", "managed", provisioned["wrapped_dek"],
                ciphertext, "job.payload",
            )
        tenant_crypto._dek_cache.clear()
        with self.assertRaises(Exception):
            tenant_crypto.decrypt_value(
                "tenant-b", "managed", provisioned["wrapped_dek"],
                ciphertext, "integration.config",
            )


class ApprovalIndependenceTests(unittest.TestCase):
    def test_requester_cannot_approve_own_request(self):
        request = {
            "id": "request-1", "company_id": "company-1",
            "requested_by": "admin-1", "requires_dual_approval": False,
        }
        with mock.patch.object(db, "get_escalation_request", return_value=request), \
             mock.patch.object(db, "_rpc") as rpc:
            token, updated = db.approve_escalation(
                "request-1", "admin-1", "pending",
            )
        self.assertIsNone(token)
        self.assertIsNone(updated)
        rpc.assert_not_called()


if __name__ == "__main__":
    unittest.main()
