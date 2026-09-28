import pathlib
import sys
import unittest
from unittest import mock

from flask import Flask, g


SERVER_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

import db
from routes import endpoints


def undecorated(function):
    while hasattr(function, "__wrapped__"):
        function = function.__wrapped__
    return function


class EndpointRetirementTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)

    @mock.patch.object(endpoints.db, "audit")
    @mock.patch.object(endpoints.db, "close_endpoint_work")
    @mock.patch.object(endpoints.db, "retire_endpoint")
    @mock.patch.object(endpoints.db, "get_endpoint")
    def test_manual_removal_retires_without_agent_job(self, get_endpoint, retire, close_work, audit):
        get_endpoint.return_value = {
            "id": "endpoint-1",
            "company_id": "company-1",
            "branch_id": "branch-1",
            "hostname": "PC-1",
            "is_active": True,
            "cloudflare_cert_id": None,
        }
        with self.app.test_request_context("/endpoints/endpoint-1/remove-from-warden", method="POST"):
            g.company = {"id": "company-1"}
            g.admin = {"id": "admin-1", "role": "company_admin"}
            response = undecorated(endpoints.remove_from_warden)("endpoint-1")

        self.assertEqual(response.status_code, 200)
        retire.assert_called_once_with("endpoint-1", clear_cloudflare_cert_id=True)
        close_work.assert_called_once_with("endpoint-1", "admin-1")
        audit.assert_called_once()
        self.assertFalse(audit.call_args.args[3]["agent_uninstalled"])
        self.assertTrue(audit.call_args.args[3]["license_released"])

    @mock.patch.object(db, "_patch")
    @mock.patch.object(db, "_endpoint_company", return_value={"id": "company-1"})
    @mock.patch.object(db, "_endpoint_encrypt", return_value="v2:encrypted-note")
    def test_retirement_closes_inflight_jobs_and_open_alerts(
        self, encrypt, endpoint_company, patch,
    ):
        db.close_endpoint_work("endpoint-1", "admin-1")
        self.assertEqual(patch.call_count, 2)
        self.assertIn("status=in.(pending,approved,running)", patch.call_args_list[0].args[0])
        self.assertEqual(patch.call_args_list[0].args[1]["status"], "cancelled")
        self.assertIn("is_resolved=eq.false", patch.call_args_list[1].args[0])
        self.assertTrue(patch.call_args_list[1].args[1]["is_resolved"])
        self.assertEqual(
            patch.call_args_list[1].args[1]["resolution_note"],
            "v2:encrypted-note",
        )

    @mock.patch.object(db, "_patch")
    @mock.patch.object(db, "_endpoint_company")
    @mock.patch.object(db, "_encrypt_endpoint_fields", side_effect=lambda company, fields: fields)
    @mock.patch.object(db, "_decrypt_endpoint", side_effect=lambda row, company=None: row)
    def test_reactivation_reuses_inactive_installation(
        self, decrypt, encrypt, endpoint_company, patch,
    ):
        endpoint_company.return_value = {"id": "company-1"}
        patch.return_value = [{"id": "endpoint-1", "is_active": True}]
        result = db.reenroll_endpoint(
            "endpoint-1", "branch-2", "PC-RENAMED", "new-hash",
            "hardware-1", "token-2",
        )
        path, fields = patch.call_args.args
        self.assertEqual(path, "endpoints?id=eq.endpoint-1")
        self.assertTrue(fields["is_active"])
        self.assertEqual(fields["branch_id"], "branch-2")
        self.assertEqual(fields["enrollment_token_id"], "token-2")
        self.assertEqual(result["id"], "endpoint-1")


if __name__ == "__main__":
    unittest.main()
