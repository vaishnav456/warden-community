import pathlib
import sys
import unittest
import base64
import json
from unittest import mock

from flask import Flask, g


SERVER_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from routes import agent_api, endpoints


def undecorated(function):
    while hasattr(function, "__wrapped__"):
        function = function.__wrapped__
    return function


class EndpointManagedIdentityControlTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)

    @mock.patch("services.entitlements.check_job")
    @mock.patch.object(endpoints.db, "get_managed_warden_usernames_for_endpoint")
    @mock.patch.object(endpoints.db, "get_endpoint")
    def test_local_user_action_rejects_managed_identity(self, get_endpoint, managed, check_job):
        get_endpoint.return_value = {
            "id": "endpoint-1", "company_id": "company-1",
            "branch_id": "branch-1", "platform": "windows",
            "capabilities": ["RESET_PASSWORD"],
        }
        managed.return_value = ["warden.alice"]
        check_job.return_value = mock.Mock(allowed=True)
        with self.app.test_request_context(
            "/endpoints/endpoint-1/dispatch-job", method="POST",
            json={
                "type": "RESET_PASSWORD", "windows_user": "WARDEN.ALICE",
                "payload": {"new_password": "must-not-be-queued"},
            },
        ):
            g.company = {"id": "company-1"}
            g.admin = {"id": "admin-1", "role": "company_admin"}
            response, status = undecorated(endpoints.dispatch_job)("endpoint-1")

        self.assertEqual(status, 409)
        self.assertEqual(response.get_json()["error"], "managed_identity_use_directory")

    @mock.patch.object(endpoints.db, "get_managed_warden_usernames_for_endpoint")
    def test_managed_username_query_is_case_insensitive_at_caller(self, managed):
        managed.return_value = ["Warden.Alice"]
        values = {value.casefold() for value in managed("endpoint-1")}
        self.assertIn("warden.alice", values)

    @mock.patch.object(endpoints.db, "get_endpoint")
    def test_technician_cannot_directly_create_local_administrator(self, get_endpoint):
        get_endpoint.return_value = {
            "id": "endpoint-1", "company_id": "company-1",
            "branch_id": "branch-1", "platform": "windows",
            "capabilities": ["CREATE_USER"],
        }
        with self.app.test_request_context(
            "/endpoints/endpoint-1/dispatch-job", method="POST",
            json={"type": "CREATE_USER", "payload": {
                "username": "backdoor", "password": "Secret-123!",
                "is_admin": True,
            }},
        ):
            g.company = {"id": "company-1"}
            g.admin = {"id": "tech-1", "role": "technician"}
            with mock.patch.object(endpoints.db, "create_job") as create_job:
                response, status = undecorated(endpoints.dispatch_job)("endpoint-1")

        self.assertEqual(status, 403)
        self.assertEqual(response.get_json()["error"], "administrator_approval_required")
        create_job.assert_not_called()

    @mock.patch("services.entitlements.check_job", return_value=mock.Mock(allowed=True))
    @mock.patch.object(endpoints.db, "get_endpoint")
    def test_technician_escalation_cannot_use_auto_approval_policy(self, get_endpoint, _check_job):
        get_endpoint.return_value = {
            "id": "endpoint-1", "company_id": "company-1",
            "branch_id": "branch-1", "platform": "windows",
            "capabilities": ["REBOOT"],
        }
        escalation = {"id": "esc-1"}
        with self.app.test_request_context(
            "/endpoints/endpoint-1/dispatch-job", method="POST",
            json={"type": "REBOOT", "payload": {}, "reason": "User requested restart"},
        ):
            g.company = {"id": "company-1", "require_dual_approval": False}
            g.admin = {"id": "tech-1", "role": "technician"}
            with mock.patch.object(endpoints.db, "find_matching_policy", return_value={"id": "policy-1"}), \
                 mock.patch.object(endpoints.db, "create_escalation_request", return_value=escalation), \
                 mock.patch.object(endpoints.db, "approve_escalation") as approve, \
                 mock.patch.object(endpoints.db, "create_job") as create_job, \
                 mock.patch.object(endpoints.db, "audit"):
                response = undecorated(endpoints.dispatch_job)("endpoint-1")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "pending_approval")
        approve.assert_not_called()
        create_job.assert_not_called()


class EndpointPacketCaptureTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)

    def _dispatch(self, payload, *, reason="Investigate TLS connection failure", platform="windows"):
        endpoint = {
            "id": "endpoint-1", "company_id": "company-1",
            "branch_id": "branch-1", "platform": platform,
            "capabilities": ["CAPTURE_PACKETS"],
        }
        with self.app.test_request_context(
            "/endpoints/endpoint-1/dispatch-job", method="POST",
            json={"type": "CAPTURE_PACKETS", "payload": payload, "reason": reason},
        ):
            g.company = {"id": "company-1", "require_dual_approval": True}
            g.admin = {"id": "admin-1", "role": "company_admin"}
            with mock.patch.object(endpoints.db, "get_endpoint", return_value=endpoint), \
                 mock.patch("services.entitlements.check_job", return_value=mock.Mock(allowed=True)), \
                 mock.patch.object(endpoints.db, "find_matching_policy", return_value=None), \
                 mock.patch.object(endpoints.db, "create_escalation_request", return_value={"id": "esc-1"}) as create, \
                 mock.patch.object(endpoints.db, "audit"):
                result = undecorated(endpoints.dispatch_job)("endpoint-1")
        return result, create

    def test_capture_is_bounded_normalized_and_approval_gated(self):
        response, create = self._dispatch({
            "duration_seconds": "10", "max_size_mb": "2", "protocol": "TCP",
            "remote_ip": "203.0.113.7/32", "port": "443",
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "pending_approval")
        saved = create.call_args.kwargs["payload"]
        self.assertEqual(saved, {
            "duration_seconds": 10, "max_size_mb": 2, "protocol": "tcp",
            "remote_ip": "203.0.113.7/32", "port": 443,
        })
        self.assertFalse(create.call_args.kwargs["requires_dual"])

    def test_capture_rejects_missing_reason_bad_filter_and_non_windows(self):
        for payload, reason, platform, expected in (
            ({}, "", "windows", "reason_required_for_packet_capture"),
            ({"duration_seconds": 121}, "diagnostic", "windows", "capture_must_be_5_to_120_seconds_and_1_to_8_mb"),
            ({"remote_ip": "not-an-address"}, "diagnostic", "windows", "invalid_remote_ip_or_cidr"),
            ({}, "diagnostic", "linux", "packet_capture_requires_windows"),
        ):
            result, create = self._dispatch(payload, reason=reason, platform=platform)
            response, status = result
            self.assertEqual(status, 400 if platform == "windows" else 409)
            self.assertEqual(response.get_json()["error"], expected)
            create.assert_not_called()

    def test_capture_download_is_organization_scoped_and_not_cached(self):
        content = b"\x0a\x0d\x0d\x0aWarden capture"
        endpoint = {"id": "endpoint-1", "company_id": "company-1", "branch_id": "branch-1"}
        job = {
            "id": "job-1", "endpoint_id": "endpoint-1", "company_id": "company-1",
            "type": "CAPTURE_PACKETS", "status": "completed",
            "log_output": json.dumps({
                "content_b64": base64.b64encode(content).decode(),
                "download_name": "capture.pcapng",
            }),
        }
        with self.app.test_request_context("/endpoints/endpoint-1/packet-captures/job-1/download"):
            g.company = {"id": "company-1"}
            g.admin = {"id": "admin-1", "role": "company_admin"}
            with mock.patch.object(endpoints.db, "get_endpoint", return_value=endpoint), \
                 mock.patch.object(endpoints.db, "get_job", return_value=job), \
                 mock.patch.object(endpoints, "require_branch_scope"), \
                 mock.patch.object(endpoints.db, "audit") as audit:
                response = undecorated(endpoints.download_packet_capture)("endpoint-1", "job-1")
        self.assertEqual(response.get_data(), content)
        self.assertEqual(response.headers["Cache-Control"], "private, no-store")
        self.assertIn("capture.pcapng", response.headers["Content-Disposition"])
        audit.assert_called_once()

    def test_agent_upload_accepts_only_pcapng_for_capture_jobs(self):
        job = {"id": "job-1", "endpoint_id": "endpoint-1", "type": "CAPTURE_PACKETS"}
        for content, expected_status, expected_error in (
            (b"not a capture", 400, "invalid_pcapng"),
            (b"\x0a\x0d\x0d\x0a valid", 200, None),
        ):
            with self.app.test_request_context(
                "/api/agent/file-content", method="POST", json={
                    "job_id": "job-1", "path": "capture.pcapng",
                    "download_name": "capture.pcapng",
                    "content_b64": base64.b64encode(content).decode(),
                    "size_bytes": len(content),
                },
            ):
                g.endpoint = {"id": "endpoint-1"}
                with mock.patch.object(agent_api.db, "get_job", return_value=job), \
                     mock.patch.object(agent_api.db, "finish_running_job", return_value=True) as finish:
                    result = undecorated(agent_api.file_content)()
            if isinstance(result, tuple):
                response, status = result
            else:
                response, status = result, result.status_code
            self.assertEqual(status, expected_status)
            if expected_error:
                self.assertEqual(response.get_json()["error"], expected_error)
                finish.assert_not_called()
            else:
                finish.assert_called_once()


class TemporarySupportLinkSecurityTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)

    def test_redemption_is_rate_limited_before_database_lookup(self):
        with self.app.test_request_context("/support/unguessable-token"):
            with mock.patch("middleware.security.check_rate_limit", return_value=False), \
                 mock.patch.object(endpoints.db, "get_remote_support_link_by_hash") as lookup:
                response = endpoints.consume_support_link("unguessable-token")

        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.headers["Retry-After"], "60")
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        lookup.assert_not_called()


class BitLockerEscrowTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)

    def test_agent_escrows_only_for_its_running_bitlocker_job(self):
        body = {
            "job_id": "job-1", "volume_mount": "c:",
            "protector_id": "{11111111-2222-3333-4444-555555555555}",
            "recovery_password": "001001-001001-001001-001001-001001-001001-001001-001001",
            "volume_status": "EncryptionInProgress", "protection_status": "On",
            "encryption_percentage": 12.5,
        }
        with self.app.test_request_context("/api/agent/bitlocker-recovery", method="POST", json=body):
            g.endpoint = {"id": "endpoint-1", "company_id": "company-1"}
            with mock.patch.object(agent_api.db, "get_job", return_value={
                "id": "job-1", "endpoint_id": "endpoint-1",
                "type": "ENABLE_BITLOCKER", "status": "running",
            }), mock.patch.object(agent_api.db, "get_company_by_id", return_value={"id": "company-1"}), \
                 mock.patch.object(agent_api.db, "escrow_endpoint_recovery_key", return_value={"id": "key-1"}) as escrow, \
                 mock.patch.object(agent_api.db, "log_endpoint_event"):
                response = undecorated(agent_api.bitlocker_recovery)()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(escrow.call_args.args[4], body["recovery_password"])

    def test_reveal_is_no_store_and_audited_without_key_in_audit(self):
        record = {
            "id": "key-1", "endpoint_id": "endpoint-1", "volume_mount": "C:",
            "protector_id": "protector-1", "recovery_password": "secret-key",
        }
        with self.app.test_request_context("/reveal", method="POST"):
            g.company = {"id": "company-1"}
            g.admin = {"id": "admin-1", "role": "company_admin"}
            with mock.patch.object(endpoints.db, "get_endpoint", return_value={
                "id": "endpoint-1", "company_id": "company-1", "branch_id": "branch-1",
            }), mock.patch.object(endpoints.db, "reveal_endpoint_recovery_key", return_value=record), \
                 mock.patch.object(endpoints.db, "audit") as audit:
                response = undecorated(endpoints.reveal_recovery_key)("endpoint-1", "key-1")
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(response.get_json()["recovery_password"], "secret-key")
        self.assertNotIn("secret-key", repr(audit.call_args))


if __name__ == "__main__":
    unittest.main()
