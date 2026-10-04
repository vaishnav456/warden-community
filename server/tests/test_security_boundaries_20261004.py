import asyncio
import base64
import hashlib
import inspect
import time
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch

from flask import Flask, g
from routes import endpoints, agent_api
from services import ws_proxy, entitlements, device_proof
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID
import websockets


class SecurityBoundaryTests(unittest.TestCase):
    def test_real_signature_rejects_modified_request_and_other_device(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "isolated-device")])
        now = datetime.now(timezone.utc)
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=1)).sign(key, hashes.SHA256())
        headers = {"X-Warden-Device-Time":str(int(time.time())), "X-Warden-Device-Nonce":"a"*32, "X-Warden-Device-Certificate":base64.b64encode(cert.public_bytes(serialization.Encoding.PEM)).decode()}
        body = b'{"status":"approved"}'
        target = "/api/agent/remote-consent"
        message = f"warden-request-v1|endpoint|POST|{target}|{headers['X-Warden-Device-Time']}|{'a'*32}|{hashlib.sha256(body).hexdigest()}".encode()
        headers["X-Warden-Device-Signature"] = base64.b64encode(key.sign(message, padding.PKCS1v15(), hashes.SHA256())).decode()
        endpoint = dict(id="endpoint", client_cert_fingerprint=cert.fingerprint(hashes.SHA256()).hex())
        with patch("db.consume_rate_limit", return_value=True):
            device_proof.verify_agent_request(endpoint, headers, "POST", target, body)
            for identity, method, path, contents in [
                (endpoint, "POST", target, b'{"status":"denied"}'),
                (endpoint, "GET", target, body),
                (endpoint, "POST", target+"?other=1", body),
                (dict(endpoint, id="other-device"), "POST", target, body),
            ]:
                with self.assertRaises(Exception):
                    device_proof.verify_agent_request(identity, headers, method, path, contents)

    def test_technician_cannot_modify_containment(self):
        app = Flask(__name__)
        endpoint = dict(id="endpoint", company_id="tenant", branch_id="branch", platform="windows")
        for action in ("contain", "release"):
            with app.test_request_context("/", method="POST", json=dict(action=action, reason="test")), patch.object(endpoints.db, "get_endpoint", return_value=endpoint), patch.object(endpoints, "require_branch_scope"), patch.object(endpoints, "_endpoint_capabilities", return_value={"PUSH_LOCAL_POLICY"}), patch.object(endpoints.db, "create_job") as create:
                g.company = dict(id="tenant")
                g.admin = dict(id="technician", role="technician")
                _, status = inspect.unwrap(endpoints.incident_response)("endpoint")
                self.assertEqual(status, 403)
                create.assert_not_called()

    def test_admin_can_still_contain(self):
        app = Flask(__name__)
        endpoint = dict(id="endpoint", company_id="tenant", branch_id="branch", platform="windows")
        with app.test_request_context("/", method="POST", json=dict(action="contain", reason="test")), patch.object(endpoints.db, "get_endpoint", return_value=endpoint), patch.object(endpoints, "require_branch_scope"), patch.object(endpoints, "_endpoint_capabilities", return_value={"PUSH_LOCAL_POLICY"}), patch.object(entitlements, "check_job", return_value=SimpleNamespace(allowed=True)), patch.object(endpoints.db, "create_job", return_value=dict(id="fake-job")), patch.object(endpoints.db, "log_endpoint_event"), patch.object(endpoints.db, "audit"):
            g.company = dict(id="tenant")
            g.admin = dict(id="admin", role="company_admin")
            _, status = inspect.unwrap(endpoints.incident_response)("endpoint")
            self.assertEqual(status, 202)

    def test_opted_in_endpoint_rejects_token_only_consent(self):
        app = Flask(__name__)
        app.add_url_rule("/api/agent/remote-consent", view_func=agent_api.remote_consent, methods=["POST"])
        endpoint = dict(id="endpoint", company_id="tenant", request_device_proof_required=True)
        with patch.object(agent_api.db, "get_endpoint_by_api_key_hash", return_value=endpoint), patch.object(agent_api.config, "REQUIRE_CLIENT_CERT", False), patch.object(agent_api.db, "update_remote_session_support_state") as update:
            response = app.test_client().post("/api/agent/remote-consent", json=dict(session_id="session", status="approved"), headers={"X-Agent-Key":"test-token"})
            self.assertEqual(response.status_code, 401)
            update.assert_not_called()

    def test_proof_binds_body_path_method_and_query(self):
        headers = {"X-Warden-Device-Time":str(int(time.time())), "X-Warden-Device-Nonce":"a"*32, "X-Warden-Device-Certificate":base64.b64encode(b"test-certificate").decode(), "X-Warden-Device-Signature":"test-signature"}
        body = b'{"status":"approved"}'
        with patch.object(device_proof, "verify_device_signature") as verify, patch("db.consume_rate_limit", return_value=True):
            device_proof.verify_agent_request(dict(id="endpoint"), headers, "POST", "/api/agent/remote-consent?scope=one", body)
        expected = f"warden-request-v1|endpoint|POST|/api/agent/remote-consent?scope=one|{headers['X-Warden-Device-Time']}|{'a'*32}|{hashlib.sha256(body).hexdigest()}".encode()
        self.assertEqual(verify.call_args.args[-1], expected)

    def test_proof_replay_fails_closed(self):
        headers = {"X-Warden-Device-Time":str(int(time.time())), "X-Warden-Device-Nonce":"a"*32, "X-Warden-Device-Certificate":base64.b64encode(b"test").decode(), "X-Warden-Device-Signature":"test"}
        with patch.object(device_proof, "verify_device_signature"), patch("db.consume_rate_limit", return_value=False), self.assertRaises(ValueError):
            device_proof.verify_agent_request(dict(id="endpoint"), headers, "POST", "/test")

    def test_remote_revocation_and_owner_changes_are_authoritative(self):
        session = dict(id="session", endpoint_id="endpoint", company_id="tenant", admin_id="admin", status="active", owner_access_token_version=3)
        owner = dict(id="admin", company_id="tenant", role="technician", is_active=True, access_token_version=3)
        for current, admin, expected in [
            (session, owner, True),
            (dict(session, status="closed"), owner, False),
            (session, dict(owner, is_active=False), False),
            (session, dict(owner, access_token_version=4), False),
            (session, dict(owner, company_id="other"), False),
        ]:
            with patch.object(ws_proxy.db, "get_remote_session", return_value=current), patch.object(ws_proxy.db, "get_admin_by_id", return_value=admin):
                self.assertEqual(ws_proxy._remote_authority_current(session), expected)

    def test_revoked_request_cannot_rebind_remote_to_new_owner_version(self):
        app = Flask(__name__)
        with app.test_request_context("/remote"), patch.object(endpoints.db, "get_remote_session", return_value=dict(admin_id="admin")), patch.object(endpoints.db, "get_admin_by_id", return_value=dict(id="admin", is_active=True, access_token_version=4)), patch.object(endpoints.db, "_patch") as write:
            g.admin = dict(id="admin", access_token_version=3)
            with self.assertRaises(ValueError):
                endpoints.db.update_remote_session_controls("session", "full_control", dict(view=True), "test", True)
            write.assert_not_called()
            g.admin["access_token_version"] = 4
            endpoints.db.update_remote_session_controls("session", "full_control", dict(view=True), "test", True)
            self.assertEqual(write.call_args.args[1]["owner_access_token_version"], 4)

    def test_remote_authorization_watch_stops_on_revocation_or_store_failure(self):
        for failure in (False, RuntimeError("offline")):
            with patch.object(ws_proxy, "_remote_authority_current", return_value=failure if failure is False else None, side_effect=failure if isinstance(failure, Exception) else None):
                asyncio.run(asyncio.wait_for(ws_proxy._watch_remote_authority(dict(id="session")), timeout=1))

    def test_missing_socket_device_proof_closes_opted_in_endpoint(self):
        class Socket:
            request = SimpleNamespace(headers={}, path="/agent-relay/session")
            closed = None
            async def close(self, code, reason=""): self.closed = code
        socket = Socket()
        self.assertFalse(asyncio.run(ws_proxy._agent_socket_proof(socket, dict(id="endpoint", request_device_proof_required=True))))
        self.assertEqual(socket.closed, 1008)


class ActiveRelayRevocationTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_paired_relay_closes_both_peers_after_database_revocation(self):
        session = dict(id="security-session", endpoint_id="security-endpoint", company_id="tenant", admin_id="admin", status="active", capabilities=dict(view=True, control=True), owner_access_token_version=0)
        current = dict(session)
        owner = dict(id="admin", company_id="tenant", role="technician", is_active=True, access_token_version=0)
        ws_proxy._pairs.clear()
        with patch.object(ws_proxy.db, "get_remote_session_by_token", return_value=session), patch.object(ws_proxy.db, "get_remote_session", side_effect=lambda *_:dict(current)), patch.object(ws_proxy.db, "get_admin_by_id", return_value=owner), patch.object(ws_proxy.db, "get_endpoint_by_api_key_hash", return_value=dict(id="security-endpoint")), patch.object(ws_proxy.config, "REQUIRE_CLIENT_CERT", False), patch.object(ws_proxy.db, "close_remote_session"), patch.object(ws_proxy.db, "_patch"), patch.object(ws_proxy, "REMOTE_AUTH_CHECK_SECONDS", 0.01):
            async with websockets.serve(ws_proxy._handle, "127.0.0.1", 0) as server:
                port = server.sockets[0].getsockname()[1]
                async with websockets.connect(f"ws://127.0.0.1:{port}/agent-relay/security-session", additional_headers={"X-Agent-Key":"fake-key"}) as agent:
                    async with websockets.connect(f"ws://127.0.0.1:{port}/remote-ws/security-endpoint", additional_headers={"Cookie":"warden_remote=fake-token"}) as browser:
                        await browser.send('{"type":"mousemove","x":1,"y":1}')
                        self.assertIn("mousemove", await asyncio.wait_for(agent.recv(), 2))
                        current["status"] = "closed"
                        with self.assertRaises(websockets.exceptions.ConnectionClosed):
                            await asyncio.wait_for(browser.recv(), 2)
                        with self.assertRaises(websockets.exceptions.ConnectionClosed):
                            await asyncio.wait_for(agent.recv(), 2)
        self.assertNotIn("security-session", ws_proxy._pairs)
