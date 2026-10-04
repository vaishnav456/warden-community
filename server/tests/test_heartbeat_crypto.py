import base64
import json
import os
import time
import unittest
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from flask import Flask, g, jsonify

import config
import db
from services import heartbeat_crypto as crypto, signing, tenant_crypto


class HeartbeatCryptoTests(unittest.TestCase):
    def setUp(self):
        self.signing_key = Ed25519PrivateKey.generate()
        self.patch = mock.patch.object(signing, "_get_private_key", return_value=self.signing_key)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()

    def message(self, endpoint="endpoint-a", api_key="agent-secret", issued=None):
        private = X25519PrivateKey.generate()
        shared = private.exchange(crypto._private_key().public_key())
        context = crypto.aad(endpoint, api_key)
        keys = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=context).derive(shared)
        nonce = os.urandom(12)
        plain = json.dumps(dict(issued_at=int(time.time()) if issued is None else issued,
                                body=dict(cpu_pct=32.5, hostname="PRIVATE-PC"))).encode()
        envelope = dict(version=1, ephemeral_key=base64.b64encode(private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode(),
            nonce=base64.b64encode(nonce).decode(),
            ciphertext=base64.b64encode(AESGCM(keys[:32]).encrypt(nonce, plain, context+b"|request")).decode())
        return envelope, keys, context

    def test_signed_endpoint_bound_key_descriptor(self):
        challenge = base64.b64encode(os.urandom(32)).decode()
        proof = crypto.descriptor("endpoint-a", challenge)
        signature = base64.b64decode(proof.pop("signature"))
        self.signing_key.public_key().verify(signature, json.dumps(proof, sort_keys=True, separators=(",", ":")).encode())
        self.assertEqual(proof["endpoint_id"], "endpoint-a")
        self.assertEqual(proof["challenge"], challenge)
        self.assertEqual(len(base64.b64decode(proof["public_key"])), 32)

    def test_request_response_and_context_binding(self):
        envelope, keys, context = self.message()
        body, response_key, nonce, received_context, replay = crypto.open_request(envelope, "endpoint-a", "agent-secret")
        self.assertEqual(body["cpu_pct"], 32.5)
        self.assertEqual(response_key, keys[32:])
        self.assertEqual(context, received_context)
        self.assertEqual(len(replay), 64)
        response = crypto.seal_response(b'{"ok":true}', response_key, nonce, context, 200)
        aad = context + f"|response|{nonce}|200".encode()
        raw = AESGCM(keys[32:]).decrypt(base64.b64decode(response["nonce"]), base64.b64decode(response["ciphertext"]), aad)
        self.assertEqual(raw, b'{"ok":true}')
        self.assertNotIn("PRIVATE-PC", json.dumps(envelope))
        for endpoint, key in (("endpoint-b", "agent-secret"), ("endpoint-a", "different-key")):
            with self.assertRaises(Exception):
                crypto.open_request(envelope, endpoint, key)
        with self.assertRaises(Exception):
            AESGCM(keys[32:]).decrypt(base64.b64decode(response["nonce"]), base64.b64decode(response["ciphertext"]), context+f"|response|{nonce}|500".encode())

    def test_tamper_expiry_and_malformed_messages(self):
        envelope, _, _ = self.message()
        raw = bytearray(base64.b64decode(envelope["ciphertext"]))
        raw[-1] ^= 1
        envelope["ciphertext"] = base64.b64encode(raw).decode()
        with self.assertRaises(Exception):
            crypto.open_request(envelope, "endpoint-a", "agent-secret")
        for issued in (int(time.time())-301, int(time.time())+301):
            with self.assertRaises(ValueError):
                crypto.open_request(self.message(issued=issued)[0], "endpoint-a", "agent-secret")
        for value in (None, [], dict(version=2), dict(version=1, ephemeral_key="!")):
            with self.assertRaises(Exception):
                crypto.open_request(value, "endpoint-a", "agent-secret")

    def test_replay_failure_closed_and_legacy_compatibility(self):
        app = Flask(__name__)
        @app.before_request
        def authenticated_fixture():
            g.endpoint = dict(id="endpoint-a")
        @app.post(crypto.PATH)
        @crypto.heartbeat_messages
        def heartbeat():
            return jsonify(ok=True, cpu=g.get("heartbeat_body", {}).get("cpu_pct"))
        client = app.test_client()
        envelope, _, _ = self.message()
        headers = {"X-Agent-Key": "agent-secret", "X-Warden-Heartbeat-Encryption": "1"}
        with mock.patch.object(config, "HEARTBEAT_MESSAGE_ENCRYPTION", True), mock.patch.object(db, "_patch"), mock.patch.object(db, "_rpc", return_value=True) as replay:
            self.assertEqual(client.post(crypto.PATH, json=envelope, headers=headers).status_code, 200)
            replay.assert_called_once()
        with mock.patch.object(config, "HEARTBEAT_MESSAGE_ENCRYPTION", True), mock.patch.object(db, "_rpc", return_value=False):
            self.assertEqual(client.post(crypto.PATH, json=envelope, headers=headers).status_code, 409)
        with mock.patch.object(config, "HEARTBEAT_MESSAGE_ENCRYPTION", True), mock.patch.object(db, "_rpc", side_effect=RuntimeError):
            self.assertEqual(client.post(crypto.PATH, json=envelope, headers=headers).status_code, 503)
        with mock.patch.object(config, "HEARTBEAT_MESSAGE_ENCRYPTION", False):
            self.assertEqual(client.post(crypto.PATH, json=envelope, headers=headers).status_code, 503)
            self.assertEqual(client.post(crypto.PATH, json={"cpu_pct": 1}).status_code, 200)

    def test_upgraded_endpoint_cannot_downgrade_after_restart(self):
        app = Flask(__name__)
        @app.before_request
        def authenticated_fixture():
            g.endpoint = dict(id="endpoint-a", heartbeat_encryption_required=True)
        @app.post(crypto.PATH)
        @crypto.heartbeat_messages
        def heartbeat():
            self.fail("A plaintext downgrade must never reach the handler")
        with mock.patch.object(config, "HEARTBEAT_MESSAGE_ENCRYPTION", False):
            response = app.test_client().post(crypto.PATH, json={"cpu_pct": 1})
        self.assertEqual(response.status_code, 426)

    def test_device_proof_rollout_preserves_old_clients_then_fails_closed(self):
        app = Flask(__name__)
        endpoint = dict(id="endpoint-a", heartbeat_encryption_required=True)
        @app.before_request
        def fixture():
            g.endpoint = endpoint
        @app.post(crypto.PATH)
        @crypto.heartbeat_messages
        def heartbeat():
            return jsonify(ok=True)
        client = app.test_client()
        headers = {"X-Agent-Key":"agent-secret","X-Warden-Heartbeat-Encryption":"1"}
        envelope = self.message()[0]
        with mock.patch.object(config,"HEARTBEAT_MESSAGE_ENCRYPTION",True), mock.patch.object(config,"HEARTBEAT_DEVICE_PROOF_REQUIRED",True), mock.patch.object(db,"_rpc",return_value=True), mock.patch.object(db,"_patch") as write:
            self.assertEqual(client.post(crypto.PATH,json=envelope,headers=headers).status_code,200)
            write.assert_not_called()
            envelope.update(device_certificate="certificate",device_signature="signature")
            with mock.patch("services.device_proof.verify_device_signature"):
                self.assertEqual(client.post(crypto.PATH,json=envelope,headers=headers).status_code,200)
            self.assertTrue(write.call_args.args[1]["heartbeat_device_proof_required"])
        endpoint["heartbeat_device_proof_required"]=True
        envelope.pop("device_certificate");envelope.pop("device_signature")
        with mock.patch.object(config,"HEARTBEAT_MESSAGE_ENCRYPTION",True), mock.patch.object(config,"HEARTBEAT_DEVICE_PROOF_REQUIRED",False), mock.patch.object(db,"_rpc") as replay:
            self.assertEqual(client.post(crypto.PATH,json=envelope,headers=headers).status_code,400)
            replay.assert_not_called()


class HeartbeatAtRestTests(unittest.TestCase):
    def test_real_heartbeat_route_consumes_decrypted_body(self):
        from routes import agent_api
        app = Flask(__name__)
        class StopBeforeWrites(Exception):
            pass
        with app.test_request_context(json={"ciphertext": "outer-envelope"}):
            g.endpoint = dict(id="endpoint-a", company_id="tenant-a")
            g.heartbeat_body = dict(hostname="DECRYPTED-PC", platform="windows")
            with mock.patch.object(config, "ENCRYPT_HEARTBEAT_TELEMETRY", False), mock.patch.object(agent_api, "_record_hostname_change", side_effect=StopBeforeWrites) as record:
                with self.assertRaises(StopBeforeWrites):
                    agent_api.heartbeat.__wrapped__.__wrapped__()
                self.assertEqual(record.call_args.args[1], "DECRYPTED-PC")

    def setUp(self):
        tenant_crypto._dek_cache.clear()
        self.patch = mock.patch.object(config, "TENANT_MASTER_KEK_B64", base64.b64encode(os.urandom(32)).decode())
        self.patch.start()
        self.company = dict(id="tenant-a", **tenant_crypto.provision_managed("tenant-a"))
    def tearDown(self):
        self.patch.stop()
        tenant_crypto._dek_cache.clear()

    def test_snapshot_and_history_round_trip_without_readable_copy(self):
        app = Flask(__name__)
        with app.test_request_context():
            g.endpoint = dict(id="endpoint-a", company_id="tenant-a", cpu_pct=8, net_recv_mbps=3)
            with mock.patch.object(config, "ENCRYPT_HEARTBEAT_TELEMETRY", True), mock.patch.object(db, "_endpoint_company", return_value=self.company), mock.patch.object(db, "_patch") as patch:
                db.update_endpoint_heartbeat("endpoint-a", 12.5, 40, 64)
                row = patch.call_args.args[1]
                self.assertTrue(row["heartbeat_encrypted"].startswith("v2:"))
                for field in db._HEARTBEAT_METRIC_FIELDS:
                    self.assertIsNone(row[field])
                decoded = db._decrypt_endpoint(dict(id="endpoint-a", company_id="tenant-a", **row), self.company)
                self.assertEqual(decoded["cpu_pct"], 12.5)
                self.assertEqual(decoded["net_recv_mbps"], 3)
            with mock.patch.object(config, "ENCRYPT_HEARTBEAT_TELEMETRY", True), mock.patch.object(db, "_endpoint_company", return_value=self.company), mock.patch.object(db, "_post") as post:
                db.insert_metric("endpoint-a", 12.5, 40, 64)
                metric = post.call_args.args[1]
                self.assertIsNone(metric["cpu_pct"])
                self.assertTrue(metric["metrics_encrypted"].startswith("v2:"))
            with mock.patch.object(db, "_get", return_value=[dict(cpu_pct=1, ram_used_pct=2), metric]), mock.patch.object(db, "_endpoint_company", return_value=self.company):
                rows = db.get_metrics("endpoint-a")
                self.assertEqual(rows[0]["cpu_pct"], 1)
                self.assertEqual(rows[1]["cpu_pct"], 12.5)
                self.assertEqual(rows[1]["disk_free_gb"], 64)

    def test_ciphertext_failure_is_not_plaintext_fallback(self):
        with self.assertRaises(Exception):
            db._decrypt_endpoint(dict(company_id="tenant-a", heartbeat_encrypted="v2:bad", cpu_pct=1), self.company)
