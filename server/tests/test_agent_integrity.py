import base64
import os
import unittest
from unittest import mock
from services import agent_integrity, signing
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

class AgentIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.endpoint = dict(id="endpoint-a", company_id="tenant-a", branch_id="branch-a", platform="windows", arch="amd64",
                             installation_id="installation-a", client_cert_fingerprint="c"*64, api_key_hash="d"*64)
        self.challenge = base64.b64encode(os.urandom(32)).decode()
        self.hash = "a" * 64

    def test_server_does_not_sign_unknown_hash(self):
        with mock.patch.object(agent_integrity.db, "_get", return_value=[]):
            self.assertIsNone(agent_integrity.manifest(self.endpoint, self.challenge, "2.6.55", self.hash))

    def test_manifest_is_signed_only_for_exact_approved_build(self):
        fresh = dict(self.endpoint)
        def persist(path, data):
            fresh.update(data)
        with mock.patch.object(agent_integrity.db, "_get", return_value=[dict(id="build-a")]) as query, mock.patch.object(signing, "_get_private_key", return_value=Ed25519PrivateKey.generate()), mock.patch.object(agent_integrity.db, "get_company_by_id", return_value=dict(id="tenant-a")), mock.patch.object(agent_integrity.db, "_endpoint_encrypt", side_effect=lambda c,f,v:v), mock.patch.object(agent_integrity.db, "_patch", side_effect=persist), mock.patch.object(agent_integrity.db, "get_endpoint", return_value=fresh):
            proof = agent_integrity.manifest(self.endpoint, self.challenge, "2.6.55", self.hash)
            self.assertEqual(proof["sha256"], self.hash)
            self.assertEqual(proof["endpoint_id"], "endpoint-a")
            self.assertIn("sha256=eq." + self.hash, query.call_args.args[0])
            self.assertIn("agent_version=eq.2.6.55", query.call_args.args[0])
            self.assertTrue(proof["signature"])
            self.assertEqual(proof["measurement_sha256"], agent_integrity.measurement(proof))
            other = dict(proof, endpoint_id="endpoint-b")
            self.assertNotEqual(agent_integrity.measurement(other), proof["measurement_sha256"])

    def test_claimed_verified_report_is_independently_checked(self):
        with mock.patch.object(agent_integrity.db, "get_company_by_id", return_value=dict(id="tenant-a")), mock.patch.object(agent_integrity.db, "_get", return_value=[]), mock.patch.object(agent_integrity.db, "_patch") as patch, mock.patch.object(agent_integrity.db, "_endpoint_encrypt", side_effect=lambda company, field, value: value), mock.patch.object(agent_integrity.db, "get_open_alert", return_value=None), mock.patch.object(agent_integrity.db, "create_alert") as alert:
            agent_integrity.record_report(self.endpoint, dict(agent_version="2.6.55", agent_integrity=dict(sha256=self.hash,status="verified")))
            saved = patch.call_args.args[1]["agent_integrity_encrypted"]
            self.assertEqual(saved["status"], "unverified")
            self.assertEqual(alert.call_args.args[3], "agent_integrity")
            self.assertEqual(alert.call_args.args[4], "critical")

    def test_malformed_integrity_request_is_rejected(self):
        for digest in ("", "b"*63, "g"*64, None):
            with self.assertRaises(ValueError):
                agent_integrity.manifest(self.endpoint,self.challenge,"2.6.55",digest)
