import pathlib
import sys
import unittest
import base64
import json
import time
import tempfile
from datetime import datetime, timedelta, timezone
from unittest.mock import patch


SERVER_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from services.effective_policy import resolve_effective_policy
from services.firewall_analysis import evaluate_flow
from services.patch_rollout import assign_rings, endpoint_in_scope
from services.vulnerability_svc import match_software
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from services.home_grants import active_writer_ids, assignment_matches, home_config_for, issue_home_grant, replication_config_for
from services.signing import get_server_pubkey_b64
from routes.agent_api import _normalise_network_flow, _valid_webrtc_offer
from routes.home import _home_update_for, _valid_webrtc_sdp


class EffectivePolicyTests(unittest.TestCase):
    def test_endpoint_overrides_tag_branch_and_tenant_with_provenance(self):
        endpoint = {"id": "ep-1", "branch_id": "b-1", "tags": ["Finance"]}
        assignments = [
            {"id": "a1", "scope_type": "tenant", "priority": 0, "settings": {"lock": 5}},
            {"id": "a2", "scope_type": "branch", "scope_value": "b-1", "priority": 0, "settings": {"lock": 10}},
            {"id": "a3", "scope_type": "tag", "scope_value": "finance", "priority": 0, "settings": {"lock": 15}},
            {"id": "a4", "scope_type": "endpoint", "scope_value": "ep-1", "priority": 0, "settings": {"lock": 20}},
        ]
        result = resolve_effective_policy(endpoint, assignments)
        self.assertEqual(result["settings"]["lock"], 20)
        self.assertEqual([item["scope_type"] for item in result["provenance"]["lock"]],
                         ["tenant", "branch", "tag", "endpoint"])

    def test_equal_precedence_disagreement_is_visible(self):
        endpoint = {"id": "ep-1", "tags": []}
        result = resolve_effective_policy(endpoint, [
            {"id": "a", "scope_type": "tenant", "priority": 0, "settings": {"x": True}},
            {"id": "b", "scope_type": "tenant", "priority": 0, "settings": {"x": False}},
        ])
        self.assertEqual(len(result["conflicts"]), 1)


class PatchRolloutTests(unittest.TestCase):
    def test_scope_and_ring_assignment_are_deterministic(self):
        endpoints = [{"id": str(i), "branch_id": "b", "tags": ["pilot"]} for i in range(20)]
        self.assertTrue(endpoint_in_scope(endpoints[0], {"scope_type": "tag", "scope_value": "PILOT"}))
        first = assign_rings(endpoints, "deployment", 10)
        second = assign_rings(list(reversed(endpoints)), "deployment", 10)
        self.assertEqual([e["id"] for e in first["pilot"]], [e["id"] for e in second["pilot"]])
        self.assertEqual(len(first["pilot"]), 2)


class FirewallAnalysisTests(unittest.TestCase):
    def test_more_specific_rule_wins_and_block_breaks_equal_weight(self):
        flow = {"direction": "out", "protocol": "tcp", "remote_address": "10.1.2.3",
                "remote_port": 443, "process_path": r"C:\Program Files\ERP\erp.exe"}
        result = evaluate_flow(flow, [
            {"name": "allow web", "action": "allow", "direction": "out", "protocol": "tcp", "remote_ports": ["443"]},
            {"name": "block ERP", "action": "block", "direction": "out", "protocol": "tcp",
             "program": r"C:\Program Files\ERP\*.exe", "remote_ports": ["443"]},
        ])
        self.assertEqual(result["action"], "block")
        self.assertEqual(result["rule"], "block ERP")

    def test_network_telemetry_is_postgres_safe_and_integer_bounded(self):
        flow = _normalise_network_flow({
            "protocol": "TCP", "local_address": "::", "local_port": 70000,
            "remote_address": "fe80::d318:d991:96fb:8445%7", "remote_port": "443",
            "process_id": 4294967295, "process_name": "bad\x00process",
            "process_path": "C:\\bad\x00.exe", "state": "Established\x00",
        }, [{"name": "unexpected", "action": "invalid-action", "direction": "out"}])
        self.assertEqual(flow["process_id"], 2147483647)
        self.assertNotIn("\x00", flow["process_name"])
        self.assertNotIn("\x00", flow["process_path"])
        self.assertIsNone(flow["local_port"])
        self.assertEqual(flow["remote_address"], "fe80::d318:d991:96fb:8445")
        self.assertEqual(flow["remote_port"], 443)
        self.assertIn(flow["policy_action"], {"allow", "block", "unmatched"})


class VulnerabilityMatchingTests(unittest.TestCase):
    def test_match_preserves_version_uncertainty(self):
        match = match_software(
            {"name": "Google Chrome", "version": "100.0", "publisher": "Google LLC"},
            {"vendor": "Google", "product": "Chrome"},
        )
        self.assertEqual(match["confidence"], "potential")
        self.assertFalse(match["evidence"]["version_verified"])

    def test_product_name_without_overlap_does_not_match(self):
        self.assertIsNone(match_software(
            {"name": "Microsoft Edge", "publisher": "Microsoft"},
            {"vendor": "Google", "product": "Chrome"},
        ))


class WardenHomeTests(unittest.TestCase):
    def test_home_node_update_manifest_is_versioned_hashed_and_signed(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = pathlib.Path(directory) / "warden-home-node-windows-amd64.exe"
            artifact.write_bytes(b"immutable-home-node-build")
            with patch("routes.home.config.HOME_NODE_DIST_DIR", pathlib.Path(directory)), patch("routes.home.config.HOME_NODE_VERSION", "1.1.0"), patch("routes.home.config.SERVER_URL", "https://warden.example"):
                manifest = _home_update_for(
                    {"id": "node-a"},
                    {"os": "windows", "arch": "amd64", "version": "1.0.0"},
                )
        self.assertEqual(manifest["node_id"], "node-a")
        self.assertEqual(manifest["version"], "1.1.0")
        self.assertEqual(
            manifest["sha256"],
            __import__("hashlib").sha256(b"immutable-home-node-build").hexdigest(),
        )
        signature = base64.b64decode(manifest.pop("signature"))
        message = json.dumps(
            manifest, sort_keys=True, separators=(",", ":")
        ).encode()
        public_key = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(get_server_pubkey_b64())
        )
        public_key.verify(signature, message)

    def test_home_node_update_is_not_offered_for_current_or_unknown_clients(self):
        self.assertIsNone(_home_update_for(
            {"id": "node-a"}, {"os": "windows", "arch": "amd64", "version": "1.1.0"}
        ))
        self.assertIsNone(_home_update_for(
            {"id": "node-a"}, {"os": "windows", "arch": "amd64"}
        ))

    def test_p2p_sdp_validation_requires_fingerprint_and_ice_identity(self):
        offer = "v=0\r\na=ice-ufrag:abc\r\na=fingerprint:sha-256 00:11\r\na=setup:actpass\r\n"
        answer = "v=0\r\na=ice-ufrag:def\r\na=fingerprint:sha-256 22:33\r\na=setup:active\r\n"
        self.assertTrue(_valid_webrtc_offer(offer))
        self.assertTrue(_valid_webrtc_sdp(answer, "answer"))
        self.assertFalse(_valid_webrtc_offer("v=0\r\na=setup:actpass\r\n"))

    def test_p2p_node_configuration_has_no_public_address_or_turn_relay(self):
        seen = datetime.now(timezone.utc).isoformat()
        endpoint = {"id": "ep", "company_id": "company", "branch_id": "branch", "tags": []}
        identity = {"id": "person", "username": "alice"}
        node = {"id": "private", "name": "Private node", "deployment_mode": "p2p",
                "status": "online", "last_seen": seen}
        spaces = [{"id": "space", "name": "Home", "space_type": "home", "enabled": True,
                   "remote_prefix_template": "homes/{identity_id}",
                   "home_space_nodes": [{"priority": 10, "role": "primary",
                                          "writable": True, "home_storage_nodes": node}]}]
        assignments = [{"space_id": "space", "scope_type": "tenant",
                        "scope_value": None, "enabled": True}]
        with patch("services.home_grants.issue_home_grant", return_value="signed"):
            result = home_config_for(endpoint, identity, spaces, assignments)
        configured = result[0]["nodes"][0]
        self.assertEqual(configured["connection_mode"], "p2p")
        self.assertTrue(configured["p2p_url"].startswith("https://warden-home-private.internal:"))
        self.assertIsNone(configured["local_url"])
        self.assertIsNone(configured["public_url"])
        self.assertTrue(all(value.startswith("stun:") for value in configured["stun_urls"]))

    def test_grant_signature_scope_and_expiry_are_offline_verifiable(self):
        token = issue_home_grant(
            company_id="tenant-a", endpoint_id="endpoint-a", identity_id="identity-a",
            space_id="space-a", node_id="node-a", prefix="homes/identity-a",
            permissions=["write", "read"], max_file_bytes=1234, quota_bytes=9876,
            ttl_seconds=900,
        )
        encoded_payload, encoded_signature = token.split(".")
        payload_bytes = base64.urlsafe_b64decode(encoded_payload + "=" * (-len(encoded_payload) % 4))
        signature = base64.urlsafe_b64decode(encoded_signature + "=" * (-len(encoded_signature) % 4))
        public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(get_server_pubkey_b64()))
        public_key.verify(signature, payload_bytes)
        payload = json.loads(payload_bytes)
        self.assertEqual(payload["aud"], "warden-home-node")
        self.assertEqual(payload["company_id"], "tenant-a")
        self.assertEqual(payload["node_id"], "node-a")
        self.assertEqual(payload["prefix"], "homes/identity-a")
        self.assertEqual(payload["max_file_bytes"], 1234)
        self.assertEqual(payload["quota_bytes"], 9876)
        self.assertLessEqual(payload["exp"] - int(time.time()), 900)

    def test_identity_assignment_ignores_stale_preferred_replica(self):
        seen = datetime.now(timezone.utc).isoformat()
        endpoint = {"id": "ep", "company_id": "company", "branch_id": "branch", "tags": []}
        identity = {"id": "person", "username": "alice"}
        nodes = [
            {"priority": 10, "writable": True, "home_storage_nodes": {
                "id": "primary", "name": "Primary", "status": "online", "last_seen": seen,
                "ca_certificate_pem": "private-ca",
            }},
            {"priority": 200, "writable": False, "home_storage_nodes": {"id": "backup", "name": "Backup", "status": "online", "last_seen": seen}},
        ]
        spaces = [{"id": "space", "name": "Home", "space_type": "home", "enabled": True,
                   "remote_prefix_template": "homes/{identity_id}", "home_space_nodes": nodes}]
        assignments = [
            {"space_id": "space", "scope_type": "tenant", "scope_value": None, "enabled": True},
            {"space_id": "space", "scope_type": "identity", "scope_value": "person", "enabled": True,
             "access_mode": "read",
             "preferred_node_id": "backup"},
        ]
        with patch("services.home_grants.issue_home_grant", return_value="signed"):
            result = home_config_for(endpoint, identity, spaces, assignments)
        self.assertEqual(result[0]["nodes"][0]["id"], "primary")
        self.assertEqual(result[0]["nodes"][0]["grant"], "signed")
        self.assertEqual(result[0]["nodes"][0]["ca_certificate_pem"], "private-ca")
        self.assertIsNone(result[0]["nodes"][1]["ca_certificate_pem"])
        self.assertEqual(result[0]["access_mode"], "read")

    def test_endpoint_assignment_matches_only_that_endpoint(self):
        assignment = {"scope_type": "endpoint", "scope_value": "ep-a", "enabled": True}
        identity = {"id": "person"}
        self.assertTrue(assignment_matches(assignment, {"id": "ep-a"}, identity))
        self.assertFalse(assignment_matches(assignment, {"id": "ep-b"}, identity))

    def test_replica_only_pulls_from_primary(self):
        seen = datetime.now(timezone.utc).isoformat()
        memberships = [
            {"priority": 10, "writable": True, "home_storage_nodes": {
                "id": "primary", "status": "online", "last_seen": seen, "ca_certificate_pem": "private-ca",
            }},
            {"priority": 200, "writable": False, "home_storage_nodes": {"id": "backup", "status": "online", "last_seen": seen}},
        ]
        space = {"id": "space", "name": "Home", "remote_prefix_template": "homes/{identity_id}",
                 "home_space_nodes": memberships}
        with patch("services.home_grants.issue_replication_grant", return_value="signed"):
            self.assertEqual(replication_config_for({"id": "primary", "company_id": "c"}, [space]), [])
            peers = replication_config_for({"id": "backup", "company_id": "c"}, [space])
        self.assertEqual([item["target_node_id"] for item in peers], ["primary"])
        self.assertEqual(peers[0]["ca_certificate_pem"], "private-ca")

    def test_private_replica_receives_direct_p2p_writer_transport(self):
        seen = datetime.now(timezone.utc).isoformat()
        memberships = [
            {"priority": 10, "role": "primary", "home_storage_nodes": {
                "id": "primary", "status": "online", "last_seen": seen,
                "deployment_mode": "p2p", "local_url": None, "public_url": None,
            }},
            {"priority": 20, "role": "replica", "home_storage_nodes": {
                "id": "backup", "status": "online", "last_seen": seen,
                "deployment_mode": "p2p",
            }},
        ]
        space = {"id": "space", "name": "Home", "remote_prefix_template": "homes/{identity_id}",
                 "home_space_nodes": memberships}
        with patch("services.home_grants.issue_replication_grant", return_value="signed"):
            peers = replication_config_for({"id": "backup", "company_id": "c"}, [space])
        self.assertEqual(peers[0]["connection_mode"], "p2p")
        self.assertEqual(peers[0]["p2p_url"], "https://warden-home-primary.internal:9443")
        self.assertTrue(peers[0]["stun_urls"])
        self.assertIsNone(peers[0]["local_url"])
        self.assertIsNone(peers[0]["public_url"])

    def test_failover_waits_for_old_grants_then_promotes(self):
        now = datetime.now(timezone.utc)
        space = {"id": "space-a", "availability_mode": "failover", "active_writer_state": "primary", "home_space_nodes": [
            {"priority": 10, "role": "primary", "home_storage_nodes": {
                "id": "primary", "status": "online", "last_seen": (now - timedelta(minutes=10)).isoformat()}},
            {"priority": 20, "role": "failover", "home_storage_nodes": {
                "id": "backup", "status": "online", "last_seen": now.isoformat(),
                "capabilities": {"replication": True, "replication_sync": {"space-a": int(now.timestamp())}}}},
        ]}
        self.assertEqual(active_writer_ids(space, now), [])
        space["home_space_nodes"][0]["home_storage_nodes"]["last_seen"] = (now - timedelta(minutes=23)).isoformat()
        self.assertEqual(active_writer_ids(space, now), ["backup"])

    def test_failover_accepts_replica_synced_before_writer_fence_elapsed(self):
        now = datetime.now(timezone.utc)
        space = {"id": "space-a", "availability_mode": "failover",
                 "active_writer_state": "primary", "home_space_nodes": [
            {"priority": 10, "role": "primary", "home_storage_nodes": {
                "id": "primary", "status": "offline",
                "last_seen": (now - timedelta(minutes=23)).isoformat()}},
            {"priority": 20, "role": "failover", "home_storage_nodes": {
                "id": "backup", "status": "online", "last_seen": now.isoformat(),
                "capabilities": {"replication": True, "replication_sync": {
                    "space-a": int((now - timedelta(minutes=23)).timestamp()),
                }}}},
        ]}
        self.assertEqual(active_writer_ids(space, now), ["backup"])

    def test_active_active_requires_one_shared_cluster(self):
        now = datetime.now(timezone.utc).isoformat()
        space = {"availability_mode": "shared_active_active", "home_space_nodes": [
            {"priority": 10, "role": "primary", "home_storage_nodes": {
                "id": "a", "status": "online", "last_seen": now, "storage_cluster_id": "shared-a",
                "capabilities": {"encryption_key_id": "key-a"}}},
            {"priority": 20, "role": "failover", "home_storage_nodes": {
                "id": "b", "status": "online", "last_seen": now, "storage_cluster_id": "shared-a",
                "capabilities": {"encryption_key_id": "key-a"}}},
        ]}
        self.assertEqual(active_writer_ids(space), ["a", "b"])
        space["home_space_nodes"][1]["home_storage_nodes"]["storage_cluster_id"] = "different"
        self.assertEqual(active_writer_ids(space), [])
        space["home_space_nodes"][1]["home_storage_nodes"]["storage_cluster_id"] = "shared-a"
        space["home_space_nodes"][1]["home_storage_nodes"]["capabilities"]["encryption_key_id"] = "key-b"
        self.assertEqual(active_writer_ids(space), [])

    def test_failover_skips_stale_replica_and_selects_next_fresh_candidate(self):
        now = datetime.now(timezone.utc)
        fresh = {"replication": True, "replication_sync": {"space-a": int(now.timestamp())}}
        stale = {"replication": True, "replication_sync": {"space-a": int(now.timestamp()) - 3600}}
        space = {"id": "space-a", "availability_mode": "failover", "active_writer_state": "primary", "home_space_nodes": [
            {"priority": 10, "role": "primary", "home_storage_nodes": {"id": "primary", "status": "offline", "last_seen": (now - timedelta(hours=1)).isoformat()}},
            {"priority": 20, "role": "failover", "home_storage_nodes": {"id": "stale", "status": "online", "last_seen": now.isoformat(), "capabilities": stale}},
            {"priority": 30, "role": "failover", "home_storage_nodes": {"id": "fresh", "status": "online", "last_seen": now.isoformat(), "capabilities": fresh}},
        ]}
        self.assertEqual(active_writer_ids(space, now), ["fresh"])

    def test_all_writer_outage_fails_closed(self):
        now = datetime.now(timezone.utc)
        space = {"id": "space-a", "availability_mode": "failover", "active_writer_state": "a", "home_space_nodes": [
            {"priority": 10, "role": "primary", "home_storage_nodes": {"id": "a", "status": "offline", "last_seen": (now - timedelta(hours=1)).isoformat()}},
            {"priority": 20, "role": "failover", "home_storage_nodes": {"id": "b", "status": "offline", "last_seen": (now - timedelta(hours=1)).isoformat()}},
        ]}
        self.assertEqual(active_writer_ids(space, now), [])


if __name__ == "__main__":
    unittest.main()
