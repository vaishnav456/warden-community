import pathlib
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from flask import Flask, g


SERVER_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

import db
from routes import topology


def _undecorated(view):
    while hasattr(view, "__wrapped__"):
        view = view.__wrapped__
    return view


class TopologyRouteTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.secret_key = "test"

    def test_state_is_tenant_scoped_and_exposes_live_presence(self):
        floor = {"id": "f1", "company_id": "c1", "branch_id": "b1"}
        endpoint = {
            "id": "e1", "hostname": "desk-1", "company_id": "c1", "branch_id": "b1",
            "interactive_user": "WARDEN\\jane", "last_seen_ip": "203.0.113.4",
            "local_ip": "10.0.0.4", "device_type": "desktop", "status": "online",
        }
        with self.app.test_request_context("/topology/state?floor_id=f1"):
            g.company = {"id": "c1"}
            g.admin = {"id": "a1", "role": "company_admin"}
            with mock.patch.object(db, "get_topology_floors", return_value=[floor]), \
                 mock.patch.object(db, "get_endpoints", return_value=[endpoint]), \
                 mock.patch.object(db, "get_topology_placements", return_value=[
                     {"endpoint_id": "e1", "floor_id": "f1", "room_id": None, "x": 20, "y": 30}
                 ]), \
                 mock.patch.object(db, "get_topology_rooms", return_value=[]), \
                 mock.patch.object(db, "get_topology_nodes", return_value=[]), \
                 mock.patch.object(db, "get_topology_links", return_value=[]), \
                 mock.patch.object(db, "get_network_flows", return_value=[]), \
                 mock.patch.object(db, "get_alerts", return_value=[]), \
                 mock.patch.object(db, "get_audit_log", return_value=[]), \
                 mock.patch.object(db, "get_topology_snapshots", return_value=[]), \
                 mock.patch.object(db, "create_topology_snapshot"), \
                 mock.patch.object(db, "prune_topology_snapshots"):
                response = _undecorated(topology.state)()
        payload = response.get_json()
        self.assertEqual(payload["floor"]["id"], "f1")
        self.assertEqual(payload["endpoints"][0]["interactive_user"], "WARDEN\\jane")
        self.assertEqual(payload["endpoints"][0]["local_ip"], "10.0.0.4")
        self.assertEqual(payload["endpoints"][0]["ip_addresses"], [{
            "address": "10.0.0.4", "cidr": "10.0.0.4/32", "family": "IPv4",
            "interface": "Primary", "mac": None, "primary": True,
        }])
        self.assertEqual(payload["endpoints"][0]["device_type"], "desktop")
        self.assertEqual(payload["placed_endpoint_ids"], ["e1"])
        self.assertNotIn("company_id", payload["endpoints"][0])
        self.assertEqual(payload["nodes"], [])
        self.assertEqual(payload["links"], [])
        self.assertEqual(payload["discovered_links"], [])
        self.assertEqual(payload["discovery"]["observation_count"], 0)

    def test_endpoint_payload_exposes_all_interface_addresses(self):
        payload = topology._endpoint_payload({
            "id": "e1", "local_ip": "10.0.0.4", "last_seen_ip": "203.0.113.4",
            "topology_telemetry": {"interfaces": [
                {"name": "Ethernet", "mac": "00:11:22:33:44:55", "addresses": ["10.0.0.4/24", "192.168.50.8/24"]},
                {"name": "Wi-Fi", "mac": "66:77:88:99:AA:BB", "addresses": ["2001:db8::8/64", "127.0.0.1/8"]},
            ]},
        })
        self.assertEqual([item["address"] for item in payload["ip_addresses"]], [
            "10.0.0.4", "192.168.50.8", "2001:db8::8",
        ])
        self.assertEqual(payload["ip_addresses"][0]["interface"], "Ethernet")
        self.assertEqual(payload["ip_addresses"][0]["cidr"], "10.0.0.4/24")
        self.assertEqual(payload["ip_addresses"][1]["family"], "IPv4")
        self.assertEqual(payload["ip_addresses"][2]["family"], "IPv6")

    def test_endpoint_payload_marks_stale_online_status_offline(self):
        payload = topology._endpoint_payload({
            "id": "e1", "status": "online",
            "last_seen": (datetime.now(timezone.utc) - timedelta(minutes=4)).isoformat(),
        })
        self.assertEqual(payload["status"], "offline")

    def test_endpoint_payload_keeps_fresh_heartbeat_online(self):
        payload = topology._endpoint_payload({
            "id": "e1", "status": "online", "last_seen": datetime.now(timezone.utc).isoformat(),
        })
        self.assertEqual(payload["status"], "online")

    def test_state_correlates_known_flow_and_alert_without_exposing_unknown_hosts(self):
        floor = {"id": "f1", "company_id": "c1", "branch_id": None}
        endpoints = [
            {"id": "e1", "hostname": "one", "local_ip": "10.0.0.4", "status": "online", "net_sent_mbps": 1.5,
             "net_recv_mbps": 2.5, "topology_telemetry": {"captured_at": "2026-09-27T12:00:00Z", "neighbors": [
                 {"ip": "10.0.0.5", "mac": "00:11:22:33:44:55", "interface": "Ethernet", "state": "Reachable", "source": "arp-ndp"}
             ]}},
            {"id": "e2", "hostname": "two", "local_ip": "10.0.0.5", "status": "online"},
        ]
        placements = [{"endpoint_id": item["id"], "floor_id": "f1", "x": 10, "y": 10} for item in endpoints]
        flows = [
            {"endpoint_id": "e1", "local_address": "10.0.0.4", "remote_address": "10.0.0.5"},
            {"endpoint_id": "e1", "local_address": "10.0.0.4", "remote_address": "8.8.8.8"},
        ]
        with self.app.test_request_context("/topology/state?floor_id=f1"):
            g.company = {"id": "c1"}; g.admin = {"id": "a1", "role": "company_admin"}
            with mock.patch.object(db, "get_topology_floors", return_value=[floor]), \
                 mock.patch.object(db, "get_endpoints", return_value=endpoints), \
                 mock.patch.object(db, "get_topology_placements", return_value=placements), \
                 mock.patch.object(db, "get_topology_rooms", return_value=[]), \
                 mock.patch.object(db, "get_topology_nodes", return_value=[]), \
                 mock.patch.object(db, "get_topology_links", return_value=[]), \
                 mock.patch.object(db, "get_network_flows", return_value=flows), \
                 mock.patch.object(db, "get_alerts", return_value=[{"endpoint_id": "e1", "severity": "critical", "title": "Malware"}]), \
                 mock.patch.object(db, "get_audit_log", return_value=[]), \
                 mock.patch.object(db, "get_topology_snapshots", return_value=[]), \
                 mock.patch.object(db, "create_topology_snapshot"), \
                 mock.patch.object(db, "prune_topology_snapshots"):
                payload = _undecorated(topology.state)().get_json()
        self.assertEqual(len(payload["discovered_links"]), 1)
        self.assertEqual(payload["discovered_links"][0]["target_id"], "e2")
        self.assertEqual(payload["discovered_links"][0]["discovery_protocol"], "arp-ndp")
        self.assertEqual(payload["discovered_links"][0]["throughput_mbps"], 4.0)
        self.assertEqual(payload["alert_summary"]["e1"]["severity"], "critical")

    def test_state_rejects_floor_from_outside_visible_scope(self):
        with self.app.test_request_context("/topology/state?floor_id=foreign"):
            g.company = {"id": "c1"}
            g.admin = {"id": "a1", "role": "company_admin"}
            with mock.patch.object(db, "get_topology_floors", return_value=[]):
                with self.assertRaises(Exception) as caught:
                    _undecorated(topology.state)()
        self.assertEqual(getattr(caught.exception, "code", None), 404)

    def test_state_replays_tenant_scoped_snapshot(self):
        floor = {"id": "f1", "company_id": "c1", "branch_id": None}
        recorded = {"rooms": [], "placements": [{"endpoint_id": "e1", "x": 12, "y": 34}], "endpoints": []}
        snapshot = {"id": "s1", "captured_at": "2026-09-27T12:00:00Z", "state": recorded}
        with self.app.test_request_context("/topology/state?floor_id=f1&snapshot_id=s1"):
            g.company = {"id": "c1"}; g.admin = {"id": "a1", "role": "company_admin"}
            with mock.patch.object(db, "get_topology_floors", return_value=[floor]), \
                 mock.patch.object(db, "get_topology_snapshots", return_value=[{"id": "s1", "captured_at": snapshot["captured_at"]}]), \
                 mock.patch.object(db, "get_topology_snapshot", return_value=snapshot):
                payload = _undecorated(topology.state)().get_json()
        self.assertEqual(payload["placements"][0]["x"], 12)
        self.assertEqual(payload["replay"]["id"], "s1")

    def test_room_update_rejects_geometry_outside_floor(self):
        room = {"id": "r1", "company_id": "c1", "floor_id": "f1", "x": 80, "y": 10, "width": 20, "height": 20}
        floor = {"id": "f1", "company_id": "c1", "branch_id": None, "layout_locked": False}
        with self.app.test_request_context("/topology/rooms/r1", method="PATCH", json={"width": 25}):
            g.company = {"id": "c1"}
            g.admin = {"id": "a1", "role": "company_admin"}
            with mock.patch.object(db, "get_topology_room", return_value=room), \
                 mock.patch.object(db, "get_topology_floor", return_value=floor), \
                 mock.patch.object(db, "update_topology_room") as update:
                response, status = _undecorated(topology.update_room)("r1")
        self.assertEqual(status, 400)
        self.assertEqual(response.get_json()["error"], "room_outside_floor")
        update.assert_not_called()

    def test_endpoint_placement_requires_matching_floor_branch(self):
        floor = {"id": "f1", "company_id": "c1", "branch_id": "b1", "layout_locked": False}
        endpoint = {"id": "e1", "company_id": "c1", "branch_id": "b2", "is_active": True}
        with self.app.test_request_context("/topology/placements/e1", method="PUT", json={"floor_id": "f1", "x": 10, "y": 10}):
            g.company = {"id": "c1"}
            g.admin = {"id": "a1", "role": "company_admin"}
            with mock.patch.object(db, "get_topology_floor", return_value=floor), \
                 mock.patch.object(db, "get_endpoint", return_value=endpoint), \
                 mock.patch.object(db, "upsert_topology_placement") as upsert:
                response, status = _undecorated(topology.place_endpoint)("e1")
        self.assertEqual(status, 409)
        self.assertEqual(response.get_json()["error"], "endpoint_outside_floor_branch")
        upsert.assert_not_called()


if __name__ == "__main__":
    unittest.main()
