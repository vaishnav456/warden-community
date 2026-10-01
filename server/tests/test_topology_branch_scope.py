import pathlib
import unittest
from unittest import mock

from flask import Flask, g
from werkzeug.exceptions import Forbidden, NotFound
import db
from routes import topology


def view(function):
    while hasattr(function, "__wrapped__"):
        function = function.__wrapped__
    return function


class TopologyBranchScopeTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)

    def context(self, role="company_admin", branch=None):
        g.company = {"id": "c1"}
        g.admin = {"id": "a1", "role": role, "branch_id": branch}

    def test_assigned_branch_is_default_for_organization_admin(self):
        with self.app.test_request_context("/topology"):
            self.context(branch="b1")
            with mock.patch.object(db, "get_branch", return_value={"id": "b1", "company_id": "c1"}):
                self.assertEqual(topology._selected_branch_id(), "b1")

    def test_organization_admin_can_choose_all_or_a_valid_branch(self):
        with self.app.test_request_context("/topology?branch_id="):
            self.context(branch="b1")
            self.assertIsNone(topology._selected_branch_id())
        with self.app.test_request_context("/topology?branch_id=b2"):
            self.context(branch="b1")
            with mock.patch.object(db, "get_branch", return_value={"id": "b2", "company_id": "c1"}):
                self.assertEqual(topology._selected_branch_id(), "b2")

    def test_branch_admin_and_assigned_technician_cannot_switch_scope(self):
        for role in ("branch_admin", "technician"):
            with self.app.test_request_context("/topology?branch_id=b2"):
                self.context(role, "b1")
                with self.assertRaises(Forbidden):
                    topology._selected_branch_id()
            with self.app.test_request_context("/topology?branch_id="):
                self.context(role, "b1")
                self.assertEqual(topology._selected_branch_id(), "b1")

    def test_missing_branch_admin_assignment_fails_closed(self):
        with self.app.test_request_context("/topology"):
            self.context("branch_admin")
            with self.assertRaises(Forbidden):
                topology._selected_branch_id()

    def test_foreign_company_branch_is_rejected(self):
        with self.app.test_request_context("/topology?branch_id=b2"):
            self.context()
            with mock.patch.object(db, "get_branch", return_value={"id": "b2", "company_id": "c2"}):
                with self.assertRaises(NotFound):
                    topology._selected_branch_id()

    def test_branch_admin_floor_creation_is_assigned_and_cannot_be_forged(self):
        for requested in (None, "b1", "b2"):
            with self.app.test_request_context("/topology/floors", method="POST",
                    json={"name": "Ground", "building": "Office", "branch_id": requested}):
                self.context("branch_admin", "b1")
                with mock.patch.object(db, "get_branch", return_value={"id": "b1", "company_id": "c1"}), \
                     mock.patch.object(db, "create_topology_floor", return_value={"id": "f1"}) as create, \
                     mock.patch.object(db, "audit"):
                    if requested == "b2":
                        with self.assertRaises(Forbidden):
                            view(topology.create_floor)()
                        create.assert_not_called()
                    else:
                        _, status = view(topology.create_floor)()
                        self.assertEqual(status, 201)
                        self.assertEqual(create.call_args.args[1], "b1")

    def test_specific_branch_floor_creation_persists_that_branch(self):
        with self.app.test_request_context("/topology/floors", method="POST",
                json={"name": "Ground", "building": "Office", "branch_id": "b2"}):
            self.context()
            with mock.patch.object(db, "get_branch", return_value={"id": "b2", "company_id": "c1"}), \
                 mock.patch.object(db, "create_topology_floor", return_value={"id": "f2"}) as create, \
                 mock.patch.object(db, "audit"):
                _, status = view(topology.create_floor)()
                self.assertEqual(status, 201)
                self.assertEqual(create.call_args.args[1], "b2")

    def test_state_excludes_other_branch_endpoints_placements_alerts_and_history(self):
        floors = [{"id": "f1", "company_id": "c1", "branch_id": "b1"},
                  {"id": "f2", "company_id": "c1", "branch_id": "b2"}]
        endpoints = [{"id": "e1", "branch_id": "b1"}, {"id": "e2", "branch_id": "b2"}]
        placements = [{"endpoint_id": "e1", "floor_id": "f1"}, {"endpoint_id": "e2", "floor_id": "f1"}]
        with self.app.test_request_context("/topology/state?branch_id=b1&floor_id=f1"):
            self.context("branch_admin", "b1")
            with mock.patch.multiple(db,
                get_topology_floors=mock.Mock(return_value=floors),
                get_endpoints=mock.Mock(return_value=endpoints),
                get_topology_placements=mock.Mock(return_value=placements),
                get_topology_rooms=mock.Mock(return_value=[]),
                get_topology_nodes=mock.Mock(return_value=[]),
                get_topology_links=mock.Mock(return_value=[
                    {"source_type": "endpoint", "source_id": "e2", "target_type": "node", "target_id": "n1"}]),
                get_network_flows=mock.Mock(return_value=[{"endpoint_id": "e2"}]),
                get_alerts=mock.Mock(return_value=[{"endpoint_id": "e2", "title": "Hidden"}]),
                get_audit_log=mock.Mock(return_value=[
                    {"id": "h1", "action": "topology_floor_created", "detail": {"floor_id": "f1"}},
                    {"id": "h2", "action": "topology_floor_created", "detail": {"floor_id": "f2"}}]),
                get_topology_snapshots=mock.Mock(return_value=[]),
                create_topology_snapshot=mock.Mock(),
                prune_topology_snapshots=mock.Mock(),
            ):
                result = view(topology.state)().get_json()
        self.assertEqual([item["id"] for item in result["floors"]], ["f1"])
        self.assertEqual([item["id"] for item in result["endpoints"]], ["e1"])
        self.assertEqual(result["placed_endpoint_ids"], ["e1"])
        self.assertEqual(result["placements"], [placements[0]])
        self.assertEqual(result["alert_summary"], {})
        self.assertEqual(result["links"], [])
        self.assertEqual(result["discovery"]["observation_count"], 0)
        self.assertEqual([item["id"] for item in result["history"]], ["h1"])

    def test_branch_selection_is_in_every_state_request_and_creation_default(self):
        server = pathlib.Path(__file__).resolve().parents[1]
        script = (server / "static/js/warden.js").read_text(encoding="utf-8")
        page = (server / "templates/topology/index.html").read_text(encoding="utf-8")
        self.assertIn("data-branch-id", page)
        self.assertIn('aria-label="Topology branch"', page)
        self.assertIn("Assigned branch", page)
        self.assertIn("this.floorForm.branch_id = this.branchId", script)
        self.assertIn("this.stateQuery(this.floor.id, id)", script)
        self.assertNotIn("showFloorModal=true", page)

    def test_replay_filters_legacy_cross_branch_data(self):
        floor = {"id": "f1", "company_id": "c1", "branch_id": "b1"}
        recorded = {
            "endpoints": [{"id": "e1", "branch_id": "b1"}, {"id": "e2", "branch_id": "b2"}],
            "placements": [{"endpoint_id": "e1"}, {"endpoint_id": "e2"}],
            "placed_endpoint_ids": ["e1", "e2"],
            "alert_summary": {"e1": {"count": 1}, "e2": {"count": 2}},
            "history": [{"id": "h2", "detail": {"floor_id": "f2"}}],
            "links": [{"source_type": "endpoint", "source_id": "e2", "target_type": "node", "target_id": "n1"}],
        }
        snapshot = {"id": "s1", "captured_at": "2026-10-01T00:00:00Z", "state": recorded}
        with self.app.test_request_context("/topology/state?floor_id=f1&snapshot_id=s1"):
            self.context("branch_admin", "b1")
            with mock.patch.object(db, "get_topology_floors", return_value=[floor]), \
                 mock.patch.object(db, "get_topology_snapshots", return_value=[]), \
                 mock.patch.object(db, "get_topology_snapshot", return_value=snapshot):
                payload = view(topology.state)().get_json()
        self.assertEqual(payload["endpoints"], [recorded["endpoints"][0]])
        self.assertEqual(payload["placed_endpoint_ids"], ["e1"])
        self.assertEqual(payload["alert_summary"], {"e1": {"count": 1}})
        self.assertEqual(payload["history"], [])
        self.assertEqual(payload["links"], [])

    def test_creation_branch_selector_renders_locked_for_branch_users(self):
        from jinja2 import Environment
        server = pathlib.Path(__file__).resolve().parents[1]
        source = (server / "templates/topology/index.html").read_text(encoding="utf-8")
        template = Environment(autoescape=True).from_string(source.replace('{% extends "base.html" %}', ""))
        rendered = template.render(
            current_user={"role": "branch_admin"},
            branches=[{"id": "b1", "name": "Assigned office"}],
            branch_locked=True, selected_branch_id="b1", wicon=lambda *args: "",
        )
        self.assertIn('data-branch-id="b1"', rendered)
        self.assertIn('x-model="floorForm.branch_id" disabled', rendered)
        self.assertNotIn("All branches", rendered)
        self.assertIn('value="b1" selected', rendered)
