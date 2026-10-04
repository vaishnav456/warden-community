import unittest
from unittest.mock import patch
from datetime import datetime, timezone, timedelta
from flask import Flask, g
from werkzeug.exceptions import Forbidden, Conflict
from services import support_workflow as workflow
from routes import fleet_tools, agent_api


def bare(function):
    while hasattr(function, "__wrapped__"):
        function = function.__wrapped__
    return function


class SupportWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.endpoint = dict(id="device", company_id="tenant", branch_id="branch", status="online",
                             last_seen=datetime.now(timezone.utc).isoformat())

    def test_fresh_and_stale_are_distinct(self):
        self.assertTrue(workflow.triage(self.endpoint)["reachable"])
        self.endpoint["last_seen"] = (datetime.now(timezone.utc)-timedelta(hours=1)).isoformat()
        self.assertFalse(workflow.triage(self.endpoint)["reachable"])
        self.assertIn("not a confirmed diagnosis", workflow.triage(self.endpoint)["note"])

    def test_visit_requires_future_and_explicit_timezone(self):
        for value in ["", "2020-01-01T00:00:00Z", "2099-01-01T00:00:00", None]:
            with self.assertRaises(ValueError): workflow.visit_time(value)
        self.assertEqual(workflow.visit_time("2099-01-01T10:00:00+05:30"), "2099-01-01T04:30:00+00:00")

    def test_messages_bounded(self):
        for value in ["", "x"*2001, "bad\x00text", {}]:
            with self.assertRaises(ValueError): workflow.text(value)
        self.assertEqual(workflow.text("  issue\nmore  "), "issue\nmore")

    def test_user_queue_key_is_case_insensitive_but_separate(self):
        self.assertEqual(workflow.requester_key("DOMAIN\\Alice"), workflow.requester_key("domain\\alice"))
        self.assertNotEqual(workflow.requester_key("alice"),workflow.requester_key("bob"))

    def test_technician_cannot_change_another_owners_request(self):
        with self.app.test_request_context(method="POST"):
            g.company = dict(id="tenant")
            g.admin = dict(id="me",role="technician")
            with patch.object(fleet_tools.db,"_get",return_value=[dict(id="req",endpoint_id="device",status="claimed",claimed_by="other")]), patch.object(fleet_tools,"scoped_endpoints",return_value=[self.endpoint]), patch.object(fleet_tools.db,"_patch") as write:
                with self.assertRaises(Forbidden): bare(fleet_tools.support_action)("11111111-1111-4111-8111-111111111111","queued")
                write.assert_not_called()

    def test_resolved_ticket_cannot_receive_admin_reply(self):
        with self.app.test_request_context(method="POST",data=dict(message="hello")):
            g.company = dict(id="tenant")
            g.admin = dict(id="me",role="company_admin")
            with patch.object(fleet_tools.db,"_get",return_value=[dict(endpoint_id="device",status="resolved")]), patch.object(fleet_tools,"scoped_endpoints",return_value=[self.endpoint]), patch.object(fleet_tools.db,"_post") as write:
                with self.assertRaises(Conflict): bare(fleet_tools.support_action)("11111111-1111-4111-8111-111111111111","reply")
                write.assert_not_called()

    def test_creation_preserves_description_encrypted_without_granting_remote(self):
        with self.app.test_request_context(method="POST",json=dict(username="domain\\alice",message="new detail")):
            g.endpoint = self.endpoint
            with patch.object(agent_api,"check_rate_limit",return_value=True), patch.object(agent_api.db,"_get",return_value=[]), patch.object(agent_api.db,"get_company_by_id",return_value=dict(id="tenant")), patch.object(agent_api.db,"encrypt_field",return_value="ciphertext") as encrypt, patch.object(agent_api.db,"_rpc",return_value=dict(id="request",status="open")) as write, patch.object(agent_api.db,"audit"), patch.object(agent_api.db,"create_remote_session") as remote:
                response=bare(agent_api.request_support)()
                self.assertEqual(response.json["status"],"open")
                self.assertEqual(write.call_args.args[0],"support_ticket_action")
                self.assertEqual(write.call_args.args[1]["p_cipher"],"ciphertext")
                self.assertEqual(encrypt.call_args.args[1]["message"],"new detail")
                remote.assert_not_called()

    def test_endpoint_cannot_see_other_windows_users_ticket(self):
        with self.app.test_request_context(method="POST",json=dict(username="alice")):
            g.endpoint=self.endpoint
            with patch.object(agent_api,"check_rate_limit",return_value=True), patch.object(agent_api.db,"get_company_by_id",return_value=dict(id="tenant")), patch.object(agent_api.db,"_get",return_value=[dict(id="req",request_encrypted="cipher",status="claimed")]), patch.object(agent_api.db,"decrypt_field",return_value=dict(username="bob",message="private")):
                response=bare(agent_api.support_status)()
                self.assertEqual(response.json["status"],"none")
                self.assertNotIn("private",response.get_data(as_text=True))
