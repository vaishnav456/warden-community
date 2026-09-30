import pathlib
import sys
import unittest
from unittest import mock
from flask import Flask, g

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from routes import endpoints
import db


def view(function):
    while hasattr(function, "__wrapped__"):
        function = function.__wrapped__
    return function


class EndpointNameTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.endpoint = {"id": "e1", "company_id": "c1", "branch_id": None,
                         "platform": "windows", "hostname": "DESK-1",
                         "agent_version": "2.6.43", "capabilities": ["CONFIGURE_DEVICE_IDENTITY"]}

    def context(self, path, body):
        return self.app.test_request_context(path, method="POST", json=body)

    def identity(self):
        g.company = {"id": "c1", "require_dual_approval": True}
        g.admin = {"id": "a1", "role": "company_admin"}

    def test_nickname_can_be_set_and_cleared_without_renaming(self):
        for nickname, label in [("Front desk", "Front desk"), ("", "DESK-1")]:
            with self.context("/endpoints/e1/nickname", {"nickname": nickname}):
                self.identity()
                with mock.patch.object(db, "get_endpoint", return_value=self.endpoint), \
                     mock.patch.object(db, "update_endpoint_nickname") as save, \
                     mock.patch.object(db, "update_endpoint_hostname") as rename, \
                     mock.patch.object(db, "audit"):
                    response = view(endpoints.update_nickname)("e1")
                    self.assertEqual(response.get_json()["display_name"], label)
                    save.assert_called_once_with("e1", nickname)
                    rename.assert_not_called()

    def test_foreign_endpoint_cannot_be_named(self):
        with self.context("/endpoints/e1/nickname", {"nickname": "Other tenant"}):
            self.identity()
            with mock.patch.object(db, "get_endpoint", return_value={**self.endpoint, "company_id": "other"}):
                from werkzeug.exceptions import NotFound
                with self.assertRaises(NotFound):
                    view(endpoints.update_nickname)("e1")

    def test_rename_defaults_to_no_restart_and_restart_requires_approval(self):
        for requested in [None, False, True]:
            payload = {"hostname": "new-desk"}
            if requested is not None:
                payload["restart"] = requested
            with self.context("/endpoints/e1/dispatch-job", {"type": "CONFIGURE_DEVICE_IDENTITY", "payload": payload}):
                self.identity()
                with mock.patch.object(db, "get_endpoint", return_value=self.endpoint), \
                     mock.patch("services.entitlements.check_job", return_value=mock.Mock(allowed=True)), \
                     mock.patch.object(db, "create_job", return_value={"id": "j1"}) as create, \
                     mock.patch.object(db, "find_matching_policy", return_value=None), \
                     mock.patch.object(db, "create_escalation_request", return_value={"id": "r1"}) as escalation, \
                     mock.patch.object(db, "audit"):
                    response = view(endpoints.dispatch_job)("e1")
                    if requested is True:
                        create.assert_not_called()
                        self.assertTrue(escalation.call_args.kwargs["requires_dual"])
                        self.assertEqual(response.get_json()["status"], "pending_approval")
                    else:
                        escalation.assert_not_called()
                        self.assertEqual(create.call_args.kwargs["payload"], {"hostname": "NEW-DESK", "restart": False})

    def test_old_agent_and_invalid_hostname_are_rejected_before_dispatch(self):
        for version, hostname, status in [("2.6.42", "NEW-DESK", 409),
                                           ("2.6.43", "invalid';shutdown", 400),
                                           ("2.6.43", "12345", 400)]:
            with self.context("/endpoints/e1/dispatch-job", {"type": "CONFIGURE_DEVICE_IDENTITY", "payload": {"hostname": hostname}}):
                self.identity()
                with mock.patch.object(db, "get_endpoint", return_value={**self.endpoint, "agent_version": version}), \
                     mock.patch.object(db, "create_job") as create:
                    response, actual = view(endpoints.dispatch_job)("e1")
                    self.assertEqual(actual, status)
                    create.assert_not_called()

    def test_nickname_storage_uses_endpoint_encryption(self):
        with mock.patch.object(db, "_endpoint_company", return_value={"id": "c1"}), \
             mock.patch.object(db, "_endpoint_encrypt", return_value="encrypted") as encrypt, \
             mock.patch.object(db, "_patch") as patch:
            db.update_endpoint_nickname("e1", "Front desk")
            encrypt.assert_called_once_with({"id": "c1"}, "display_name", "Front desk")
            self.assertEqual(patch.call_args.args[1]["display_name"], "encrypted")

    def test_alert_endpoint_label_uses_current_nickname(self):
        alert = {"company_id": "c1", "endpoint_id": "e1",
                 "title": "DESK-1 is offline", "endpoints": {**self.endpoint, "display_name": "Front desk"}}
        result = db._decrypt_alert(alert, {"id": "c1"})
        self.assertEqual(result["title"], "Front desk is offline")
        self.assertEqual(result["_endpoint"]["display_name"], "Front desk")
        self.assertEqual(result["_endpoint"]["hostname"], "DESK-1")
