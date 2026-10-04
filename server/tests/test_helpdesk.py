import unittest
import uuid
from unittest.mock import patch
from flask import Flask, g
from services import helpdesk
from routes import agent_api, fleet_tools
from werkzeug.exceptions import NotFound


def bare(f):
    while hasattr(f, "__wrapped__"):
        f=f.__wrapped__
    return f


class HelpdeskTests(unittest.TestCase):
    def setUp(self):
        self.app=Flask(__name__)
        self.ticket=str(uuid.uuid4())
        self.endpoint=dict(id=str(uuid.uuid4()),company_id=str(uuid.uuid4()))
        self.company=dict(id=self.endpoint["company_id"])

    def test_custom_form_validation_and_snapshot(self):
        form=helpdesk.form_definition(dict(categories=["General"],fields=[
            dict(id="location",label="Work location",type="select",required=True,options=["Office","Home"])]))
        body=helpdesk.ticket_content(dict(subject="Network issue",category="General",priority="high",
             message="Connection drops",fields=dict(location="Home")),form,"DOMAIN\\alice")
        self.assertEqual(body["fields"]["location"],dict(label="Work location",value="Home"))
        for fields in ({},{'location':'invalid'},{'unknown':'value'}):
            with self.assertRaises(ValueError):
                helpdesk.ticket_content(dict(message="Issue",fields=fields),form,"alice")
        for definition in (dict(categories=["same","SAME"]),dict(fields=[dict(id="bad-id",label="X")]),
                           dict(fields=[dict(id="one",label="X",type="html")]),dict(fields=[{}]*9)):
            with self.assertRaises(ValueError):helpdesk.form_definition(definition)

    def test_transaction_uses_authenticated_actor_and_encrypted_body(self):
        with patch.object(helpdesk.db,"encrypt_field",return_value="v2:encrypted"),patch.object(helpdesk.db,"_rpc",return_value=dict(id=self.ticket)) as rpc:
            helpdesk.action(self.company,self.endpoint,self.ticket,"reply",admin=dict(id="trusted-admin"),
                            message_id=str(uuid.uuid4()),body=dict(message="Private reply"))
        params=rpc.call_args.args[1]
        self.assertEqual(params["p_admin"],"trusted-admin")
        self.assertEqual(params["p_cipher"],"v2:encrypted")
        self.assertNotIn("Private reply",str(params))

    def conditional_form(self):
        return helpdesk.form_definition(dict(categories=["General","Network"],fields=[
            dict(id="location",label="Location",type="select",options=["Office","Home"],required=True),
            dict(id="network",label="Network name",required=True,show_if=dict(mode="all",rules=[
                dict(source="field",field="location",operator="equals",value="Home"),
                dict(source="category",operator="equals",value="Network")])),
            dict(id="office",label="Office desk",show_if=dict(mode="any",rules=[
                dict(source="field",field="location",operator="not_equals",value="Home"),
                dict(source="priority",operator="equals",value="urgent")]))]))

    def test_hidden_required_answers_are_not_required_or_saved(self):
        form=self.conditional_form()
        body=helpdesk.ticket_content(dict(message="Problem",category="General",
            fields=dict(location="Office",network="Stale hidden secret",office="Desk 1")),form,"alice")
        self.assertNotIn("network",body["fields"])
        self.assertEqual(body["fields"]["office"]["value"],"Desk 1")
        with self.assertRaises(ValueError):
            helpdesk.ticket_content(dict(message="Problem",category="Network",fields=dict(location="Home")),form,"alice")

    def test_branch_conditions_use_authenticated_endpoint_not_posted_branch(self):
        branch=str(uuid.uuid4())
        form=helpdesk.form_definition(dict(fields=[dict(id="branch_question",label="Branch detail",required=True,
            show_if=dict(mode="all",rules=[dict(source="branch",operator="equals",value=branch)]))]))
        body=helpdesk.ticket_content(dict(message="Issue",branch=branch,fields={}),form,"alice",str(uuid.uuid4()))
        self.assertEqual(body["fields"],{})
        with self.assertRaises(ValueError):
            helpdesk.ticket_content(dict(message="Issue",fields={}),form,"alice",branch)

    def test_cycles_forward_references_and_executable_conditions_rejected(self):
        for condition in (dict(mode="all",rules=[dict(source="field",field="self",operator="equals",value="x")]),
                          dict(mode="all",rules=[dict(source="category",operator="eval",value="script")]),
                          dict(mode="any",rules=[])):
            with self.assertRaises(ValueError):
                helpdesk.form_definition(dict(fields=[dict(id="self",label="Question",show_if=condition)]))

    def test_reply_does_not_accept_another_accounts_ticket(self):
        with self.app.test_request_context(method="POST",json=dict(username="alice",request_id=self.ticket,message="hello")):
            g.endpoint=self.endpoint
            with patch.object(agent_api,"check_rate_limit",return_value=True),patch.object(helpdesk.db,"get_company_by_id",return_value=self.company),patch.object(helpdesk.db,"_get",return_value=[dict(id=self.ticket,request_encrypted="cipher")]),patch.object(helpdesk.db,"decrypt_field",return_value=dict(username="bob")),patch.object(helpdesk.db,"_rpc") as write:
                response,status=bare(agent_api.support_reply)()
                self.assertEqual(status,404);write.assert_not_called()

    def test_reply_reuses_stable_message_identifier(self):
        message=str(uuid.uuid4())
        with self.app.test_request_context(method="POST",json=dict(username="alice",request_id=self.ticket,message_id=message,message="Details")):
            g.endpoint=self.endpoint
            with patch.object(agent_api,"check_rate_limit",return_value=True),patch.object(helpdesk.db,"get_company_by_id",return_value=self.company),patch.object(agent_api,"owned_support_ticket",return_value=dict(id=self.ticket)),patch.object(helpdesk.db,"encrypt_field",return_value="cipher"),patch.object(helpdesk.db,"_rpc",return_value=dict(id=self.ticket)) as rpc:
                response=bare(agent_api.support_reply)()
                self.assertTrue(response.json["ok"])
                self.assertEqual(rpc.call_args.args[1]["p_assignee"],message)

    def test_invalid_creation_rejected_before_database_reads(self):
        with self.app.test_request_context(method="POST",json=dict(username="alice",message="x"*2001)):
            g.endpoint=self.endpoint
            with patch.object(agent_api,"check_rate_limit",return_value=True),patch.object(helpdesk.db,"get_company_by_id") as read:
                self.assertEqual(bare(agent_api.request_support)()[1],400);read.assert_not_called()

    def test_browser_cannot_select_foreign_endpoint(self):
        with self.app.test_request_context(method="POST",data=dict(endpoint_id="foreign")):
            g.company=self.company;g.admin=dict(id="admin",role="company_admin")
            with patch.object(fleet_tools,"scoped_endpoints",return_value=[self.endpoint]),patch.object(helpdesk.db,"_rpc") as write:
                with self.assertRaises(NotFound):bare(fleet_tools.support_create)()
                write.assert_not_called()

    def test_templates_compile_and_escape_user_text(self):
        from app import app
        with app.test_request_context():
            g.admin=dict(id="admin",role="company_admin",email="test@example.invalid")
            g.company=dict(id="tenant",name="Tenant")
            item=dict(id=self.ticket,number="ABC",status="resolved",claimed_by=None,
                endpoint=dict(id=self.endpoint["id"],hostname="Device"),
                request=dict(subject="<script>alert(1)</script>",username="alice",message="<unsafe>",fields={}),
                messages=[],triage=dict(connection="Offline",observations=[],note="Reported evidence"))
            context=dict(g=g,company=g.company,current_user=g.admin,is_superadmin=False,
                csrf_token=lambda:"test",page_help=None,active_page="fleet_support")
            html=app.jinja_env.get_template("fleet/support_detail.html").render(**context,item=item,admins=[],message_id=str(uuid.uuid4()))
            self.assertNotIn("<script>alert(1)</script>",html)
            self.assertIn("&lt;script&gt;",html)
            for name in ("support.html","support_new.html","support_form.html"):
                app.jinja_env.get_template("fleet/"+name)


if __name__=="__main__":unittest.main()
