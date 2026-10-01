import csv
import io
import unittest
from unittest import mock
from datetime import datetime,timezone,timedelta
from flask import Flask,g
from werkzeug.exceptions import NotFound,BadRequest
from services import fleet_tools as tools,fleet_reports as reports
from routes import fleet_tools as routes,agent_api
from services.home_grants import issue_package_grant


class FleetToolsTests(unittest.TestCase):
    def setUp(self):
        self.endpoint=dict(id='device',company_id='tenant',branch_id='branch',status='online',software_inventory_at=datetime.now(timezone.utc).isoformat())
        self.rule=dict(id='rule',company_id='tenant',branch_id='branch',inventory_name='Example App',publisher='Example Inc',target_version='2.10.0',enabled=True,window_start=0,window_end=0)
        self.installed=[dict(name='Example App',publisher='Example Inc',version='2.9.0')]
    def undecorated(self,function):
        while hasattr(function,'__wrapped__'):function=function.__wrapped__
        return function
    def test_numeric_versions_not_lexical(self):
        self.assertEqual(tools.match_patch(self.rule,self.endpoint,self.installed)['status'],'outdated')
        self.installed[0]['version']='2.10'
        self.assertEqual(tools.match_patch(self.rule,self.endpoint,self.installed)['status'],'current')
        for text in ['beta','1.2-rc1','1;execute','9999999999','']:
            self.assertIsNone(tools.numeric_version(text))
    def test_missing_ambiguous_or_other_publisher_never_installed(self):
        self.assertIsNone(tools.match_patch(self.rule,self.endpoint,[]))
        self.assertIsNone(tools.match_patch(self.rule,self.endpoint,self.installed*2))
        self.assertIsNone(tools.match_patch(self.rule,self.endpoint,[dict(self.installed[0],publisher='Other')]))
    def test_tenant_and_branch_boundaries(self):
        for endpoint in [dict(self.endpoint,company_id='other'),dict(self.endpoint,branch_id='other')]:
            self.assertIsNone(tools.match_patch(self.rule,endpoint,self.installed))
    def test_unknown_version_stays_review_only(self):
        self.installed[0]['version']='release two'
        self.assertEqual(tools.match_patch(self.rule,self.endpoint,self.installed)['status'],'unknown')
    def test_stale_inventory_never_dispatches(self):
        endpoint=dict(self.endpoint,software_inventory_at=(datetime.now(timezone.utc)-timedelta(days=2)).isoformat())
        with mock.patch.object(tools.db,'_rpc') as dispatch:
            self.assertIsNone(tools.dispatch(self.rule,endpoint,dict(status='outdated')))
            dispatch.assert_not_called()
    def test_business_window_defers_updates(self):
        rule=dict(defer_updates=True,business_start=22,business_end=6)
        with mock.patch.object(tools,'traffic_for',return_value=rule):
            self.assertTrue(tools.defer_updates(self.endpoint,datetime(2026,10,1,23,tzinfo=timezone.utc)))
            self.assertFalse(tools.defer_updates(self.endpoint,datetime(2026,10,1,12,tzinfo=timezone.utc)))
    def test_disabled_rule_does_not_touch_device(self):
        with mock.patch.object(tools.db,'get_active_remote_session') as session:
            self.assertIsNone(tools.dispatch(dict(self.rule,enabled=False),self.endpoint,dict(status='outdated')))
            session.assert_not_called()
    def test_csv_formula_injection_escaped(self):
        for value in ['=cmd','+cmd','-cmd','@cmd','  =cmd','\tcmd']:
            self.assertTrue(reports.csv_cell(value).startswith("'"))
        self.assertEqual(reports.csv_cell('normal'),'normal')
    def test_storage_export_is_metadata_only(self):
        with mock.patch.object(reports.db,'_get',return_value=[]) as read:
            reports.export('tenant','storage')
        query=read.call_args.args[0]
        self.assertIn('company_id=eq.tenant',query)
        self.assertIn('action.ilike.*storage*',query)
        self.assertNotIn('details',query)
    def test_export_never_silently_truncates(self):
        with mock.patch.object(reports.db,'_get',return_value=[dict(id='row')]*1000):
            with self.assertRaises(ValueError):reports.export('tenant','jobs')
    def test_branch_export_filters_current_endpoint_ownership(self):
        with mock.patch.object(reports.db,'get_endpoints',return_value=[dict(id='allowed')]),mock.patch.object(reports.db,'_get',return_value=[dict(id='a',endpoint_id='allowed',type='UPDATE_AGENT'),dict(id='b',endpoint_id='foreign',type='RUN_CMD')]) as read:
            result=reports.export('tenant','jobs','branch')
        rows=list(csv.reader(io.StringIO(result)))
        self.assertEqual(len(rows),2);self.assertNotIn('RUN_CMD',result)
        self.assertNotIn('payload',read.call_args.args[0])
    def test_reports_reject_unknown_type_and_unbounded_period(self):
        for kind,days in [('payloads',30),('jobs',0),('audit',91)]:
            with self.assertRaises(ValueError):reports.export('tenant',kind,days=days)
    def test_support_claim_cannot_touch_another_tenant(self):
        app=Flask(__name__)
        with app.test_request_context('/operations/support/foreign/claim',method='POST'):
            g.company=dict(id='tenant');g.admin=dict(id='admin',role='company_admin')
            with mock.patch.object(routes.db,'_get',return_value=[]),mock.patch.object(routes.db,'_patch') as write:
                with self.assertRaises(NotFound):self.undecorated(routes.support_action)('foreign','claim')
                write.assert_not_called()
    def test_cache_config_does_not_serve_another_tenant_package(self):
        app=Flask(__name__)
        with app.test_request_context('/api/agent/package-cache?app_id=foreign'):
            g.endpoint=self.endpoint
            with mock.patch.object(tools,'traffic_for',return_value=dict(package_cache_node_id='node')),mock.patch.object(agent_api.db,'get_app',return_value=dict(company_id='other')):
                with self.assertRaises(NotFound):self.undecorated(agent_api.package_cache_config)()
    def test_support_request_is_bounded_and_has_no_remote_side_effect(self):
        app=Flask(__name__)
        with app.test_request_context('/api/agent/support-request',method='POST',json=dict(username='alice',message='x'*2001)):
            g.endpoint=self.endpoint
            with mock.patch.object(agent_api,'check_rate_limit',return_value=True),mock.patch.object(agent_api.db,'create_remote_session') as remote,mock.patch.object(agent_api.db,'_post') as write:
                _,status=self.undecorated(agent_api.request_support)()
                self.assertEqual(status,400);remote.assert_not_called();write.assert_not_called()
    def test_policy_presets_are_catalog_valid(self):
        from policy_settings import validate_settings_dict
        for _,settings in routes.PRESETS.values():validate_settings_dict(settings)
    def test_traffic_template_accepts_older_node_without_capabilities(self):
        from app import app
        with app.test_request_context('/operations/traffic'):
            g.admin=dict(id='admin',role='company_admin',email='test@example.invalid');g.company=dict(id='tenant',name='Tenant')
            html=app.jinja_env.get_template('fleet/traffic.html').render(g=g,company=g.company,is_superadmin=False,current_user=g.admin,csrf_token=lambda:'test',nodes=[dict(id='old',name='Old node',capabilities=None)],rules=[],branches=[],page_help=None)
            self.assertIn('Save branch policy',html)
            self.assertNotIn('value="old"',html)
    def test_support_rejects_non_object_json(self):
        app=Flask(__name__)
        with app.test_request_context('/api/agent/support-request',method='POST',json=['not-an-object']):
            g.endpoint=self.endpoint
            with mock.patch.object(agent_api,'check_rate_limit',return_value=True):
                _,status=self.undecorated(agent_api.request_support)()
                self.assertEqual(status,400)
    def test_remote_quality_task_owned_by_browser_handler(self):
        import ast, pathlib
        tree=ast.parse((pathlib.Path(__file__).parents[1]/'services'/'ws_proxy.py').read_text())
        functions={node.name:node for node in tree.body if isinstance(node,ast.AsyncFunctionDef)}
        browser=functions['_handle_browser'];agent=functions['_handle_agent']
        self.assertTrue(any(isinstance(node,ast.Attribute) and isinstance(node.value,ast.Name) and node.value.id=='quality_task' and node.attr=='cancel' for block in ast.walk(browser) if isinstance(block,ast.Try) for final in block.finalbody for node in ast.walk(final)))
        self.assertFalse(any(isinstance(node,ast.Name) and node.id=='quality_task' for node in ast.walk(agent)))
    def test_cache_grant_is_signed_and_endpoint_scoped(self):
        import base64,json
        with mock.patch('services.home_grants.sign_canonical_payload',return_value=b'signature'):
            token=issue_package_grant(self.endpoint,dict(id='node'),dict(id='app',sha256='a'*64,size_bytes=1024))
        raw=token.split('.')[0];payload=json.loads(base64.urlsafe_b64decode(raw+'='*(-len(raw)%4)))
        self.assertEqual(payload['aud'],'warden-package-cache')
        self.assertEqual(payload['endpoint_id'],'device');self.assertEqual(payload['company_id'],'tenant')
        self.assertLessEqual(payload['exp']-payload['iat'],900)


if __name__=='__main__':unittest.main()
