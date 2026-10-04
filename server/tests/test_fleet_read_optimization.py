"""Read optimization regressions using synthetic data and loopback HTTP only."""
import io
import os
import ssl
import threading
import unittest
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock
from flask import Flask, g
import db
from database import http_pool, metrics, transport
from services import dashboard_fleet, fleet_reads, process_role, scheduler

NOW = datetime(2026, 10, 4, 10, tzinfo=timezone.utc)


class FleetReadTests(unittest.TestCase):
    def aggregate(self, rows=None):
        return dict(total_count=1000, online_count=990, offline_count=10, stale_count=2,
                    health=dict(agent_updates=20, agent_unknown=1, encryption_attention=2,
                                encryption_unknown=3, patch_attention=4), endpoints=rows or [])

    def test_blockers_use_two_company_scoped_reads(self):
        with mock.patch.object(db, '_get_all', side_effect=[
                [{'endpoint_id': str(i)} for i in range(1200)], [{'endpoint_id': 'remote'}]]) as read:
            result = fleet_reads.update_blockers('tenant', NOW)
        self.assertEqual(len(result), 1201)
        self.assertEqual(read.call_count, 2)
        for call in read.call_args_list:
            self.assertIn('company_id=eq.tenant', call.args[0])
            self.assertIn('select=endpoint_id', call.args[0])
            self.assertIn('order=id.asc', call.args[0])

    def test_blocker_failure_is_not_empty_success(self):
        with mock.patch.object(db, '_get_all', side_effect=OSError('offline')):
            with self.assertRaises(OSError):
                fleet_reads.update_blockers('tenant', NOW)

    def test_snapshot_decrypts_only_bounded_sample(self):
        rows = [dict(id=str(i), company_id='tenant', branch_id='branch') for i in range(10)]
        with mock.patch.object(db, '_rpc', return_value=self.aggregate(rows)), \
             mock.patch.object(db, 'get_company_by_id', return_value={'id': 'tenant'}), \
             mock.patch.object(db, '_decrypt_endpoint', side_effect=lambda row, company: dict(row, hostname='Plain name')) as decrypt:
            result = dashboard_fleet.snapshot('tenant', 'branch', NOW)
        self.assertEqual(result['total_count'], 1000)
        self.assertEqual(decrypt.call_count, 10)
        self.assertEqual(result['endpoints'][0]['hostname'], 'Plain name')

    def test_snapshot_rejects_foreign_tenant_or_branch(self):
        for row in (dict(company_id='other', branch_id='branch'),
                    dict(company_id='tenant', branch_id='other')):
            with mock.patch.object(db, '_rpc', return_value=self.aggregate([row])), \
                 mock.patch.object(db, 'get_company_by_id', return_value={'id': 'tenant'}), \
                 mock.patch.object(db, '_decrypt_endpoint') as decrypt:
                with self.assertRaises(RuntimeError):
                    dashboard_fleet.snapshot('tenant', 'branch', NOW)
                decrypt.assert_not_called()

    def test_invalid_aggregate_is_not_silent_zero(self):
        for changes in (dict(online_count=-1), dict(stale_count=11),
                        dict(endpoints=[{}]*11), dict(total_count=True)):
            with mock.patch.object(db, '_rpc', return_value=dict(self.aggregate(), **changes)):
                with self.assertRaises(RuntimeError):
                    dashboard_fleet.snapshot('tenant', None, NOW)

    def test_only_missing_rpc_permits_legacy_fallback(self):
        for status, body, fallback in ((404, b'{"code":"PGRST202"}', True),
                                      (404, b'not json', False), (500,b'{}',False)):
            error = urllib.error.HTTPError('http://database', status, '', {}, io.BytesIO(body))
            with mock.patch.object(db, '_rpc', side_effect=error):
                if fallback:
                    self.assertIsNone(dashboard_fleet.snapshot('tenant',None,NOW))
                else:
                    with self.assertRaises(urllib.error.HTTPError):
                        dashboard_fleet.snapshot('tenant',None,NOW)

    def test_company_cache_is_request_local_and_invalidated(self):
        app = Flask(__name__)
        with mock.patch.object(db, '_get', side_effect=lambda path: [{'id':path}]) as read:
            with app.test_request_context('/'):
                db.get_company_by_id('one')
                db.get_company_by_id('one')
                db.get_company_by_id('two')
                self.assertEqual(read.call_count,2)
                with mock.patch.object(transport, '_json_request', return_value=[]):
                    transport.patch('companies?id=eq.one', {'name':'changed'})
                db.get_company_by_id('one')
                self.assertEqual(read.call_count,3)
            with app.test_request_context('/'):
                db.get_company_by_id('one')
            self.assertEqual(read.call_count,4)

    def test_metric_bounds_reject_bool_and_excess(self):
        for options in (dict(hours=True),dict(hours=169),dict(max_points=True),dict(max_points=1441)):
            with self.assertRaises(ValueError):
                metrics.get_metrics('endpoint', **options)

    def test_metric_rpc_keeps_ciphertext_until_bounded_decryption(self):
        rows = [dict(endpoint_id='endpoint', metrics_encrypted='v2:cipher') for _ in range(240)]
        with mock.patch.object(db,'_endpoint_company',return_value={'id':'tenant'}), \
             mock.patch.object(db,'_rpc',return_value=rows) as rpc, \
             mock.patch.object(db,'_get_all') as read, \
             mock.patch.object(db,'_endpoint_decrypt',return_value={'cpu_pct':5}) as decrypt:
            result = metrics.get_metrics('endpoint',max_points=240)
        self.assertEqual(len(result),240)
        self.assertEqual(decrypt.call_count,240)
        read.assert_not_called()
        self.assertEqual(rpc.call_args.args[1]['p_company_id'],'tenant')
        self.assertNotIn('metrics_encrypted',result[0])

    def test_metric_rpc_excess_is_rejected_before_decrypting(self):
        with mock.patch.object(db,'_endpoint_company',return_value={'id':'tenant'}), \
             mock.patch.object(db,'_rpc',return_value=[{}]*241), \
             mock.patch.object(db,'_endpoint_decrypt') as decrypt:
            with self.assertRaises(RuntimeError):
                metrics.get_metrics('endpoint',max_points=240)
        decrypt.assert_not_called()

    def test_missing_metric_rpc_buckets_before_decrypting(self):
        rows = [dict(collected_at=(NOW-timedelta(seconds=i+1)).isoformat(),
                     metrics_encrypted='v2:cipher') for i in reversed(range(3600))]
        error = urllib.error.HTTPError('http://database',404,'',{},io.BytesIO(b'{"code":"PGRST202"}'))
        clock = mock.Mock(wraps=datetime)
        clock.now.return_value = NOW
        with mock.patch.object(db,'datetime',clock), \
             mock.patch.object(db,'_endpoint_company',return_value={'id':'tenant'}), \
             mock.patch.object(db,'_rpc',side_effect=error), \
             mock.patch.object(db,'_get_all',return_value=rows), \
             mock.patch.object(db,'_endpoint_decrypt',return_value={'cpu_pct':5}) as decrypt:
            result = metrics.get_metrics('endpoint',hours=1,max_points=60)
        self.assertEqual(len(result),60)
        self.assertEqual(decrypt.call_count,60)

    def test_scheduler_measures_artifact_once_per_platform(self):
        endpoints = [dict(id=str(i),status='online',platform='windows',agent_version='2.6.9') for i in range(5)]
        build = dict(agent_version='2.6.10',sha256='a'*64)
        with mock.patch.object(db,'get_auto_update_company',return_value={'id':'tenant'}), \
             mock.patch('services.agent_rollouts.campaigns',return_value=[]), \
             mock.patch.object(db,'get_endpoints',return_value=endpoints), \
             mock.patch('services.fleet_reads.update_blockers',return_value={'0'}), \
             mock.patch.object(db,'get_latest_completed_build',return_value=build), \
             mock.patch.object(db,'get_active_remote_session',return_value=None) as remote, \
             mock.patch.object(scheduler,'update_payload',return_value={'sha256':'a'*64}) as payload, \
             mock.patch('services.fleet_tools.defer_updates',return_value=False), \
             mock.patch.object(db,'create_system_job_once',return_value={'id':'job'}) as create:
            scheduler._check_auto_updates()
        self.assertEqual(payload.call_count,1)
        self.assertEqual(remote.call_count,4)
        self.assertEqual(create.call_count,4)

    def test_split_roles_require_explicit_opt_in(self):
        with mock.patch.dict(os.environ,{},clear=True):
            self.assertEqual(process_role.role(),'combined')
            for value in ('api','background','relay','invalid'):
                os.environ['WARDEN_PROCESS_ROLE']=value
                with self.assertRaises(RuntimeError):
                    process_role.role()
            os.environ['WARDEN_ALLOW_SPLIT_SERVICES']='true'
            os.environ['WARDEN_PROCESS_ROLE']='api'
            self.assertEqual(process_role.role(),'api')

    def test_api_role_does_not_start_background_owners(self):
        os.environ['WERKZEUG_RUN_MAIN']='true'
        import app
        with mock.patch.dict(os.environ,dict(WARDEN_PROCESS_ROLE='api',WARDEN_ALLOW_SPLIT_SERVICES='true',
                                           WARDEN_RELAY_HEALTH_URL='http://relay:35022/ready')), \
             mock.patch('services.scheduler.start') as start, \
             mock.patch.object(db,'close_all_active_remote_sessions') as close:
            app.start_background_services()
        start.assert_not_called()
        close.assert_not_called()

    def test_dashboard_uses_full_counts_not_sample_length(self):
        from routes import dashboard
        app = Flask(__name__)
        rows = [dict(id='e1',company_id='tenant',hostname='Sample')]
        with app.test_request_context('/dashboard'):
            g.company={'id':'tenant'}
            g.admin={'id':'admin','role':'company_admin'}
            with mock.patch.object(dashboard_fleet,'snapshot',return_value=self.aggregate(rows)), \
                 mock.patch.object(db,'get_endpoints') as all_rows, \
                 mock.patch.object(db,'get_alerts',return_value=[dict(id='a1',endpoint_id='e2',type='offline')]), \
                 mock.patch.object(db,'get_jobs',return_value=[dict(endpoint_id='e2')]), \
                 mock.patch.object(db,'dashboard_counts',return_value={}), \
                 mock.patch.object(db,'get_branches',return_value=[]), \
                 mock.patch.object(db,'get_notifications',return_value=[]), \
                 mock.patch.object(db,'count_unread_notifications',return_value=0), \
                 mock.patch.object(db,'get_endpoints_bulk',return_value=[dict(id='e2',hostname='Other')]) as extra:
                data=dashboard._data()
        self.assertEqual(data['total_count'],1000)
        self.assertEqual(len(data['endpoints']),1)
        self.assertEqual(data['recent_jobs'][0]['_label'],'Other')
        self.assertEqual(data['recent_alerts'][0]['_label'],'Other')
        extra.assert_called_once_with('tenant',branch_id=None,endpoint_ids=['e2'])
        all_rows.assert_not_called()


class PoolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.connections = set()
        cls.requests = []
        parent = cls
        class Handler(BaseHTTPRequestHandler):
            protocol_version='HTTP/1.1'
            def do_GET(self):
                parent.connections.add(self.client_address)
                parent.requests.append(self.path)
                body=b'[]'
                self.send_response(302 if self.path=='/redirect' else 200)
                if self.path=='/redirect':
                    self.send_header('Location','http://example.invalid/secret')
                self.send_header('Content-Length',str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self,*args):
                pass
        cls.server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        cls.server.daemon_threads=True
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True)
        cls.thread.start()
        cls.origin='http://127.0.0.1:'+str(cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(2)

    def setUp(self):
        self.pool=http_pool.Pool(self.origin,ssl.create_default_context(),1)
        self.addCleanup(self.pool.close)

    def test_fully_consumed_responses_reuse_one_connection(self):
        before=len(self.connections)
        for _ in range(5):
            response=self.pool.open(urllib.request.Request(self.origin+'/reuse'))
            self.assertEqual(response.read(),b'[]')
            response.close()
            response.close()
        self.assertEqual(len(self.connections)-before,1)

    def test_redirect_never_follows_or_leaks_credentials(self):
        before=len(self.requests)
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.pool.open(urllib.request.Request(self.origin+'/redirect',headers={'Authorization':'test-only'}))
        caught.exception.close()
        self.assertEqual(self.requests[before:],['/redirect'])
        response=self.pool.open(urllib.request.Request(self.origin+'/okay'))
        response.close()

    def test_unconsumed_body_discards_connection_and_releases_slot(self):
        response=self.pool.open(urllib.request.Request(self.origin+'/partial'))
        response.read(1)
        response.close()
        self.assertEqual(len(self.pool.idle),0)
        response=self.pool.open(urllib.request.Request(self.origin+'/next'))
        response.close()

    def test_other_origin_and_userinfo_rejected_before_request(self):
        for url in ('http://example.invalid/', self.origin.replace('http://','http://user:password@')):
            with self.assertRaises(ValueError):
                self.pool.open(urllib.request.Request(url))

    def test_insecure_tls_context_is_rejected(self):
        with self.assertRaises(ValueError):
            http_pool.Pool('https://database.invalid',ssl._create_unverified_context())

    def test_closed_pool_does_not_accept_more_requests(self):
        self.pool.close()
        with self.assertRaises(urllib.error.URLError):
            self.pool.open(urllib.request.Request(self.origin+'/closed'))

    def test_failed_write_is_not_retried_and_slot_is_released(self):
        connection=mock.Mock()
        connection.request.side_effect=BrokenPipeError('synthetic stale socket')
        with mock.patch.object(http_pool.http.client,'HTTPConnection',return_value=connection) as create:
            with self.assertRaises(urllib.error.URLError):
                self.pool.open(urllib.request.Request(self.origin+'/write',data=b'{}',method='POST'))
        create.assert_called_once()
        connection.request.assert_called_once()
        connection.close.assert_called_once()
        self.assertTrue(self.pool.slots.acquire(blocking=False))
        self.pool.slots.release()
