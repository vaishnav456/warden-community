import importlib.util
import json
import os
import pathlib
import signal
import asyncio
import base64
import hashlib
import threading
import tempfile
import unittest
from unittest import mock
from flask import Flask, g
from services import lifecycle, operational_metrics, operational_requests
from services import operations, storage_reconciliation, mail
os.environ['WERKZEUG_RUN_MAIN'] = 'true'


def load_tool(name):
    path = pathlib.Path(__file__).resolve().parents[2] / 'tools' / (name + '.py')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FoundationTests(unittest.TestCase):
    def tearDown(self):
        lifecycle.stopping.clear()

    def test_metrics_are_bounded_and_snapshot_is_independent(self):
        metrics = operational_metrics.Metrics()
        for index in range(1000):
            metrics.observe('route' + str(index), .1)
        self.assertLessEqual(len(metrics.snapshot()), 128)
        snapshot = metrics.snapshot()
        snapshot['route0']['buckets'][0] = 100
        self.assertNotEqual(metrics.snapshot()['route0']['buckets'][0], 100)
        metrics.observe('invalid', float('nan'))
        self.assertNotIn('invalid', metrics.snapshot())

    def test_database_failure_records_timing_without_payloads(self):
        @operational_metrics.observe_database
        def fail(secret):
            raise OSError(secret)
        metrics = operational_metrics.Metrics()
        with mock.patch.object(operational_metrics, 'metrics', metrics):
            with self.assertRaises(OSError):
                fail('never-retain-this-secret')
        result = metrics.snapshot()
        self.assertEqual(result['database']['errors'], 1)
        self.assertNotIn('never-retain-this-secret', json.dumps(result))

    def test_admission_borrows_idle_capacity_but_is_bounded(self):
        admission = operational_requests.Admission(4)
        for _ in range(4):
            self.assertTrue(admission.acquire('a'))
        self.assertFalse(admission.acquire('b'))
        for _ in range(4):
            admission.release('a')
        self.assertEqual(admission.snapshot()['active'], 0)
        self.assertTrue(admission.acquire('a'))
        self.assertTrue(admission.acquire('b'))
        self.assertTrue(admission.acquire('a'))
        self.assertFalse(admission.acquire('a'))
        self.assertTrue(admission.acquire('b'))

    def test_pressure_does_not_shed_heartbeat_and_teardown_releases(self):
        app = Flask(__name__)
        @app.before_request
        def identity():
            g.admin = {'role': 'company_admin'}
            g.company = {'id': 'tenant'}
        operational_requests.install(app)
        @app.post('/api/agent/heartbeat')
        def heartbeat():
            return {'ok': True}
        @app.post('/apps/upload')
        def upload():
            return {'ok': True}
        admission = operational_requests.Admission(1)
        with mock.patch.object(operational_requests, 'admission', admission), \
             mock.patch.object(operational_requests.controller, 'busy', True):
            self.assertEqual(app.test_client().post('/api/agent/heartbeat').status_code, 200)
            response = app.test_client().post('/apps/upload', content_type='multipart/form-data')
            self.assertEqual(response.status_code, 429)
            self.assertEqual(response.headers['Retry-After'], '5')
        with mock.patch.object(operational_requests, 'admission', admission), \
             mock.patch.object(operational_requests.controller, 'busy', False):
            lifecycle.begin_shutdown()
            self.assertEqual(app.test_client().post('/apps/upload', content_type='multipart/form-data').status_code, 503)
            lifecycle.stopping.clear()
            self.assertEqual(app.test_client().post('/apps/upload', content_type='multipart/form-data').status_code, 200)
        self.assertEqual(admission.snapshot()['active'], 0)

    def test_shutdown_chains_worker_handlers(self):
        previous = mock.Mock()
        handlers = {}
        with mock.patch.object(signal, 'getsignal', return_value=previous), \
             mock.patch.object(signal, 'signal', side_effect=lambda number, handler: handlers.update({number: handler})):
            lifecycle.install_signal_handlers()
        handlers[signal.SIGTERM](signal.SIGTERM, None)
        self.assertTrue(lifecycle.stopping.is_set())
        previous.assert_called_once_with(signal.SIGTERM, None)

    def test_queue_snapshot_never_reads_payloads_and_keeps_branch_filter(self):
        with mock.patch.object(operations.db, '_count', return_value=4) as count, \
             mock.patch.object(operations.db, '_get', return_value=[]) as read:
            result = operations.queue_snapshot('tenant', 'branch')
        self.assertIsNone(result['oldest_pending_seconds'])
        for call in count.call_args_list + read.call_args_list:
            self.assertIn('company_id=eq.tenant', call.args[0])
            self.assertIn('branch_id=eq.branch', call.args[0])
            self.assertNotIn('payload', call.args[0])

    def test_storage_reconciliation_is_read_only_and_excludes_other_tenants(self):
        tenant = '11111111-1111-1111-1111-111111111111'
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            own = root / 'apps' / tenant
            own.mkdir(parents=True)
            orphan = own / 'unreferenced'
            orphan.write_bytes(b'abc')
            other = root / 'apps' / 'another'
            other.mkdir()
            (other / 'secret').write_bytes(b'123456')
            with mock.patch.object(storage_reconciliation.config, 'UPLOAD_DIR', root), \
                 mock.patch.object(storage_reconciliation, 'admission') as lease, \
                 mock.patch.object(storage_reconciliation.db, '_get_all', return_value=[]) as read:
                report = storage_reconciliation.reconcile(tenant)
            self.assertEqual(report['unreferenced_bytes'], 3)
            self.assertTrue(orphan.exists())
            self.assertNotIn('unreferenced', str(report['path_fingerprints']))
            self.assertIn('company_id=eq.' + tenant, read.call_args.args[0])
            lease.assert_called_once_with(tenant, 0)

    def test_fanout_failure_has_backoff_and_eventually_dead_letters(self):
        for attempt in (1, 6):
            event = dict(id='event', attempts=attempt)
            with mock.patch.object(mail.db, '_rpc', return_value=[event]), \
                 mock.patch.object(mail, '_fanout_event', side_effect=ValueError('secret')), \
                 mock.patch.object(mail.db, '_patch') as patch:
                self.assertTrue(mail.fanout_one())
            query, fields = patch.call_args.args
            self.assertIn('claim_token=eq.', query)
            self.assertIsNone(fields['lease_until'])
            self.assertIn('dead_lettered_at' if attempt == 6 else 'available_at', fields)
            self.assertNotIn('secret', json.dumps(fields))

    def test_tools_reject_unsafe_load_targets_and_invalid_bounds(self):
        path = pathlib.Path(__file__).resolve().parents[2] / 'tools' / 'load_test_server.py'
        spec = importlib.util.spec_from_file_location('load_test_server', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for target in ['http://public.example', 'https://user:password@example.com', 'https://example.com?secret=1']:
            with self.assertRaises(ValueError):
                module.run(target)
        with self.assertRaises(ValueError):
            module.run('http://localhost', requests=10001)

    def test_load_probe_runs_bounded_concurrent_gets(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        module = load_tool('load_test_server')
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"status":"ok"}')
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with mock.patch.dict(os.environ, {'WARDEN_LOAD_TEST_TOKEN': ''}):
                report = module.run('http://127.0.0.1:' + str(server.server_port), requests=20, concurrency=4)
            self.assertEqual(report['statuses'], {'200': 20})
            self.assertGreaterEqual(report['p95_ms'], report['median_ms'])
        finally:
            server.shutdown()
            server.server_close()
            worker.join(2)

    def test_recovery_hashes_key_probe_and_tampering(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        module = load_tool('verify_recovery_bundle')
        key, nonce, plain = os.urandom(32), os.urandom(12), b'recovery-test-probe'
        blob = nonce + AESGCM(key).encrypt(nonce, plain, module.AAD)
        with tempfile.TemporaryDirectory() as directory:
            file = pathlib.Path(directory) / 'synthetic.dump'
            file.write_bytes(b'database-fixture')
            manifest = dict(version=1, files=[dict(path=file.name, bytes=file.stat().st_size,
                            sha256=hashlib.sha256(file.read_bytes()).hexdigest())],
                            encrypted_probe=base64.b64encode(blob).decode(),
                            probe_sha256=hashlib.sha256(plain).hexdigest())
            self.assertEqual(module.verify(directory, manifest, key)['key_probe'], 'passed')
            with self.assertRaises(Exception):
                module.verify(directory, manifest, os.urandom(32))
            file.write_bytes(b'modified')
            with self.assertRaises(ValueError):
                module.verify(directory, manifest, key)

    def test_readiness_rejects_drain_without_database_work(self):
        import app as warden_app
        lifecycle.begin_shutdown()
        with mock.patch('db.healthcheck') as health:
            response = warden_app.app.test_client().get('/ready')
        self.assertEqual(response.status_code, 503)
        health.assert_not_called()

    def test_performance_endpoint_requires_privilege_and_returns_safe_load_fields(self):
        import app as warden_app
        from middleware import auth
        hosted = hasattr(auth, 'superadmin_required')
        def identity(privileged):
            g.admin = dict(id='admin', role=('superadmin' if hosted else 'company_admin')
                           if privileged else 'technician', mfa_enabled=True)
            g.company = dict(id='tenant', encryption_mode='server')
            g.is_superadmin = hosted and privileged
        for privileged, expected in ((False, 403), (True, 200)):
            with mock.patch.object(warden_app, 'load_current_user', side_effect=lambda: identity(privileged)), \
                 mock.patch.object(warden_app, 'check_firewall', return_value=None):
                response = warden_app.app.test_client().get('/status/performance')
            self.assertEqual(response.status_code, expected)
            if privileged:
                self.assertIn('cpu_ratio', response.get_json()['load'])
                self.assertEqual(response.headers['Cache-Control'], 'no-store')

    def test_reconciliation_bounds_are_explicit(self):
        tenant = '11111111-1111-1111-1111-111111111111'
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            own = root / 'apps' / tenant
            own.mkdir(parents=True)
            for name in ('one', 'two'):
                (own / name).write_bytes(b'a')
            with mock.patch.object(storage_reconciliation.config, 'UPLOAD_DIR', root), \
                 mock.patch.object(storage_reconciliation, 'admission'), \
                 mock.patch.object(storage_reconciliation.db, '_get_all', return_value=[]):
                report = storage_reconciliation.reconcile(tenant, max_files=1)
            self.assertFalse(report['complete'])
            self.assertEqual(report['scanned_files'], 1)


class RelayDrainTests(unittest.IsolatedAsyncioTestCase):
    async def test_controlled_close_does_not_abort_when_one_peer_fails(self):
        from services import ws_proxy
        pair = ws_proxy._Pair()
        pair.agent_ws = mock.Mock(close=mock.AsyncMock(side_effect=OSError('disconnected')))
        pair.browser_ws = mock.Mock(close=mock.AsyncMock())
        with mock.patch.object(ws_proxy, '_pairs', {'test': pair}), \
             mock.patch.object(ws_proxy, '_home_pairs', {}):
            await ws_proxy._shutdown_relays()
        pair.browser_ws.close.assert_awaited_once_with(1012, 'server restarting; reconnect')
