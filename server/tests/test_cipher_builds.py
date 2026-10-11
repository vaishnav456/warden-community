import importlib.util
import io
import json
import pathlib
import sys
import types
import unittest
from unittest import mock
from flask import Flask
import config
from routes import build_service


class CipherBuildRoutesTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.register_blueprint(build_service.bp)
        self.client = self.app.test_client()
        self.headers = {'X-Build-Key': config.BUILD_SERVICE_KEY}

    def test_claim_requires_authentication_and_returns_atomic_claim_without_caching(self):
        with mock.patch.object(build_service.db, '_rpc', return_value=[{'id': 'synthetic', 'claim_token': 'claim'}]) as rpc:
            self.assertEqual(self.client.post('/api/build/claim').status_code, 401)
            rpc.assert_not_called()
            response = self.client.post('/api/build/claim', headers=self.headers)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json['id'], 'synthetic')
            self.assertEqual(response.headers['Cache-Control'], 'no-store')
            rpc.assert_called_once_with('claim_next_build', {'p_lease_seconds': 900})

    def test_renewal_is_fenced_and_refuses_invalid_or_expired_claims(self):
        token = '00000000-0000-4000-8000-000000000000'
        with mock.patch.object(build_service.db, '_rpc', return_value=False) as rpc:
            self.assertEqual(self.client.post('/api/build/test/renew', headers=self.headers).status_code, 400)
            rpc.assert_not_called()
            headers = dict(self.headers, **{'X-Build-Claim': token})
            self.assertEqual(self.client.post('/api/build/test/renew', headers=headers).status_code, 409)
            rpc.return_value = True
            self.assertEqual(self.client.post('/api/build/test/renew', headers=headers).json, {'ok': True})

    def test_failed_build_revokes_enrollment_only_after_fenced_update_succeeds(self):
        token = '00000000-0000-4000-8000-000000000000'
        row = {'status': 'building', 'claim_token': token, 'enrollment_token_id': 'synthetic-enrollment'}
        headers = dict(self.headers, **{'X-Build-Claim': token})
        with mock.patch.object(build_service.db, 'get_build_request', return_value=row), \
             mock.patch.object(build_service.db, 'fail_claimed_build', return_value=False) as failed, \
             mock.patch.object(build_service.db, 'deactivate_enrollment_token') as revoke:
            self.assertEqual(self.client.post('/api/build/test/fail', headers=headers, json={'error': 'test'}).status_code, 409)
            revoke.assert_not_called()
            failed.return_value = True
            self.assertEqual(self.client.post('/api/build/test/fail', headers=headers, json={'error': 'test'}).json, {'ok': True})
            revoke.assert_called_once_with('synthetic-enrollment')


class CipherBuildWorkerTests(unittest.TestCase):
    def setUp(self):
        fake = types.SimpleNamespace(SUPABASE_URL='http://127.0.0.1:9', SUPABASE_KEY='unused',
              DATABASE_MODE='ciphertext', WARDEN_SERVER_URL='https://configured.example.invalid', BUILD_SERVICE_KEY='isolated-test-build-key')
        path = pathlib.Path(__file__).resolve().parents[2] / 'build-service/db.py'
        spec = importlib.util.spec_from_file_location('cipher_build_worker_database', path)
        self.worker = importlib.util.module_from_spec(spec)
        with mock.patch.dict(sys.modules, {'config': fake}):
            spec.loader.exec_module(self.worker)

    def test_claim_and_renewal_use_configured_application_api_without_database_credentials(self):
        response = io.BytesIO(b'{"id":"synthetic","claim_token":"claim"}')
        with mock.patch.object(self.worker.urllib.request, 'urlopen', return_value=response) as send:
            self.assertEqual(self.worker.claim_next_queued_build()['id'], 'synthetic')
            request = send.call_args.args[0]
            self.assertEqual(request.full_url, 'https://configured.example.invalid/api/build/claim')
            self.assertEqual(request.method, 'POST')
            self.assertNotIn('Authorization', request.headers)
        with mock.patch.object(self.worker.urllib.request, 'urlopen', return_value=io.BytesIO(b'{"ok":true}')) as send:
            self.worker.renew_build_claim('id', 'claim')
            self.assertEqual(send.call_args.args[0].headers['X-build-claim'], 'claim')

    def test_failure_uses_fenced_api_and_direct_database_paths_fail_closed(self):
        with mock.patch.object(self.worker, '_application', return_value={'ok': True}) as send:
            self.worker.set_build_status('id', 'failed', 'claim', error_msg='synthetic failure')
            send.assert_called_once_with('/api/build/id/fail', {'error': 'synthetic failure'}, claim_token='claim')
        with mock.patch.object(self.worker.urllib.request, 'urlopen') as send:
            for fn,args in [(self.worker._get,('build_requests',)), (self.worker._post,('rpc/claim_next_build',{})),(self.worker._patch,('build_requests',{}))]:
                with self.assertRaises(RuntimeError):fn(*args)
            send.assert_not_called()


if __name__ == '__main__':
    unittest.main()
