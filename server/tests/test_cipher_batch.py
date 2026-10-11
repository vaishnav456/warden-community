"""Coupled writes must use one encrypted request without a partial fallback."""
import json
import os
import unittest
from unittest import mock

from flask import Flask, g

import db
from database import cipher_transport, sessions
from middleware.auth import issue_refresh_token
from routes import auth as auth_routes


class CipherBatchTests(unittest.TestCase):
    def application(self):
        app = Flask(__name__)
        app.secret_key = 'synthetic-route-tests'
        app.register_blueprint(auth_routes.bp)

        @app.before_request
        def prepare_request():
            g.company_slug = ''
            g.admin = None

        @app.errorhandler(RuntimeError)
        def unavailable(_error):
            return 'Database unavailable', 503

        return app

    def admin(self, mfa_enabled=False):
        return {'id': 'synthetic-admin', 'email': 'fixture@example.invalid',
                'role': 'company_admin', 'is_active': True, 'company_id': 'synthetic-company',
                'password_hash': 'synthetic-hash', 'mfa_enabled': mfa_enabled,
                'mfa_secret': 'JBSWY3DPEHPK3PXP'}

    def test_batch_encodes_exact_values_and_validates_each_response(self):
        operations = [{'path': 'rows?id=eq.fixture', 'method': 'PATCH', 'data': {'value': 9007199254740993}},
                      {'path': 'rpc/create_refresh_session', 'method': 'POST', 'data': {'p_admin_id': 'fixture'}}]
        response = cipher_transport.Response({'status': 200, 'headers': {}, 'body': json.dumps([
            {'status': 200, 'headers': {}, 'body': ''},
            {'status': 200, 'headers': {}, 'body': '[{"value":9007199254740993}]'},
        ])})
        with mock.patch.object(cipher_transport, '_exchange', return_value=response) as send:
            self.assertEqual(cipher_transport.open_batch(operations), [None, [{'value': 9007199254740993}]])
            wire = send.call_args.args[0]
            self.assertEqual(set(wire), {'batch'})
            self.assertEqual(json.loads(wire['batch'][0]['data_json'])['value'], 9007199254740993)
            self.assertTrue(response.closed)
        for count in (0, 9):
            with self.assertRaises(ValueError):
                cipher_transport.open_batch(operations[:1] * count)
        for invalid in ({'status': 409, 'headers': {}, 'body': '{}'}, {'status': 200, 'headers': {}, 'body': None}):
            response = cipher_transport.Response({'status': 200, 'headers': {}, 'body': json.dumps([invalid])})
            with mock.patch.object(cipher_transport, '_exchange', return_value=response):
                with self.assertRaises(RuntimeError):
                    cipher_transport.open_batch(operations[:1])
            self.assertTrue(response.closed)

    def test_lost_batch_response_is_not_retried(self):
        with mock.patch.object(cipher_transport, '_exchange', side_effect=RuntimeError('lost response')) as send:
            with self.assertRaises(RuntimeError):
                cipher_transport.open_batch([{'method': 'POST', 'path': 'fixture', 'data': {'id': 'one'}}])
            send.assert_called_once()

    def test_cipher_login_bookkeeping_and_session_share_one_commit(self):
        with mock.patch.dict(os.environ, {'CIPHER_SOCKET': '/synthetic/private.sock'}), \
                mock.patch.object(db, '_batch', return_value=[None, [{'id': 'session'}]]) as batch, \
                mock.patch.object(db, '_rpc') as rpc, mock.patch.object(db, 'update_admin_last_login') as update:
            self.assertEqual(sessions.create_refresh_token('admin', 'hash', '127.0.0.1', 'test', 'future', 'absolute', record_login=True), {'id': 'session'})
            operations = batch.call_args.args[0]
            self.assertEqual(operations[0]['method'], 'PATCH')
            self.assertEqual(operations[0]['data']['failed_attempts'], 0)
            self.assertIsNone(operations[0]['data']['locked_until'])
            self.assertEqual(operations[1]['path'], 'rpc/create_refresh_session')
            self.assertEqual(operations[1]['data']['p_max_sessions'], db.config.MAX_CONCURRENT_SESSIONS)
            self.assertEqual(operations[1]['data']['p_token_hash'], 'hash')
            rpc.assert_not_called(); update.assert_not_called()

    def test_login_failure_returns_no_token_and_has_no_sequential_fallback(self):
        with mock.patch.dict(os.environ, {'CIPHER_SOCKET': '/synthetic/private.sock'}), \
                mock.patch.object(db, '_batch', side_effect=RuntimeError('failed atomic commit')) as batch, \
                mock.patch.object(db, '_rpc') as rpc, mock.patch.object(db, 'update_admin_last_login') as update:
            with self.assertRaises(RuntimeError):
                issue_refresh_token('admin', '127.0.0.1', 'test', record_login=True)
            batch.assert_called_once(); rpc.assert_not_called(); update.assert_not_called()

    def test_legacy_login_and_non_login_session_paths_remain_separate(self):
        with mock.patch.dict(os.environ, {'CIPHER_SOCKET': ''}), \
                mock.patch.object(db, '_rpc', return_value=[{'id': 'session'}]) as rpc, \
                mock.patch.object(db, 'update_admin_last_login') as update, mock.patch.object(db, '_batch') as batch:
            sessions.create_refresh_token('admin', 'hash', '127.0.0.1', 'test', 'future', 'absolute', record_login=True)
            update.assert_called_once_with('admin', '127.0.0.1'); rpc.assert_called_once(); batch.assert_not_called()
        with mock.patch.dict(os.environ, {'CIPHER_SOCKET': '/synthetic/private.sock'}), \
                mock.patch.object(db, '_rpc', return_value=[]) as rpc, mock.patch.object(db, '_batch') as batch:
            sessions.create_refresh_token('admin', 'hash', '127.0.0.1', 'test', 'future', 'absolute')
            rpc.assert_called_once(); batch.assert_not_called()

    def test_login_route_durability_failure_sends_no_auth_cookies(self):
        with self.application().test_client() as client:
            with mock.patch.dict(os.environ, {'CIPHER_SOCKET': '/synthetic/private.sock'}), \
                    mock.patch.object(auth_routes, 'check_rate_limit', return_value=True), \
                    mock.patch.object(auth_routes, '_check_password', return_value=True), \
                    mock.patch.object(db, 'get_admin_by_email', return_value=self.admin()), \
                    mock.patch.object(db, 'get_single_company', return_value={'id': 'synthetic-company', 'slug': 'fixture'}, create=True), \
                    mock.patch.object(db, '_batch', side_effect=RuntimeError('injected durability failure')) as batch, \
                    mock.patch.object(db, '_rpc') as rpc, \
                    mock.patch.object(db, 'update_admin_last_login') as update, \
                    mock.patch.object(auth_routes, '_set_auth_cookies', wraps=auth_routes._set_auth_cookies) as cookies:
                response = client.post('/login', data={'email': 'fixture@example.invalid', 'password': 'synthetic-password'})
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.headers.getlist('Set-Cookie'), [])
        batch.assert_called_once()
        rpc.assert_not_called(); update.assert_not_called(); cookies.assert_not_called()

    def test_mfa_route_durability_failure_sends_no_auth_cookies(self):
        with self.application().test_client() as client:
            client.set_cookie('warden_mfa_token', 'synthetic-token')
            client.set_cookie('warden_mfa_state', 'synthetic-state')
            with mock.patch.dict(os.environ, {'CIPHER_SOCKET': '/synthetic/private.sock'}), \
                    mock.patch.object(auth_routes, 'check_rate_limit', return_value=True), \
                    mock.patch.object(db, 'get_admin_by_id', return_value=self.admin(mfa_enabled=True)), \
                    mock.patch.object(db, 'get_single_company', return_value={'id': 'synthetic-company', 'slug': 'fixture'}, create=True), \
                    mock.patch('jwt.decode', return_value={'sub': 'synthetic-admin', 'state': 'synthetic-state'}), \
                    mock.patch('pyotp.TOTP.verify', return_value=True), \
                    mock.patch.object(db, '_batch', side_effect=RuntimeError('injected durability failure')) as batch, \
                    mock.patch.object(db, '_rpc') as rpc, \
                    mock.patch.object(db, 'update_admin_last_login') as update, \
                    mock.patch.object(auth_routes, '_set_auth_cookies', wraps=auth_routes._set_auth_cookies) as cookies:
                response = client.post('/mfa', data={'code': '123456'})
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.headers.getlist('Set-Cookie'), [])
        batch.assert_called_once()
        rpc.assert_not_called(); update.assert_not_called(); cookies.assert_not_called()
