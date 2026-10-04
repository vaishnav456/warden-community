"""Database compatibility, response cleanup and metadata count regressions."""
import json
import subprocess
import sys
import unittest
from unittest import mock

import db
from database import transport


class DatabaseModularityTests(unittest.TestCase):
    def response(self, payload=b'[]', count='*/2501'):
        result = mock.Mock()
        result.read.return_value = payload
        result.headers = {'Content-Range': count}
        return result

    def test_json_requests_close_response_and_preserve_profiles(self):
        calls = [
            ('GET', lambda: db._get('things', schema='other')),
            ('POST', lambda: db._post('things', {'x': 1}, schema='other')),
            ('PATCH', lambda: db._patch('things', {'x': 1}, schema='other')),
            ('POST', lambda: db._rpc('atomic_operation', {'x': 1}, schema='other')),
        ]
        for method, call in calls:
            with self.subTest(method=method, call=call):
                response = self.response()
                with mock.patch.object(db.urllib.request, 'urlopen', return_value=response) as send:
                    self.assertEqual(call(), [])
                response.close.assert_called_once()
                request = send.call_args.args[0]
                self.assertEqual(request.get_method(), method)
                profile = 'Accept-profile' if method == 'GET' else 'Content-profile'
                self.assertEqual(request.get_header(profile), 'other')
                self.assertEqual(request.get_header('Apikey'), db.config.SUPABASE_SERVICE_KEY)
                self.assertEqual(send.call_args.kwargs, {'timeout': 15, 'context': db._SSL_CTX})
                if method != 'GET':
                    self.assertEqual(json.loads(request.data), {'x': 1})

    def test_empty_writes_supported_but_empty_get_is_not_success(self):
        for call in [lambda: db._post('things', None, prefer='return=minimal'),
                     lambda: db._patch('things', {}), lambda: db._rpc('atomic_operation', {})]:
            response = self.response(b'')
            with mock.patch.object(db.urllib.request, 'urlopen', return_value=response):
                self.assertIsNone(call())
            response.close.assert_called_once()
        response = self.response(b'')
        with mock.patch.object(db.urllib.request, 'urlopen', return_value=response):
            with self.assertRaises(json.JSONDecodeError):
                db._get('things')
        response.close.assert_called_once()

    def test_parse_or_read_failure_closes_response_without_retry(self):
        for response in [self.response(b'not JSON'), self.response()]:
            if response.read.return_value == b'[]':
                response.read.side_effect = OSError('interrupted response')
            with mock.patch.object(db.urllib.request, 'urlopen', return_value=response) as send:
                with self.assertRaises((json.JSONDecodeError, OSError)):
                    db._post('things', {})
            response.close.assert_called_once()
            send.assert_called_once()

    def test_delete_closes_response_without_reading_it(self):
        response = self.response()
        with mock.patch.object(db.urllib.request, 'urlopen', return_value=response) as send:
            self.assertIsNone(db._delete('things', schema='other'))
        response.close.assert_called_once()
        response.read.assert_not_called()
        self.assertEqual(send.call_args.args[0].get_method(), 'DELETE')

    def test_counts_use_head_without_downloading_rows(self):
        for call in [lambda: db.count_open_alerts('tenant', 'branch'),
                     lambda: db.count_unread_notifications('admin')]:
            response = self.response()
            with mock.patch.object(db.urllib.request, 'urlopen', return_value=response) as send:
                self.assertEqual(call(), 2501)
            request = send.call_args.args[0]
            self.assertEqual(request.get_method(), 'HEAD')
            self.assertEqual(request.get_header('Prefer'), 'count=exact')
            response.read.assert_not_called()
            response.close.assert_called_once()

    def test_alert_count_retains_tenant_branch_and_snooze_filters(self):
        with mock.patch.object(db, '_count', return_value=5000) as count:
            self.assertEqual(db.count_open_alerts('tenant&other', 'branch'), 5000)
        path = count.call_args.args[0]
        self.assertIn('company_id=eq.tenant%26other', path)
        self.assertIn('branch_id=eq.branch', path)
        self.assertIn('is_resolved=eq.false', path)
        self.assertIn('snoozed_until.is.null', path)

    def test_unknown_counts_fail_closed(self):
        for value in ['', '*/unknown', '0-9/*']:
            response = self.response(count=value)
            with mock.patch.object(db.urllib.request, 'urlopen', return_value=response):
                with self.assertRaises(RuntimeError):
                    transport.count('things?select=id')
            response.close.assert_called_once()

    def test_domain_queries_resolve_patched_transport_dynamically(self):
        self.assertEqual(db.get_home_nodes.__module__, 'database.home_storage')
        with mock.patch.object(db, '_get', return_value=[{'id': 'node'}]) as get:
            self.assertEqual(db.get_home_nodes('tenant'), [{'id': 'node'}])
        self.assertIn('company_id=eq.tenant', get.call_args.args[0])

    def test_remote_domain_resolves_patched_security_helpers(self):
        with mock.patch.object(db, 'get_remote_session', return_value={'admin_id': 'owner'}), \
             mock.patch.object(db, 'get_admin_by_id', return_value={'is_active': False}), \
             mock.patch.object(db, '_patch') as write:
            with self.assertRaises(ValueError):
                db.update_remote_session_controls('session', 'view', {}, '', False)
        write.assert_not_called()

    def test_domain_can_be_imported_before_db_without_circular_import(self):
        result = subprocess.run([sys.executable, '-c',
            'from database.home_storage import get_home_nodes; import db; assert db.get_home_nodes is get_home_nodes'],
            capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
