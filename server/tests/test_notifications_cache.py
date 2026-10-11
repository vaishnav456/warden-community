"""Request-local notification counts must never survive requests or mutations."""
import os
import unittest
from unittest import mock

from flask import Flask

import db
from database import notifications, transport


class UnreadCountCacheTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)

    def test_repeated_badge_reads_share_only_the_same_admin_and_request(self):
        with mock.patch.object(db, '_count', side_effect=[4, 7, 9]) as read:
            with self.app.test_request_context('/'):
                self.assertEqual(notifications.count_unread_notifications('admin-a'), 4)
                self.assertEqual(notifications.count_unread_notifications('admin-a'), 4)
                self.assertEqual(notifications.count_unread_notifications('admin-b'), 7)
                self.assertEqual(read.call_count, 2)
            with self.app.test_request_context('/'):
                self.assertEqual(notifications.count_unread_notifications('admin-a'), 9)
        self.assertEqual(read.call_count, 3)

    def test_background_reads_and_failed_counts_are_never_cached(self):
        with mock.patch.object(db, '_count', side_effect=[2, 3]) as read:
            self.assertEqual(notifications.count_unread_notifications('admin-a'), 2)
            self.assertEqual(notifications.count_unread_notifications('admin-a'), 3)
        self.assertEqual(read.call_count, 2)
        with self.app.test_request_context('/'):
            with mock.patch.object(db, '_count', side_effect=[RuntimeError('unavailable'), 5]) as read:
                with self.assertRaises(RuntimeError):
                    notifications.count_unread_notifications('admin-a')
                self.assertEqual(notifications.count_unread_notifications('admin-a'), 5)
                self.assertEqual(notifications.count_unread_notifications('admin-a'), 5)
                self.assertEqual(read.call_count, 2)

    def test_every_attempted_mutation_invalidates_all_admin_counts(self):
        mutations = (
            lambda: transport.post('unrelated_rows', {'value': 1}),
            lambda: transport.patch('unrelated_rows?id=eq.one', {'value': 1}),
            lambda: transport.rpc('possibly_writes_notifications', {}),
            lambda: transport.delete('unrelated_rows?id=eq.one'),
        )
        for mutation in mutations:
            for failed in (False, True):
                with self.subTest(mutation=mutation, failed=failed):
                    with self.app.test_request_context('/'):
                        with mock.patch.object(db, '_count', side_effect=[4, 7, 5, 8]) as read:
                            self.assertEqual(notifications.count_unread_notifications('admin-a'), 4)
                            self.assertEqual(notifications.count_unread_notifications('admin-b'), 7)
                            response = mock.Mock()
                            response.read.return_value = b'[]'
                            options = {'side_effect': RuntimeError('lost response')} if failed else {'return_value': response}
                            with mock.patch.dict(os.environ, {
                                    'WARDEN_DATABASE_MODE': 'legacy', 'CIPHER_SOCKET': '',
                                    'WARDEN_DB_HTTP_POOL': 'false'}), \
                                    mock.patch.object(db.urllib.request, 'urlopen', **options) as send:
                                if failed:
                                    with self.assertRaises(RuntimeError):
                                        mutation()
                                else:
                                    mutation()
                            send.assert_called_once()
                            self.assertEqual(notifications.count_unread_notifications('admin-a'), 5)
                            self.assertEqual(notifications.count_unread_notifications('admin-b'), 8)
                            self.assertEqual(read.call_count, 4)

    def test_read_only_transport_calls_keep_the_badge_count(self):
        with self.app.test_request_context('/'):
            with mock.patch.object(db, '_count', return_value=6) as count:
                self.assertEqual(notifications.count_unread_notifications('admin-a'), 6)
                response = mock.Mock()
                response.read.return_value = b'[]'
                response.headers = {'Content-Range': '*/6'}
                with mock.patch.object(transport, '_open', return_value=response):
                    transport.get('unrelated_rows')
                    transport.count('unrelated_rows')
                self.assertEqual(notifications.count_unread_notifications('admin-a'), 6)
                count.assert_called_once()

    def test_batch_attempts_invalidate_even_when_unavailable_or_response_is_lost(self):
        from database import cipher_transport
        for configured, failed in ((False, True), (True, False), (True, True)):
            with self.subTest(configured=configured, failed=failed):
                with self.app.test_request_context('/'):
                    with mock.patch.object(db, '_count', side_effect=[3, 8]) as read:
                        self.assertEqual(notifications.count_unread_notifications('admin-a'), 3)
                        options = {'side_effect': RuntimeError('lost response')} if failed else {'return_value': []}
                        with mock.patch.dict(os.environ, {'CIPHER_SOCKET': '/synthetic/cipher.sock' if configured else ''}), \
                                mock.patch.object(cipher_transport, 'open_batch', **options) as send:
                            if failed:
                                with self.assertRaises(RuntimeError):
                                    transport.batch([])
                            else:
                                transport.batch([])
                        self.assertEqual(send.call_count, int(configured))
                        self.assertEqual(notifications.count_unread_notifications('admin-a'), 8)
                        self.assertEqual(read.call_count, 2)


if __name__ == '__main__':
    unittest.main()
