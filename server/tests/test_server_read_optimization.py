"""Pagination and aggregate-query rollout/authorization regressions."""
import io
import json
import unittest
import urllib.error
from datetime import datetime, timezone
from unittest import mock

import db
from database.dashboard import COUNTERS
from database.transport import RowPage


class ServerReadOptimizationTests(unittest.TestCase):
    def test_short_server_capped_pages_are_not_mistaken_for_the_end(self):
        pages = [RowPage([{'id': 1}, {'id': 2}]), RowPage([{'id': 3}], offset=2), RowPage([], offset=3)]
        with mock.patch.object(db, '_get', side_effect=pages) as read:
            self.assertEqual(db._get_all('endpoints?company_id=eq.tenant&order=id.asc'), [{'id': 1}, {'id': 2}, {'id': 3}])
        for call, offset in zip(read.call_args_list, [0, 2, 3]):
            self.assertIn(f'offset={offset}', call.args[0])
            self.assertIn('company_id=eq.tenant', call.args[0])

    def test_known_total_avoids_an_extra_empty_page_request(self):
        with mock.patch.object(db, '_get', return_value=RowPage([1, 2], total=2)) as read:
            self.assertEqual(db._get_all('things?order=id.asc'), [1, 2])
        read.assert_called_once()

    def test_pagination_rejects_ambiguous_query_bounds_and_non_lists(self):
        for path in ['things', 'things?order=id.asc&limit=1', 'things?order=id.asc&offset=1']:
            with self.assertRaises(ValueError):
                db._get_all(path)
        with mock.patch.object(db, '_get', return_value={'rows': []}):
            with self.assertRaises(RuntimeError):
                db._get_all('things?order=id.asc')

    def test_safety_bound_never_returns_a_silently_incomplete_list(self):
        with mock.patch.object(db, '_get', return_value=RowPage([1])):
            with self.assertRaises(RuntimeError):
                db._get_all('things?order=id.asc', max_pages=2)

    def test_get_response_remains_a_list_but_preserves_total(self):
        response = mock.Mock()
        response.read.return_value = b'[{"id": 1}]'
        response.headers = {'Content-Range': '10-10/100'}
        with mock.patch.object(db.urllib.request, 'urlopen', return_value=response):
            page = db._get('things?order=id.asc&offset=10')
        self.assertIsInstance(page, list)
        self.assertEqual(page.offset, 10)
        self.assertEqual(page.total, 100)
        self.assertEqual(json.dumps(page), '[{"id": 1}]')
        response.close.assert_called_once()

    def test_aggregate_uses_one_request_with_explicit_company_branch_and_time(self):
        now = datetime(2026, 10, 4, tzinfo=timezone.utc)
        expected = dict.fromkeys(COUNTERS, 10)
        with mock.patch.object(db, '_rpc', return_value=expected) as read, mock.patch.object(db, 'dashboard_count') as old:
            self.assertEqual(db.dashboard_counts('company', 'branch', now), expected)
        read.assert_called_once_with('dashboard_counts', {'p_company_id': 'company', 'p_branch_id': 'branch', 'p_now': now.isoformat()})
        old.assert_not_called()

    def test_missing_function_alone_uses_scoped_legacy_counts(self):
        error = urllib.error.HTTPError('http://isolated/rpc/dashboard_counts', 404, 'missing function', {}, io.BytesIO(b'{"code":"PGRST202"}'))
        with mock.patch.object(db, '_rpc', side_effect=error), mock.patch.object(db, 'dashboard_count', return_value=9) as old:
            self.assertEqual(db.dashboard_counts('company', 'branch'), dict.fromkeys(COUNTERS, 9))
        self.assertEqual(old.call_count, 6)
        self.assertTrue(all(c.kwargs['company_id'] == 'company' and c.kwargs['branch_id'] == 'branch' for c in old.call_args_list))

    def test_permission_or_database_failures_never_fall_back_or_become_zero(self):
        for status, payload in [(401, b'{}'), (500, b'{}'), (404, b'{"code":"OTHER"}')]:
            error = urllib.error.HTTPError('http://isolated', status, 'failure', {}, io.BytesIO(payload))
            with mock.patch.object(db, '_rpc', side_effect=error), mock.patch.object(db, 'dashboard_count') as old:
                with self.assertRaises(urllib.error.HTTPError):
                    db.dashboard_counts('company')
            old.assert_not_called()

    def test_aggregate_rejects_missing_negative_boolean_or_noninteger_counts(self):
        for bad in [None, {}, dict.fromkeys(COUNTERS, -1), dict.fromkeys(COUNTERS, True), dict.fromkeys(COUNTERS, '10')]:
            with mock.patch.object(db, '_rpc', return_value=bad):
                with self.assertRaises(RuntimeError):
                    db.dashboard_counts('company')

    def test_naive_timestamps_are_rejected(self):
        with self.assertRaises(ValueError):
            db.dashboard_counts('company', now=datetime(2026, 10, 4))

    def test_bulk_selection_cannot_override_the_requested_branch(self):
        with mock.patch.object(db, '_get_all', return_value=[]) as read, \
             mock.patch.object(db, 'get_company_by_id', return_value={'id': 'tenant'}):
            self.assertEqual(db.get_endpoints_bulk('tenant', 'branch', ['device']), [])
        query = read.call_args.args[0]
        for constraint in ['company_id=eq.tenant', 'branch_id=eq.branch', 'id=in.(device)', 'order=id.asc']:
            self.assertIn(constraint, query)

    def test_monitoring_summaries_read_all_rows_with_stable_scoped_queries(self):
        with mock.patch.object(db, '_get_all', return_value=[{'status': 'pending'}, {'status': 'running'}]) as read:
            self.assertEqual(db.get_job_queue_stats('tenant', 'branch')['running'], 1)
        self.assertIn('order=id.asc', read.call_args.args[0])
        self.assertIn('branch_id=eq.branch', read.call_args.args[0])
        with mock.patch.object(db, '_get_all', return_value=[{'status': 'online'}, {'status': 'offline'}]) as read:
            self.assertEqual(db.get_endpoint_summary('tenant', 'branch')['total'], 2)
        self.assertIn('order=id.asc', read.call_args.args[0])
        self.assertIn('company_id=eq.tenant', read.call_args.args[0])

    def test_endpoint_pages_decrypt_once_per_row_and_can_skip_redundant_sort(self):
        rows = [{'id': '2', 'hostname': 'Z'}, {'id': '1', 'hostname': 'A'}]
        with mock.patch.object(db, '_get_all', return_value=rows) as reads, \
             mock.patch.object(db, 'get_company_by_id', return_value={'id': 'tenant'}), \
             mock.patch.object(db, '_decrypt_endpoint', side_effect=lambda row, company: row) as decrypt:
            self.assertEqual(db.get_endpoints('tenant', 'branch', sort_names=False), rows)
        self.assertEqual(decrypt.call_count, 2)
        self.assertIn('branch_id=eq.branch', reads.call_args.args[0])
        self.assertIn('order=id.asc', reads.call_args.args[0])


if __name__ == '__main__':
    unittest.main()
