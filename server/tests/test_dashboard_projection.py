"""Dashboard cards and activity labels must not decrypt unused private data."""
import unittest
from datetime import datetime, timezone
from unittest import mock
from urllib.parse import parse_qs, urlsplit

import db
from services import dashboard_fleet

NOW = datetime(2026, 10, 11, tzinfo=timezone.utc)


class DashboardProjectionTests(unittest.TestCase):
    def company(self):
        return {'id': 'tenant', 'encryption_mode': 'managed', 'wrapped_dek': 'synthetic-wrapped'}

    def aggregate(self, row):
        return {'total_count': 20, 'online_count': 19, 'offline_count': 1, 'stale_count': 1,
                'health': {'agent_updates': 2, 'agent_unknown': 3, 'encryption_attention': 4,
                           'encryption_unknown': 5, 'patch_attention': 6}, 'endpoints': [row]}

    def endpoint(self):
        return {'id': 'endpoint', 'company_id': 'tenant', 'branch_id': 'branch',
                'hostname': 'v2:hostname', 'display_name': 'v2:display-name', 'os_name': 'v2:os-name',
                'platform': 'windows', 'status': 'online', 'last_seen': NOW.isoformat(),
                'cpu_pct': 2, 'ram_used_pct': 3, 'heartbeat_encrypted': 'v2:heartbeat',
                '_online': True, '_fresh': True, '_agent_update': False, '_agent_unknown': False,
                '_encryption': 'pass', '_patch_attention': True, '_offline_age': 'recent',
                'hardware_id': 'v2:unused-hardware', 'notes': 'v2:unused-notes',
                'agent_integrity_encrypted': 'v2:unused-integrity',
                'device_identity_encrypted': 'v2:unused-identity',
                'topology_telemetry_encrypted': 'v2:unused-topology',
                'capability_details_encrypted': 'v2:unused-capabilities',
                'asset_metadata_encrypted': 'v2:unused-assets', 'sys_info': 'unused-inventory'}

    def decrypt(self, company, field, value):
        expected = {'hostname', 'display_name', 'os_name', 'heartbeat'}
        if field not in expected:
            self.fail('Dashboard decrypted unused field: ' + field)
        if field == 'heartbeat':
            return {'cpu_pct': 31, 'ram_used_pct': 47, 'disk_free_gb': 90,
                    'agent_memory_mb': 30, 'agent_uptime_sec': 60, 'net_sent_mbps': 1, 'net_recv_mbps': 2}
        return field + '-readable'

    def test_snapshot_decrypts_card_fields_and_keeps_metrics_flags_and_totals(self):
        original = self.endpoint()
        aggregate = self.aggregate(original)
        with mock.patch.object(db, '_rpc', return_value=aggregate), \
                mock.patch.object(db, 'get_company_by_id', return_value=self.company()), \
                mock.patch.object(db, '_endpoint_decrypt', side_effect=self.decrypt) as decrypt:
            result = dashboard_fleet.snapshot('tenant', 'branch', NOW)
        row = result['endpoints'][0]
        self.assertEqual({call.args[1] for call in decrypt.call_args_list},
                         {'hostname', 'display_name', 'os_name', 'heartbeat'})
        self.assertEqual(row['hostname'], 'hostname-readable')
        self.assertEqual(row['cpu_pct'], 31)
        self.assertEqual(row['ram_used_pct'], 47)
        self.assertEqual(row['disk_free_gb'], 90)
        self.assertEqual(row['net_recv_mbps'], 2)
        self.assertEqual(result['total_count'], 20)
        self.assertEqual(result['health']['patch_attention'], 6)
        for field in ('_online', '_fresh', '_agent_update', '_agent_unknown', '_encryption',
                      '_patch_attention', '_offline_age', 'status', 'last_seen', 'platform'):
            self.assertEqual(row[field], original[field])
        for field in ('hardware_id', 'notes', 'agent_integrity_encrypted', 'device_identity_encrypted',
                      'topology_telemetry_encrypted', 'capability_details_encrypted',
                      'asset_metadata_encrypted', 'sys_info'):
            self.assertNotIn(field, row)
            self.assertIn(field, original)

    def test_label_read_selects_only_scoped_names_and_decrypts_no_other_data(self):
        row = self.endpoint()
        with mock.patch.object(db, '_get_all', return_value=[row]) as read, \
                mock.patch.object(db, 'get_company_by_id', return_value=self.company()), \
                mock.patch.object(db, '_endpoint_decrypt', side_effect=self.decrypt) as decrypt:
            labels = db.get_endpoints_bulk('tenant', branch_id='branch', endpoint_ids=['endpoint'], labels_only=True)
        query = parse_qs(urlsplit(read.call_args.args[0]).query)
        self.assertEqual(query['company_id'], ['eq.tenant'])
        self.assertEqual(query['branch_id'], ['eq.branch'])
        self.assertEqual(query['id'], ['in.(endpoint)'])
        self.assertEqual(query['is_active'], ['eq.true'])
        self.assertEqual(query['order'], ['id.asc'])
        self.assertEqual(query['select'], ['id,company_id,branch_id,hostname,display_name'])
        self.assertEqual({call.args[1] for call in decrypt.call_args_list}, {'hostname', 'display_name'})
        self.assertEqual(set(labels[0]), {'id', 'company_id', 'branch_id', 'hostname', 'display_name'})

    def test_empty_label_id_set_never_reads_the_entire_fleet(self):
        with mock.patch.object(db, '_get_all') as read, mock.patch.object(db, 'get_company_by_id') as company:
            self.assertEqual(db.get_endpoints_bulk('tenant', endpoint_ids=[], labels_only=True), [])
        read.assert_not_called(); company.assert_not_called()

    def test_label_reads_reject_foreign_tenant_or_branch_before_decryption(self):
        for row in (dict(self.endpoint(), company_id='other'), dict(self.endpoint(), branch_id='other')):
            with self.subTest(row=row['company_id'] + ':' + row['branch_id']):
                with mock.patch.object(db, '_get_all', return_value=[row]), \
                        mock.patch.object(db, 'get_company_by_id', return_value=self.company()), \
                        mock.patch.object(db, '_decrypt_endpoint') as decrypt:
                    with self.assertRaises(RuntimeError):
                        db.get_endpoints_bulk('tenant', branch_id='branch', labels_only=True)
                decrypt.assert_not_called()

    def test_default_bulk_reads_keep_full_rows_and_existing_full_fleet_behavior(self):
        row = self.endpoint()
        for ids, branch in ((['endpoint'], None), (None, 'branch')):
            with self.subTest(ids=ids, branch=branch):
                with mock.patch.object(db, '_get_all', return_value=[row]) as read, \
                        mock.patch.object(db, 'get_company_by_id', return_value=self.company()), \
                        mock.patch.object(db, '_decrypt_endpoint', side_effect=lambda item, company: dict(item)) as decrypt:
                    result = db.get_endpoints_bulk('tenant', branch_id=branch, endpoint_ids=ids)
                self.assertNotIn('select=', read.call_args.args[0])
                self.assertIn('sys_info', decrypt.call_args.args[0])
                self.assertIn('agent_integrity_encrypted', result[0])
        with mock.patch.object(db, 'get_endpoints', return_value=[row]) as full:
            self.assertEqual(db.get_endpoints_bulk('tenant'), [row])
        full.assert_called_once_with('tenant')


if __name__ == '__main__':
    unittest.main()
