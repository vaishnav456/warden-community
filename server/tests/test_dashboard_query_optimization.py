"""Dashboard projections must retain tenant, branch and artifact boundaries."""
import unittest
from datetime import datetime, timezone
from unittest import mock

import db
from services.dashboard_view import prepare_endpoints


class DashboardQueryOptimizationTests(unittest.TestCase):
    def query(self, call):
        with mock.patch.object(db, '_get', return_value=[]) as read:
            call()
        return read.call_args.args[0]

    def test_build_summary_does_not_fetch_config_or_remove_artifact_checks(self):
        query = self.query(lambda: db.get_latest_completed_build('linux-arm64', summary_only=True))
        for required in ['select=agent_version', 'status=eq.completed', 'sha256=not.is.null',
                         'target_platform=eq.linux-arm64', 'order=completed_at.desc', 'limit=1']:
            self.assertIn(required, query)
        self.assertNotIn('config_json', query)

    def test_full_build_caller_remains_full_detail(self):
        self.assertNotIn('select=', self.query(lambda: db.get_latest_completed_build()))

    def test_patch_summary_filters_tenant_and_branch_before_transferring_data(self):
        query = self.query(lambda: db.get_patch_inventory('tenant&other', 'branch&other', summary_only=True))
        for required in ['company_id=eq.tenant%26other', 'endpoints.branch_id=eq.branch%26other',
                         'select=endpoint_id,endpoints!inner(branch_id)', 'order=endpoint_id.asc']:
            self.assertIn(required, query)
        self.assertNotIn('title', query)

    def test_compliance_summary_keeps_fields_needed_for_encryption_status(self):
        query = self.query(lambda: db.get_compliance_results_for_company('tenant', 'branch', summary_only=True))
        self.assertIn('company_id=eq.tenant', query)
        self.assertIn('endpoints.branch_id=eq.branch', query)
        self.assertIn('select=endpoint_id,scanned_at,results,endpoints!inner(branch_id)', query)

    def test_branch_filter_applies_to_full_compliance_caller_too(self):
        query = self.query(lambda: db.get_compliance_results_for_company('tenant', 'branch'))
        self.assertIn('select=*,endpoints!inner(branch_id)', query)
        self.assertIn('endpoints.branch_id=eq.branch', query)

    def test_unscoped_full_reports_remain_compatible(self):
        patch = self.query(lambda: db.get_patch_inventory('tenant'))
        compliance = self.query(lambda: db.get_compliance_results_for_company('tenant'))
        self.assertNotIn('select=', patch)
        self.assertIn('order=severity.desc,title.asc', patch)
        self.assertNotIn('select=', compliance)

    def test_build_reads_scale_with_platforms_not_device_count(self):
        now = datetime.now(timezone.utc)
        endpoints = [dict(id=str(index), platform='linux' if index % 3 else 'windows',
                          arch='arm64' if index % 3 == 2 else 'amd64',
                          hostname=f'PC-{index}', status='online', last_seen=now.isoformat(),
                          agent_version='2.6.58') for index in range(1000)]
        with mock.patch.object(db, 'get_latest_completed_build', return_value={'agent_version': '2.6.59'}) as reads:
            result = prepare_endpoints(endpoints, now=now)
        self.assertEqual(len(result), 1000)
        self.assertEqual(reads.call_count, 3)
        self.assertTrue(all(call.kwargs == {'summary_only': True} for call in reads.call_args_list))
        self.assertTrue(all(row['_agent_update'] for row in result))


if __name__ == '__main__':
    unittest.main()
