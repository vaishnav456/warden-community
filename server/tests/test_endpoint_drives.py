import unittest
from services.endpoint_drives import local_drives


class DriveTests(unittest.TestCase):
    def endpoint(self, values):
        return {'capability_details': {'local_drives': {'volumes': values}}}

    def test_all_drive_letters_sorted_with_total_and_used(self):
        rows = local_drives(self.endpoint([
            dict(mount_point='H:', total_gb=100, free_gb=0),
            dict(mount_point='c:', total_gb=500, free_gb=200),
            dict(mount_point='D:', total_gb=50, free_gb=50)]))
        self.assertEqual([r['mount_point'] for r in rows], ['C:', 'D:', 'H:'])
        self.assertEqual(rows[0]['used_gb'], 300)
        self.assertEqual(rows[1]['used_pct'], 0)
        self.assertEqual(rows[2]['used_pct'], 100)

    def test_bad_or_duplicate_data_never_becomes_valid_usage(self):
        base = dict(mount_point='C:', total_gb=100, free_gb=20)
        rows = local_drives(self.endpoint([base, base,
            dict(base, mount_point='<script>'), dict(base, free_gb=-1),
            dict(base, total_gb=True), dict(base, free_gb=float('nan')),
            dict(base, free_gb=101), dict(base, total_gb=float('inf'))]))
        self.assertEqual(len(rows), 1)

    def test_old_agents_and_malformed_payloads_are_unknown(self):
        for endpoint in ({}, {'capability_details': []}, self.endpoint(None),
                         self.endpoint([None, 'C:'])):
            self.assertEqual(local_drives(endpoint), [])
