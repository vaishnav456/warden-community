import unittest
import tempfile
from pathlib import Path
from unittest import mock
from services import tenant_storage


class ProfileStorageTests(unittest.TestCase):
    def test_database_photo_bytes_are_included_without_hosted_plan_limits(self):
        with tempfile.TemporaryDirectory() as folder, \
             mock.patch.object(tenant_storage.config, 'UPLOAD_DIR', Path(folder)), \
             mock.patch.object(tenant_storage.config, 'AGENT_DIST_DIR', Path(folder)), \
             mock.patch.object(tenant_storage.db, 'get_app_library', return_value=[]), \
             mock.patch.object(tenant_storage.db, 'get_build_requests', return_value=[]), \
             mock.patch.object(tenant_storage.db, '_rpc', return_value=12345) as rpc:
            result = tenant_storage.usage('tenant')
        self.assertEqual(result, dict(used_bytes=12345, file_bytes=0, database_bytes=12345))
        rpc.assert_called_once_with('tenant_database_bytes', {'p_company_id': 'tenant'})
