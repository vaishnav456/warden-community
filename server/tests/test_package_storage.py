from contextlib import nullcontext
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import db
from services import package_storage as packages
from services.tenant_storage import StorageError


class PackageDeletionTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        sha = "a" * 64
        self.app = {"id": "app", "company_id": "tenant", "sha256": sha,
                    "file_path": f"apps/tenant/aa/{sha}.msi"}
        self.path = self.root / self.app["file_path"]
        self.path.parent.mkdir(parents=True)
        self.path.write_bytes(b"installer bytes")
        patches = [patch.object(packages.config, "UPLOAD_DIR", self.root),
                   patch.object(packages, "admission", return_value=nullcontext()),
                   patch.object(db, "get_app", return_value=self.app),
                   patch.object(db, "package_in_use", return_value=False),
                   patch.object(db, "get_app_file_references", return_value=[{"id": "app"}]),
                   patch.object(db, "request_app_deletion"), patch.object(db, "delete_app")]
        self.mocks = [item.start() for item in patches]
        for item in patches:
            self.addCleanup(item.stop)

    def test_last_reference_frees_file_bytes(self):
        result = packages.delete_package("tenant", "app")
        self.assertEqual(result["freed_bytes"], len(b"installer bytes"))
        self.assertFalse(self.path.exists())
        self.mocks[-1].assert_called_once_with("app")

    def test_other_reference_keeps_shared_file(self):
        self.mocks[4].return_value = [{"id": "app"}, {"id": "other-app"}]
        result = packages.delete_package("tenant", "app")
        self.assertEqual(result["freed_bytes"], 0)
        self.assertTrue(result["shared_file_retained"])
        self.assertTrue(self.path.exists())

    def test_active_install_blocks_before_any_change(self):
        self.mocks[3].return_value = True
        with self.assertRaises(StorageError) as caught:
            packages.delete_package("tenant", "app")
        self.assertEqual(caught.exception.code, "package_in_use")
        self.mocks[-2].assert_not_called()
        self.mocks[-1].assert_not_called()
        self.assertTrue(self.path.exists())

    def test_cleanup_failure_keeps_retryable_entry(self):
        with patch.object(Path, "unlink", side_effect=PermissionError("file busy")):
            with self.assertRaises(StorageError) as caught:
                packages.delete_package("tenant", "app")
        self.assertEqual(caught.exception.code, "package_cleanup_failed")
        self.assertTrue(self.path.exists())
        self.mocks[-2].assert_called_once()
        self.mocks[-1].assert_not_called()
        self.app["deletion_requested_at"] = "pending"
        result = packages.delete_package("tenant", "app")
        self.assertGreater(result["freed_bytes"], 0)
        self.assertFalse(self.path.exists())

    def test_missing_file_still_cleans_metadata(self):
        self.path.unlink()
        result = packages.delete_package("tenant", "app")
        self.assertEqual(result["freed_bytes"], 0)
        self.mocks[-1].assert_called_once()

    def test_other_tenant_and_global_package_cannot_be_removed(self):
        for owner in ("other-tenant", None):
            self.app["company_id"] = owner
            with self.assertRaises(StorageError) as caught:
                packages.delete_package("tenant", "app")
            self.assertEqual(caught.exception.status, 404)
            self.assertTrue(self.path.exists())
        self.mocks[-2].assert_not_called()

    def test_non_package_or_other_tenant_path_is_rejected(self):
        for relative in ("../outside", "branding/tenant/image.png", "apps/other/aa/" + "a" * 64 + ".msi"):
            self.app["file_path"] = relative
            with self.assertRaises(StorageError):
                packages.delete_package("tenant", "app")
        self.mocks[-2].assert_not_called()
        self.assertTrue(self.path.exists())

    def test_legacy_layout_can_be_reclaimed(self):
        self.app["file_path"] = f"apps/aa/{'a' * 64}.msi"
        legacy = self.root / self.app["file_path"]
        legacy.parent.mkdir(parents=True)
        legacy.write_bytes(b"legacy")
        result = packages.delete_package("tenant", "app")
        self.assertEqual(result["freed_bytes"], 6)
        self.assertFalse(legacy.exists())
        self.assertTrue(self.path.exists())


class PackageInstallTests(unittest.TestCase):
    @patch.object(packages, "admission", return_value=nullcontext())
    @patch.object(db, "get_app", return_value=None)
    def test_missing_package_cannot_be_queued_after_deletion(self, get_app, admission):
        with self.assertRaises(StorageError):
            with packages.installation("tenant", {"app_url": "https://warden/api/agent/apps/app/download"}):
                self.fail("Deleted package was queued")

    @patch.object(packages, "admission", return_value=nullcontext())
    @patch.object(db, "get_app", return_value={"company_id": "other"})
    def test_cross_tenant_package_cannot_be_queued(self, get_app, admission):
        with self.assertRaises(StorageError):
            with packages.installation("tenant", {"app_id": "app"}):
                self.fail("Other tenant package was queued")

    def test_actual_download_url_wins_over_conflicting_id(self):
        self.assertEqual(packages.package_id({"app_id": "wrong", "app_url": "https://warden/api/agent/apps/actual/download"}), "actual")

    @patch.object(packages, "admission")
    def test_external_installer_has_no_library_dependency(self, admission):
        with packages.installation("tenant", {"app_url": "https://vendor/package.msi"}):
            pass
        admission.assert_not_called()


class PackageReferenceTests(unittest.TestCase):
    @patch.object(db, "decrypt_field", side_effect=lambda company, payload, domain: payload)
    @patch.object(db, "get_company_by_id", return_value={"id": "tenant"})
    @patch.object(db, "_get")
    def test_references_beyond_first_page_are_checked(self, get, company, decrypt):
        get.side_effect = [[{"id": str(i), "payload": {"app_id": "unrelated"}} for i in range(500)],
                           [{"id": "last", "payload": {"app_id": "app"}}]]
        self.assertTrue(db.package_in_use("tenant", "app"))
        self.assertIn("offset=500", get.call_args.args[0])

    @patch.object(db, "_get", side_effect=[[], [], [{"id": "schedule", "payload": {"app_id": "app"}}]])
    def test_enabled_schedule_blocks_deletion(self, get):
        self.assertTrue(db.package_in_use("tenant", "app"))
        self.assertIn("enabled=eq.true", get.call_args.args[0])

    @patch.object(db, "decrypt_field", return_value={"app_id": "app"})
    @patch.object(db, "get_company_by_id", return_value={"id": "tenant"})
    @patch.object(db, "_get", return_value=[{"id": "job", "payload": "encrypted"}])
    def test_encrypted_active_reference_blocks_deletion(self, get, company, decrypt):
        self.assertTrue(db.package_in_use("tenant", "app"))
        self.assertEqual(decrypt.call_args.args[2], "job.payload")

    @patch.object(db, "_get", return_value=[{"id": "job", "payload": None}])
    def test_unreadable_active_reference_fails_closed(self, get):
        self.assertTrue(db.package_in_use("tenant", "app"))

    @patch.object(db, "_get", return_value=[])
    def test_only_terminal_jobs_allow_deletion(self, get):
        self.assertFalse(db.package_in_use("tenant", "app"))
        self.assertIn("status=in.(pending,approved,running)", get.call_args_list[0].args[0])
