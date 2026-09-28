import io
import pathlib
import tempfile
import unittest
import inspect
from datetime import datetime, timedelta, timezone
from unittest import mock

from werkzeug.datastructures import FileStorage

from routes import endpoints
from routes.enroll import ALLOWED_OPERATIONS
from services.experience_assets import cleanup_expired, is_available


class DeviceExperienceTests(unittest.TestCase):
    def test_operation_is_available_to_signed_agent_jobs(self):
        self.assertIn("APPLY_DEVICE_EXPERIENCE", ALLOWED_OPERATIONS)
        self.assertIn("APPLY_DEVICE_EXPERIENCE", endpoints.PLATFORM_DEFAULT_CAPABILITIES["windows"])

    def test_branding_upload_is_content_addressed_and_tenant_scoped(self):
        data = b"\x89PNG\r\n\x1a\n" + b"safe-test-image"
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            endpoints.config, "UPLOAD_DIR", pathlib.Path(directory)
        ):
            asset_id = endpoints._store_experience_image(
                FileStorage(stream=io.BytesIO(data), filename="wallpaper.png"), "tenant-1"
            )
            stored = pathlib.Path(directory) / "branding" / "tenant-1" / f"{asset_id}.png"
            self.assertEqual(stored.read_bytes(), data)

    def test_branding_upload_rejects_extension_spoofing(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            endpoints.config, "UPLOAD_DIR", pathlib.Path(directory)
        ):
            with self.assertRaisesRegex(ValueError, "genuine PNG and JPEG"):
                endpoints._store_experience_image(
                    FileStorage(stream=io.BytesIO(b"not an image"), filename="fake.png"), "tenant-1"
                )

    def test_experience_payload_has_three_day_retention(self):
        payload = endpoints._experience_payload(
            {"announcement_title": "Notice", "announcement_message": "Hello"}, {}, "tenant-1"
        )
        self.assertEqual(payload["deployment_retention_hours"], 72)

    def test_experience_routes_report_storage_failures_as_json(self):
        single_source = inspect.getsource(endpoints.apply_endpoint_experience)
        bulk_source = inspect.getsource(endpoints.apply_bulk_endpoint_experience)
        for source in (single_source, bulk_source):
            self.assertIn("except OSError", source)
            self.assertIn("Image storage is temporarily unavailable", source)

    def test_expired_assets_are_unavailable_and_cleaned(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "branding" / "tenant-1" / (("a" * 64) + ".png")
            path.parent.mkdir(parents=True)
            path.write_bytes(b"image")
            now = datetime.now(timezone.utc)
            old = (now - timedelta(days=3, seconds=1)).timestamp()
            import os
            os.utime(path, (old, old))
            self.assertFalse(is_available(path, now=now))
            self.assertEqual(cleanup_expired(pathlib.Path(directory), now=now), 1)
            self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
