import base64
import os
import pathlib
import sys
import unittest
from unittest import mock

SERVER_DIR = pathlib.Path(__file__).resolve().parents[1]
ROOT_DIR = SERVER_DIR.parent
for path in (SERVER_DIR, ROOT_DIR / "tools"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import config
import db
import encrypt_endpoint_private_data as migration
from services import tenant_crypto


class EndpointPrivateDataTests(unittest.TestCase):
    def setUp(self):
        tenant_crypto._dek_cache.clear()
        self.patch = mock.patch.object(
            config, "TENANT_MASTER_KEK_B64",
            base64.b64encode(os.urandom(32)).decode(),
        )
        self.patch.start()
        provisioned = tenant_crypto.provision_managed("tenant-a")
        self.company = {
            "id": "tenant-a",
            "encryption_mode": "managed",
            **provisioned,
        }

    def tearDown(self):
        self.patch.stop()
        tenant_crypto._dek_cache.clear()

    def test_endpoint_private_fields_round_trip_and_scrub_json(self):
        plaintext = {
            "hostname": "PC-ACCOUNTING-01",
            "hardware_id": "hardware-secret",
            "installation_id": "installation-secret",
            "last_seen_ip": "203.0.113.10",
            "local_ip": "10.0.0.22",
            "interactive_user": "alice",
            "notes": "Executive laptop",
            "tags": ["finance", "priority"],
            "device_identity": {"serial_number": "SERIAL-SECRET"},
            "topology_telemetry": {"neighbors": [{"ip": "10.0.0.1"}]},
        }
        stored = db._encrypt_endpoint_fields(self.company, plaintext)
        self.assertTrue(stored["hostname"].startswith("v2:"))
        self.assertNotIn("PC-ACCOUNTING-01", str(stored))
        self.assertEqual(stored["tags"], [])
        self.assertEqual(stored["device_identity"], {})
        self.assertRegex(stored["hardware_id_hash"], r"^[0-9a-f]{64}$")

        hydrated = db._decrypt_endpoint(
            {"id": "endpoint-a", "company_id": "tenant-a", **stored},
            self.company,
        )
        for key, value in plaintext.items():
            self.assertEqual(hydrated[key], value)

    def test_blind_indexes_are_stable_and_organization_field_scoped(self):
        first = db.blind_index(
            self.company, "Device-ABC", "endpoint.hardware-id",
        )
        self.assertEqual(
            first,
            db.blind_index(
                self.company, " device-abc ", "endpoint.hardware-id",
            ),
        )
        self.assertNotEqual(
            first,
            db.blind_index(
                self.company, "Device-ABC", "endpoint.installation-id",
            ),
        )
        other = {"id": "tenant-b", **tenant_crypto.provision_managed("tenant-b")}
        self.assertNotEqual(
            first,
            db.blind_index(other, "Device-ABC", "endpoint.hardware-id"),
        )

    def test_migration_patch_is_restartable(self):
        row = {
            "hostname": "PC-01",
            "hardware_id": "HW-01",
            "installation_id": "INSTALL-01",
            "device_identity": {"serial_number": "SERIAL-01"},
            "topology_telemetry": {"neighbors": []},
            "capability_details": {"remote": True},
            "tags": ["office"],
            "asset_metadata": {"cost_center": "finance"},
        }
        first = migration.endpoint_patch(self.company, row)
        migrated = {**row, **first}
        second = migration.endpoint_patch(self.company, migrated)
        self.assertNotIn("hostname", second)
        self.assertEqual(
            first["hardware_id_hash"], second["hardware_id_hash"],
        )
        self.assertEqual(second["private_data_encryption_version"], 1)

    def test_hardware_lookup_uses_blind_index_not_plaintext(self):
        with (
            mock.patch.object(
                db, "get_company_by_id", return_value=self.company,
            ),
            mock.patch.object(db, "_get", return_value=[]) as get,
        ):
            db.get_endpoint_by_hardware_id("tenant-a", "VISIBLE-HARDWARE")
        query = get.call_args.args[0]
        self.assertIn("hardware_id_hash=eq.", query)
        self.assertNotIn("VISIBLE-HARDWARE", query)

    def test_legacy_plaintext_fields_remain_readable_but_v2_corruption_fails(self):
        self.assertEqual(
            db.decrypt_field(self.company, "legacy job error", "job.error-message"),
            "legacy job error",
        )
        legacy_payload = {"reason": "created before encryption"}
        self.assertIs(
            db.decrypt_field(self.company, legacy_payload, "job.payload"),
            legacy_payload,
        )
        with self.assertRaises(Exception):
            db.decrypt_field(self.company, "v2:not-valid", "job.error-message")


if __name__ == "__main__":
    unittest.main()
