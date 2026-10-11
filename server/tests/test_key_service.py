"""Key custody boundaries, compatibility, and fail-closed client behavior."""
import base64
import importlib.util
import json
import os
import pathlib
import sys
import unittest
from unittest import mock

SERVER_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

import config
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from services import key_service_client, platform_secrets, tenant_crypto

spec = importlib.util.spec_from_file_location(
    "warden_key_service_app", SERVER_DIR.parent / "key-service" / "app.py")
service = importlib.util.module_from_spec(spec)
spec.loader.exec_module(service)


class KeyServiceTests(unittest.TestCase):
    def setUp(self):
        self.master = b"k" * 32
        self.token = "a" * 64
        self.patches = [
            mock.patch.object(config, "TENANT_MASTER_KEK_B64", base64.b64encode(self.master).decode()),
            mock.patch.object(config, "CLIENT_TOKEN", self.token, create=True),
            mock.patch.object(config, "KEY_SERVICE_SOCKET", ""),
        ]
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)
        tenant_crypto._dek_cache.clear()
        self.addCleanup(tenant_crypto._dek_cache.clear)
        self.client = service.app.test_client()

    def operate(self, name, **arguments):
        return self.client.post("/v1/operate", json={
            "operation": name, "arguments": arguments,
        }, headers={"Authorization": "Bearer " + self.token})

    def company(self):
        response = self.operate("tenant.provision_managed", company_id="tenant-a")
        self.assertEqual(response.status_code, 200)
        fields = response.json["result"]
        self.assertEqual(set(fields), {"encryption_mode", "wrapped_dek", "byok_salt"})
        return dict(company_id="tenant-a", mode="managed", wrapped_dek=fields["wrapped_dek"])

    def test_credentials_are_required_before_any_key_operation(self):
        response = self.client.post("/v1/operate", json={
            "operation": "tenant.provision_managed", "arguments": {"company_id": "tenant-a"},
        })
        self.assertEqual(response.status_code, 401)
        self.assertFalse(tenant_crypto._dek_cache)

    def test_key_export_and_arbitrary_function_calls_are_rejected(self):
        for name in ("tenant._master_kek", "tenant._get_dek", "platform._key", "eval"):
            with self.subTest(name=name):
                self.assertEqual(self.operate(name).status_code, 400)

    def test_database_batch_boundaries_and_record_authentication(self):
        records = [dict(record_id=f"record-{index}", purpose="database.row.v1:test", value=f"private-{index}") for index in range(4)]
        encrypted = self.operate("platform.encrypt_database_batch", records=records)
        self.assertEqual(encrypted.status_code, 200)
        values = encrypted.json["result"]
        self.assertTrue(all(value.startswith("enc:v1:") for value in values))
        sealed = [dict(record, value=value) for record, value in zip(records, values)]
        self.assertEqual(self.operate("platform.decrypt_database_batch", records=sealed).json["result"], [r["value"] for r in records])
        sealed[0]["record_id"] = "other"
        self.assertEqual(self.operate("platform.decrypt_database_batch", records=sealed).status_code, 400)
        for invalid in ([], records * 33, [dict(records[0], purpose="tenant.data")], [dict(records[0], unexpected=True)]):
            self.assertEqual(self.operate("platform.encrypt_database_batch", records=invalid).status_code, 400)

    def test_roundtrip_is_authenticated_and_bound_to_tenant_and_purpose(self):
        company = self.company()
        response = self.operate("tenant.encrypt_value", **company,
                                plaintext={"private": "value"}, purpose="job.payload")
        encrypted = response.json["result"]
        self.assertTrue(encrypted.startswith("v2:"))
        self.assertNotIn("private", encrypted)
        response = self.operate("tenant.decrypt_value", **company,
                                ciphertext_b64=encrypted, purpose="job.payload")
        self.assertEqual(response.json["result"], {"private": "value"})
        self.assertEqual(self.operate("tenant.decrypt_value", **company,
                         ciphertext_b64=encrypted, purpose="job.error").status_code, 400)
        other = dict(company, company_id="tenant-b")
        self.assertEqual(self.operate("tenant.decrypt_value", **other,
                         ciphertext_b64=encrypted, purpose="job.payload").status_code, 400)

    def test_cached_dek_cannot_bypass_changed_wrapping_material_or_mode(self):
        company = self.company()
        invalid = dict(company, wrapped_dek="v2:" + base64.b64encode(b"x" * 60).decode())
        self.assertEqual(self.operate("tenant.encrypt_value", **invalid,
                                     plaintext="secret").status_code, 400)
        changed_mode = dict(company, mode="byok")
        self.assertEqual(self.operate("tenant.encrypt_value", **changed_mode,
                                     plaintext="secret").status_code, 423)

    def test_existing_legacy_wrapped_keys_and_ciphertext_stay_readable(self):
        dek = b"d" * 32
        nonce = os.urandom(12)
        wrapped = base64.b64encode(nonce + AESGCM(self.master).encrypt(nonce, dek, None)).decode()
        nonce = os.urandom(12)
        encrypted = base64.b64encode(nonce + AESGCM(dek).encrypt(
            nonce, json.dumps({"old": "record"}).encode(), None)).decode()
        response = self.operate("tenant.decrypt_value", company_id="legacy-tenant",
                                mode="managed", wrapped_dek=wrapped, ciphertext_b64=encrypted)
        self.assertEqual(response.json["result"], {"old": "record"})

    def test_byok_rewrap_preserves_data_and_lock_is_enforced(self):
        company = self.company()
        encrypted = self.operate("tenant.encrypt_value", **company, plaintext="retained").json["result"]
        passphrase = "test passphrase longer than twelve"
        fields = self.operate("tenant.rewrap_to_byok", company_id="tenant-a",
                              current_mode="managed", current_wrapped_dek=company["wrapped_dek"],
                              passphrase=passphrase).json["result"]
        byok = dict(company, mode="byok", wrapped_dek=fields["wrapped_dek"])
        self.assertEqual(self.operate("tenant.decrypt_value", **byok,
                         ciphertext_b64=encrypted).json["result"], "retained")

        self.operate("tenant.lock_company", company_id="tenant-a")
        self.assertEqual(self.operate("tenant.decrypt_value", **byok,
                         ciphertext_b64=encrypted).status_code, 423)
        self.assertEqual(self.operate("tenant.unlock_byok", company_id="tenant-a",
                         passphrase="incorrect", wrapped_dek=fields["wrapped_dek"],
                         byok_salt_b64=fields["byok_salt"]).status_code, 400)
        self.assertEqual(self.operate("tenant.unlock_byok", company_id="tenant-a",
                         passphrase=passphrase, wrapped_dek=fields["wrapped_dek"],
                         byok_salt_b64=fields["byok_salt"]).status_code, 200)
        self.assertEqual(self.operate("tenant.decrypt_value", **byok,
                         ciphertext_b64=encrypted).json["result"], "retained")

    def test_server_chooses_fixed_byok_expiry_and_enforces_it_for_all_key_uses(self):
        for choice, days in ((0, 7), (23, 30)):
            with self.subTest(days=days), mock.patch.object(tenant_crypto.secrets, "randbelow", return_value=choice) as random, \
                 mock.patch.object(tenant_crypto.time, "monotonic", return_value=100) as monotonic, \
                 mock.patch.object(tenant_crypto.time, "time", return_value=1000) as wall:
                company = self.company()
                fields = self.operate("tenant.rewrap_to_byok", company_id="tenant-a", current_mode="managed",
                    current_wrapped_dek=company["wrapped_dek"], passphrase="synthetic-server-expiry-phrase").json["result"]
                random.assert_called_once_with(24)
                byok = dict(company, mode="byok", wrapped_dek=fields["wrapped_dek"])
                expiry = 1000 + days * 86400
                response = self.operate("tenant.vault_status", company_id="tenant-a")
                self.assertEqual(response.json["result"], {"unlocked": True, "expires_at": expiry})
                self.assertEqual(response.headers["Cache-Control"], "no-store")
                encrypted = self.operate("tenant.encrypt_value", **byok, plaintext="expiry-fixture").json["result"]
                monotonic.return_value = 100 + days * 86400 - 1
                wall.return_value = expiry - 1
                self.assertEqual(self.operate("tenant.decrypt_value", **byok, ciphertext_b64=encrypted).json["result"], "expiry-fixture")
                self.assertEqual(self.operate("tenant.vault_status", company_id="tenant-a").json["result"]["expires_at"], expiry)
                # Wall clock rollback cannot defeat the monotonic deadline.
                wall.return_value = 1000
                monotonic.return_value += 1
                for operation, extra in (("encrypt_value", {"plaintext": "secret"}),
                                         ("decrypt_value", {"ciphertext_b64": encrypted}),
                                         ("blind_index_value", {"value": "secret", "purpose": "test"})):
                    self.assertEqual(self.operate("tenant." + operation, **byok, **extra).status_code, 423)
                self.assertEqual(self.operate("tenant.vault_status", company_id="tenant-a").json["result"],
                                 {"unlocked": False, "expires_at": None})
                self.assertNotIn("tenant-a", tenant_crypto._dek_cache)

    def test_clients_cannot_override_expiry_and_lock_removes_all_state(self):
        fields = self.operate("tenant.provision_byok", company_id="tenant-a", passphrase="synthetic-lock-state-phrase").json["result"]
        self.assertEqual(self.operate("tenant.unlock_byok", company_id="tenant-a",
            passphrase="synthetic-lock-state-phrase", wrapped_dek=fields["wrapped_dek"],
            byok_salt_b64=fields["byok_salt"], expires_at=9999999999).status_code, 400)
        self.assertEqual(self.operate("tenant.lock_company", company_id="tenant-a").status_code, 200)
        self.assertEqual(self.operate("tenant.vault_status", company_id="tenant-a").json["result"],
                         {"unlocked": False, "expires_at": None})
        self.assertNotIn("tenant-a", tenant_crypto._dek_cache_context)
        self.assertNotIn("tenant-a", tenant_crypto._dek_cache_expiry)

    def test_platform_mfa_and_backup_codes_are_compatible(self):
        old = platform_secrets.encrypt_mfa_secret("admin-a", "test-mfa")
        response = self.operate("platform.decrypt_mfa_secret", admin_id="admin-a", value=old)
        self.assertEqual(response.json["result"], "test-mfa")
        self.assertEqual(self.operate("platform.decrypt_mfa_secret", admin_id="admin-b",
                                     value=old).status_code, 400)
        stored = platform_secrets.hash_backup_code("backup-test")
        self.assertTrue(self.operate("platform.backup_code_matches", candidate="backup-test",
                                    stored=stored).json["result"])
        self.assertFalse(self.operate("platform.backup_code_matches", candidate="wrong",
                                     stored=stored).json["result"])

    def test_blind_indexes_preserve_lookup_tokens_and_purpose_isolation(self):
        company = self.company()
        expected = tenant_crypto.blind_index_value(**company, value=" HOST-A ", purpose="endpoint.hostname")
        result = self.operate("tenant.blind_index_value", **company,
                              value="host-a", purpose="endpoint.hostname").json["result"]
        self.assertEqual(result, expected)
        other = self.operate("tenant.blind_index_value", **company,
                             value="host-a", purpose="endpoint.asset_tag").json["result"]
        self.assertNotEqual(result, other)

    def test_errors_and_audit_do_not_disclose_supplied_secrets(self):
        marker = "private-marker-never-log-this"
        with self.assertLogs("key_service.audit", level="WARNING") as logs:
            response = self.operate("tenant.unlock_byok", company_id="tenant-a",
                                    passphrase=marker, wrapped_dek=marker, byok_salt_b64=marker)
        self.assertEqual(response.status_code, 400)
        self.assertNotIn(marker, response.get_data(as_text=True))
        self.assertNotIn(marker, " ".join(logs.output))

    def test_invalid_schema_extra_arguments_and_large_bodies_are_rejected(self):
        self.assertEqual(self.operate("tenant.provision_managed", company_id="tenant-a",
                                     master_key="never-accepted").status_code, 400)
        with mock.patch.dict(service.app.config, MAX_CONTENT_LENGTH=64):
            response = self.client.post("/v1/operate", data="x" * 65,
                                       content_type="application/json",
                                       headers={"Authorization": "Bearer " + self.token})
        self.assertEqual(response.status_code, 400)


class KeyServiceClientTests(unittest.TestCase):
    def test_delegation_never_creates_a_local_dek(self):
        with mock.patch.object(config, "KEY_SERVICE_SOCKET", "/test/service.sock"), \
             mock.patch.object(key_service_client, "call", return_value="ciphertext") as call, \
             mock.patch.object(tenant_crypto, "_get_dek", side_effect=AssertionError("local key access")):
            self.assertEqual(tenant_crypto.encrypt_value("tenant-a", "managed", "wrapped",
                             {"test": "value"}, "job.payload"), "ciphertext")
        self.assertEqual(call.call_args.args[0], "tenant.encrypt_value")
        self.assertEqual(call.call_args.args[1]["purpose"], "job.payload")

    def test_unavailable_service_never_falls_back_to_local_master_key(self):
        with mock.patch.object(config, "KEY_SERVICE_SOCKET", "/test/service.sock"), \
             mock.patch.object(key_service_client, "call", side_effect=key_service_client.KeyServiceUnavailable()), \
             mock.patch.object(tenant_crypto, "_master_kek", side_effect=AssertionError("local key access")):
            with self.assertRaises(key_service_client.KeyServiceUnavailable):
                tenant_crypto.provision_managed("tenant-a")

    def test_transport_authenticates_and_does_not_retry_or_leak_token(self):
        connection = mock.Mock()
        connection.getresponse.side_effect = OSError("no service")
        token = "t" * 64
        with mock.patch.object(config, "KEY_SERVICE_TOKEN_FILE", "/test/token"), \
             mock.patch.object(pathlib.Path, "read_text", return_value=token), \
             mock.patch.object(key_service_client, "UnixConnection", return_value=connection) as factory:
            with self.assertRaises(key_service_client.KeyServiceUnavailable) as raised:
                key_service_client.call("tenant.lock_company", {"company_id": "tenant-a"})
        self.assertNotIn(token, str(raised.exception))
        self.assertEqual(factory.call_count, 1)
        self.assertEqual(connection.request.call_args.args[3]["Authorization"], "Bearer " + token)
        connection.close.assert_called_once()

    def test_locked_remote_vault_preserves_application_error_type(self):
        connection = mock.Mock()
        response = connection.getresponse.return_value
        response.status = 423
        response.read.return_value = b'{"error":"vault_locked"}'
        with mock.patch.object(config, "KEY_SERVICE_TOKEN_FILE", "/test/token"), \
             mock.patch.object(pathlib.Path, "read_text", return_value="t" * 64), \
             mock.patch.object(key_service_client, "UnixConnection", return_value=connection):
            with self.assertRaises(tenant_crypto.VaultLocked):
                key_service_client.call("tenant.encrypt_value", {})


if __name__ == "__main__":
    unittest.main()
