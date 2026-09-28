import io
import json
import pathlib
import sys
import unittest
import urllib.error
from unittest import mock


SERVER_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

import db
from services import microsoft_graph


class FakeResponse:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return self.payload


class MicrosoftGraphTests(unittest.TestCase):
    @mock.patch.object(microsoft_graph.urllib.request, "urlopen")
    def test_connection_verifies_credentials_organization_and_autopilot(self, urlopen):
        urlopen.side_effect = [
            FakeResponse({"access_token": "temporary-access-token"}),
            FakeResponse({"value": [{
                "id": "11111111-1111-1111-1111-111111111111",
                "displayName": "Example Ltd",
                "verifiedDomains": [{"name": "example.com", "isDefault": True}],
            }]}),
            FakeResponse({"value": [{"id": "device-1", "serialNumber": "ABC"}]}),
        ]
        result = microsoft_graph.test_connection({
            "tenant_id": "11111111-1111-1111-1111-111111111111",
            "client_id": "22222222-2222-2222-2222-222222222222",
            "client_secret": "very-secret-value",
        })
        self.assertEqual(result["organization_name"], "Example Ltd")
        self.assertEqual(result["default_domain"], "example.com")
        self.assertTrue(result["autopilot_access"])
        self.assertNotIn("temporary-access-token", json.dumps(result))
        self.assertIn("windowsAutopilotDeviceIdentities", urlopen.call_args_list[2].args[0].full_url)

    @mock.patch.object(microsoft_graph.urllib.request, "urlopen")
    def test_provider_error_never_echoes_client_secret(self, urlopen):
        secret = "secret-that-must-not-leak"
        body = io.BytesIO(json.dumps({
            "error": "invalid_client",
            "error_description": f"Bad credential {secret}",
        }).encode("utf-8"))
        urlopen.side_effect = urllib.error.HTTPError(
            "https://login.microsoftonline.com", 401, "Unauthorized", {}, body,
        )
        with self.assertRaises(microsoft_graph.MicrosoftGraphError) as caught:
            microsoft_graph.acquire_access_token("tenant", "client", secret)
        self.assertNotIn(secret, str(caught.exception))
        self.assertIn("[redacted]", str(caught.exception))

    @mock.patch.object(microsoft_graph.urllib.request, "urlopen")
    def test_autopilot_inventory_follows_pagination_and_normalizes_ids(self, urlopen):
        urlopen.side_effect = [
            FakeResponse({"access_token": "temporary"}),
            FakeResponse({
                "value": [{"id": "ap-1", "serialNumber": "SERIAL-1"}],
                "@odata.nextLink": "https://graph.microsoft.com/v1.0/next-page",
            }),
            FakeResponse({"value": [{
                "id": "ap-2", "serialNumber": "SERIAL-2",
                "azureActiveDirectoryDeviceId": "entra-2",
            }]}),
        ]
        devices = microsoft_graph.list_autopilot_devices({
            "tenant_id": "tenant", "client_id": "client", "client_secret": "secret",
        })
        self.assertEqual([d["provider_device_id"] for d in devices], ["ap-1", "ap-2"])
        self.assertEqual(devices[1]["entra_device_id"], "entra-2")

    @mock.patch.object(db, "_post")
    @mock.patch.object(db, "get_tenant_integration")
    @mock.patch.object(db, "encrypt_field")
    def test_new_integration_is_encrypted_before_database_write(self, encrypt, get_existing, post):
        encrypt.return_value = "ciphertext"
        get_existing.return_value = None
        post.return_value = [{"id": "integration-1"}]
        company = {"id": "company-1"}
        config = {"client_secret": "plaintext-secret"}
        db.save_tenant_integration(company, "microsoft_entra", config, "admin-1")
        encrypt.assert_called_once_with(company, config, "integration.config")
        stored = post.call_args.args[1]
        self.assertEqual(stored["config_encrypted"], "ciphertext")
        self.assertNotIn("plaintext-secret", json.dumps(stored))


if __name__ == "__main__":
    unittest.main()
