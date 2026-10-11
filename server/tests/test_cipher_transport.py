"""Encrypted interface boundaries, exact values and failure behavior."""
import json
import os
import pathlib
import sys
import runpy
import unittest
from unittest import mock
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from database import cipher_transport, transport


class CipherTransportTests(unittest.TestCase):
    def test_multichunk_utf8_identity_binding_and_no_clear_wire(self):
        sealed = {}
        def custody(operation, args):
            context = (args["record_id"], args["purpose"])
            if operation.endswith("encrypt_platform_field"):
                value = "enc:v1:" + (str(len(sealed)).zfill(48))
                sealed[value] = (context, args["value"])
                return value
            bound, value = sealed[args["value"]]
            if bound != context:
                raise ValueError("authentication failed")
            return value
        text = "Private 🛡" * 200000
        with mock.patch.object(cipher_transport, "call", side_effect=custody):
            encrypted = cipher_transport._seal("row", "database.test", text)
            self.assertNotIn("Private", encrypted)
            self.assertEqual(cipher_transport._unseal("row", "database.test", encrypted), text)
            with self.assertRaises(ValueError):
                cipher_transport._unseal("other", "database.test", encrypted)
            with self.assertRaises(ValueError):
                cipher_transport._unseal("row", "other", encrypted)
        self.assertEqual(len(sealed), 3)

    def test_cipher_configuration_forces_interface_with_no_postgrest_fallback(self):
        with mock.patch.dict(os.environ, {"CIPHER_SOCKET": "/private/cipher.sock"}), mock.patch.object(cipher_transport, "open_request", side_effect=RuntimeError("unavailable")) as request:
            with self.assertRaises(RuntimeError):
                transport._open("companies?select=id", "GET", "endpt")
            request.assert_called_once_with("companies?select=id", "GET", "endpt", None, has_data=False, prefer='return=representation')

    def test_response_preserves_exact_json_numbers_and_rejects_plaintext(self):
        response = cipher_transport.Response(dict(body='[{"n":9007199254740993}]', headers={"Content-Range": "0-0/1"}, status=200))
        self.assertEqual(json.loads(response.read())[0]["n"], 9007199254740993)
        response.close()
        with self.assertRaises(ValueError):
            cipher_transport._unseal("row", "purpose", '{"clear":"value"}')

    def test_ciphertext_mode_refuses_missing_socket_and_does_not_load_legacy_credentials(self):
        with mock.patch.dict(os.environ, {"WARDEN_DATABASE_MODE": "ciphertext", "CIPHER_SOCKET": ""}):
            with self.assertRaises(RuntimeError):
                transport._open("companies", "GET", "endpt")
        with mock.patch.dict(os.environ, {"WARDEN_DATABASE_MODE": "ciphertext", "CIPHER_SOCKET": "/private/db.sock",
                            "CIPHER_TOKEN_FILE": "/private/token", "CIPHER_DATASET": "synthetic-dataset",
                            "SUPABASE_SERVICE_KEY": "must-not-load"}):
            candidate = runpy.run_path(str(pathlib.Path(__file__).resolve().parents[1] / "config.py"))
            self.assertEqual(candidate["SUPABASE_SERVICE_KEY"], "ciphertext-interface")
            self.assertEqual(candidate["SUPABASE_URL"], "http://127.0.0.1:9")


if __name__ == "__main__":
    unittest.main()
