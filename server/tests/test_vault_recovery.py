import base64
import os
import pathlib
import sys
import unittest
from unittest.mock import patch

from flask import Flask, g

SERVER = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER))
os.environ["WERKZEUG_RUN_MAIN"] = "true"

from middleware.auth import company_required, login_required
from middleware.csrf import csrf_protect, get_csrf_token
from routes.settings import bp
from services import tenant_crypto
from services.vault_access import locked_vault_response


class VaultRecoveryTests(unittest.TestCase):
    def setUp(self):
        tenant_crypto._dek_cache.clear()
        self.passphrase = "test-only-vault-passphrase"
        self.company = {"id": "vault-test", **tenant_crypto.provision_byok("vault-test", self.passphrase)}
        self.ciphertext = tenant_crypto.encrypt_value(
            self.company["id"], "byok", self.company["wrapped_dek"], "original data")
        tenant_crypto.lock_company(self.company["id"])
        self.admin = {"id": "admin-test", "role": "company_admin", "company_id": "vault-test"}
        self.app = Flask(__name__, template_folder=str(SERVER / "templates"))
        self.app.secret_key = "test-only-session-key"
        self.app.register_blueprint(bp)
        self.app.register_error_handler(tenant_crypto.VaultLocked, locked_vault_response)
        self.app.add_url_rule("/login", "auth.login", lambda: "login")
        self.app.add_url_rule("/logout", "auth.logout", lambda: "logout", methods=["POST"])

        @self.app.before_request
        def context():
            csrf_protect()
            g.admin, g.company, g.is_superadmin = self.admin, self.company, False

        @self.app.context_processor
        def globals():
            return {"csrf_token": get_csrf_token, "asset_v": "test"}

        @self.app.route("/dashboard", endpoint="dashboard.index")
        @login_required
        @company_required
        def dashboard():
            return "protected dashboard"

        @self.app.route("/api/test-protected", methods=["GET", "POST"])
        @login_required
        @company_required
        def protected_api():
            return {"ok": True}

        @self.app.route("/api/test-uncaught")
        def uncaught():
            raise tenant_crypto.VaultLocked("Do not expose tenant identifiers")

        self.client = self.app.test_client()
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "test-csrf"
        self.audit = patch("db.audit").start()
        self.rate = patch("middleware.security.check_rate_limit", return_value=True).start()
        self.endpoints = patch("db.get_endpoints", side_effect=AssertionError("Encrypted endpoints must not be read")).start()
        self.addCleanup(patch.stopall)
        self.addCleanup(tenant_crypto._dek_cache.clear)

    def post(self, path="/settings/security/vault", **data):
        return self.client.post(path, data={"csrf_token": "test-csrf", **data})

    def test_locked_dashboard_and_security_redirect_to_recovery(self):
        for path in ("/dashboard", "/settings/security"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.headers["Location"], "/settings/security/vault")
            self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.endpoints.assert_not_called()

    def test_recovery_renders_without_encrypted_records(self):
        response = self.client.get("/settings/security/vault")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Unlock vault", response.data)
        self.assertIn(b"csrf_token", response.data)
        self.assertNotIn(b"test-only-vault-passphrase", response.data)
        self.endpoints.assert_not_called()

    def test_json_and_agent_errors_are_423_not_500(self):
        for path in ("/dashboard", "/api/test-protected", "/api/test-uncaught"):
            response = self.client.get(path, headers={"Accept": "application/json"})
            self.assertEqual(response.status_code, 423)
            self.assertEqual(response.json["error"], "tenant_vault_locked")
            self.assertEqual(response.json["unlock_url"], "/settings/security/vault")
            self.assertNotIn("identifiers", str(response.json))

    def test_htmx_redirect_does_not_swap_unlock_document_into_sidebar(self):
        response = self.client.get("/dashboard", headers={"HX-Request": "true"})
        self.assertEqual(response.status_code, 423)
        self.assertEqual(response.headers["HX-Redirect"], "/settings/security/vault")

    def test_protected_mutation_is_not_replayed(self):
        response = self.post("/api/test-protected")
        self.assertEqual(response.status_code, 423)
        self.assertEqual(response.json["error"], "tenant_vault_locked")

    def test_wrong_passphrase_stays_locked_and_is_not_reflected(self):
        response = self.post(passphrase="wrong-secret")
        self.assertEqual(response.status_code, 401)
        self.assertIn(b"Incorrect vault passphrase", response.data)
        self.assertNotIn(b"wrong-secret", response.data)
        self.assertFalse(tenant_crypto.is_unlocked("vault-test"))
        self.audit.assert_not_called()

    def test_unlock_restores_existing_data_and_restart_locks_again(self):
        response = self.post(passphrase=self.passphrase)
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["Location"], "/dashboard")
        self.assertEqual(self.client.get("/dashboard").status_code, 200)
        self.assertEqual(tenant_crypto.decrypt_value("vault-test", "byok",
            self.company["wrapped_dek"], self.ciphertext), "original data")
        self.audit.assert_called_once_with("vault-test", "admin-test", "tenant_vault_unlocked")
        tenant_crypto._dek_cache.clear()  # Simulate the fresh process after restart.
        self.assertEqual(self.client.get("/dashboard").status_code, 302)

    def test_technician_sees_admin_guidance_but_cannot_unlock(self):
        self.admin["role"] = "technician"
        response = self.client.get("/settings/security/vault")
        self.assertIn(b"Ask your organization administrator", response.data)
        self.assertNotIn(b'name="passphrase"', response.data)
        self.assertEqual(self.post(passphrase=self.passphrase).status_code, 403)
        self.assertFalse(tenant_crypto.is_unlocked("vault-test"))

    def test_unlock_still_requires_csrf(self):
        response = self.client.post("/settings/security/vault", data={"passphrase": self.passphrase})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(tenant_crypto.is_unlocked("vault-test"))

    def test_unlock_attempts_are_rate_limited(self):
        self.rate.return_value = False
        self.assertEqual(self.post(passphrase=self.passphrase).status_code, 429)
        self.assertFalse(tenant_crypto.is_unlocked("vault-test"))

    def test_legacy_json_unlock_endpoint_remains_usable_when_locked(self):
        response = self.post("/settings/security/vault/unlock", passphrase=self.passphrase)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {"ok": True})
        self.assertTrue(tenant_crypto.is_unlocked("vault-test"))

    def test_managed_mode_does_not_prompt_and_anonymous_user_must_login(self):
        self.company["encryption_mode"] = "managed"
        self.assertEqual(self.client.get("/dashboard").status_code, 200)
        self.admin = None
        response = self.client.get("/settings/security/vault")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

    def test_application_registers_global_vault_handler(self):
        import app as application
        self.assertIn(tenant_crypto.VaultLocked, application.app.error_handler_spec[None][None])

    def test_managed_to_byok_rewrap_keeps_existing_data_key(self):
        with patch("config.TENANT_MASTER_KEK_B64", base64.b64encode(os.urandom(32)).decode()):
            managed = tenant_crypto.provision_managed("switch-test")
            encrypted = tenant_crypto.encrypt_value("switch-test", "managed",
                managed["wrapped_dek"], "data written before switching")
            byok = tenant_crypto.rewrap_to_byok("switch-test", "managed",
                managed["wrapped_dek"], self.passphrase)
            self.assertTrue(tenant_crypto.is_unlocked("switch-test"))
            self.assertEqual(tenant_crypto.decrypt_value("switch-test", "byok",
                byok["wrapped_dek"], encrypted), "data written before switching")
            tenant_crypto._dek_cache.clear()
            with self.assertRaises(tenant_crypto.VaultLocked):
                tenant_crypto.decrypt_value("switch-test", "byok", byok["wrapped_dek"], encrypted)
            tenant_crypto.unlock_byok("switch-test", self.passphrase,
                byok["wrapped_dek"], byok["byok_salt"])
            self.assertEqual(tenant_crypto.decrypt_value("switch-test", "byok",
                byok["wrapped_dek"], encrypted), "data written before switching")
