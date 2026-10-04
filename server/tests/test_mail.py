import hashlib
import json
import pathlib
import smtplib
import ssl
import unittest
from unittest import mock
from flask import Flask, g

from services import mail
from routes import mail as routes


def raw(view):
    while hasattr(view, "__wrapped__"):
        view = view.__wrapped__
    return view


class MailTests(unittest.TestCase):
    def setUp(self):
        self.settings = dict(enabled=True, host="smtp.example.com", port=587, mode="starttls",
                             username="user", password="secret", from_email="warden@example.com", from_name="Warden")
        self.admin = dict(id="a1", company_id="c1", email="owner@example.com", is_active=True,
                          role="company_admin", branch_id=None, access_token_version=3, notification_prefs={})
        self.base = mock.patch.object(mail.config, "SERVER_URL", "https://warden.example.com")
        self.base.start()
        self.addCleanup(self.base.stop)

    def test_settings_requires_tls(self):
        with self.assertRaises(ValueError):
            mail.validate_settings(dict(self.settings, mode="plain"))

    def test_google_app_password_display_spaces_normalized_only_for_google(self):
        formatted = "abcd efgh ijkl mnop"
        saved = mail.validate_settings(dict(self.settings, host="smtp.gmail.com", password=formatted))
        self.assertEqual(saved["password"], "abcdefghijklmnop")
        other = mail.validate_settings(dict(self.settings, password=formatted))
        self.assertEqual(other["password"], formatted)

    def test_settings_rejects_header_injection(self):
        for field in ("from_email", "from_name", "username", "host"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                mail.validate_settings(dict(self.settings, **{field: "evil\r\nBcc:x@example.com"}))

    def test_settings_rejects_invalid_ports(self):
        for port in ("x", 0, 65536):
            with self.subTest(port=port), self.assertRaises(ValueError):
                mail.validate_settings(dict(self.settings, port=port))

    def test_password_preserved_only_on_same_host_and_user(self):
        self.assertEqual(mail.validate_settings(dict(self.settings, password=""), self.settings)["password"], "secret")
        with self.assertRaises(ValueError):
            mail.validate_settings(dict(self.settings, host="new.example.com", password=""), self.settings)
        with self.assertRaises(ValueError):
            mail.validate_settings(dict(self.settings, username="new", password=""), self.settings)

    def test_clear_password_supported_for_unauthenticated_relay(self):
        saved = mail.validate_settings(dict(self.settings, username="", password="", clear_password=True), self.settings)
        self.assertEqual(saved["password"], "")

    def test_public_settings_never_returns_password(self):
        public = mail.public_settings(self.settings)
        self.assertTrue(public["password_saved"])
        self.assertNotIn("password", public)

    def test_settings_encrypted_and_scope_bound(self):
        with mock.patch.object(mail.db, "_post") as post, mock.patch.object(mail, "encrypt_platform_field", return_value="cipher") as enc:
            mail.save_settings("c1", "a1", self.settings)
        record = post.call_args.args[1]
        self.assertEqual(record["config_encrypted"], "cipher")
        self.assertNotIn("password", record)
        self.assertEqual(enc.call_args.args[:2], (mail.scope_key("c1"), "smtp.config"))
        self.assertEqual(record["company_id"], "c1" if mail.SCOPE_MODE == "company" else None)

    def test_canonical_url_not_arbitrary_host(self):
        self.assertEqual(mail.base_url(), "https://warden.example.com")
        for url in ("http://public.example.com", "https://user:pass@example.com", "https://example.com?x=1"):
            with self.subTest(url=url), mock.patch.object(mail.config, "SERVER_URL", url), self.assertRaises(ValueError):
                mail.base_url()

    def test_local_development_http_allowed(self):
        with mock.patch.object(mail.config, "SERVER_URL", "http://localhost:5000"):
            self.assertEqual(mail.base_url(), "http://localhost:5000")

    def test_defaults_critical_and_failed_only(self):
        self.assertTrue(mail.allowed(self.admin, "alerts_critical", "c1"))
        self.assertTrue(mail.allowed(self.admin, "jobs_failed", "c1"))
        self.assertFalse(mail.allowed(self.admin, "jobs_completed", "c1"))

    def test_explicit_opt_out_overrides_default(self):
        admin = dict(self.admin, notification_prefs={"email_categories": {"jobs_failed": False}})
        self.assertFalse(mail.allowed(admin, "jobs_failed", "c1"))

    def test_security_not_subject_to_optional_preferences(self):
        admin = dict(self.admin, notification_prefs={"email_categories": {}})
        self.assertTrue(mail.allowed(admin, "security", "c1"))

    def test_recipient_requires_active_same_company(self):
        self.assertFalse(mail.allowed(self.admin, "security", "c2"))
        self.assertFalse(mail.allowed(dict(self.admin, is_active=False), "security", "c1"))

    def test_branch_scope_applies_to_optional_mail(self):
        admin = dict(self.admin, role="branch_admin", branch_id="b1")
        self.assertTrue(mail.allowed(admin, "jobs_failed", "c1", "b1"))
        self.assertFalse(mail.allowed(admin, "jobs_failed", "c1", "b2"))
        self.assertFalse(mail.allowed(admin, "jobs_failed", "c1"))

    def test_approval_mail_restricted_to_approvers(self):
        admin = dict(self.admin, role="technician", notification_prefs={"email_categories": {"approvals": True}})
        self.assertFalse(mail.allowed(admin, "approvals", "c1"))

    def test_starttls_precedes_auth_and_message_has_fallback(self):
        with mock.patch.object(mail.smtplib, "SMTP") as smtp:
            smtp.return_value.__enter__.return_value.send_message.return_value = {}
            mail.send(self.settings, self.admin["email"], "Subject", "Plain body", html="<p>HTML</p>")
        client = smtp.return_value.__enter__.return_value
        names = [call[0] for call in client.method_calls]
        self.assertLess(names.index("starttls"), names.index("login"))
        msg = client.send_message.call_args.args[0]
        self.assertEqual(msg.get_body(preferencelist=("plain",)).get_content().strip(), "Plain body")
        self.assertEqual(msg.get_body(preferencelist=("html",)).get_content().strip(), "<p>HTML</p>")

    def test_failed_tls_never_falls_back_or_authenticates(self):
        with mock.patch.object(mail.smtplib, "SMTP") as smtp:
            client = smtp.return_value.__enter__.return_value
            client.starttls.side_effect = ssl.SSLError("private provider text")
            with self.assertRaises(ssl.SSLError):
                mail.send(self.settings, self.admin["email"], "Subject", "Body")
            client.login.assert_not_called()
            client.send_message.assert_not_called()

    def test_implicit_tls_uses_verified_context(self):
        with mock.patch.object(mail.smtplib, "SMTP_SSL") as smtp:
            smtp.return_value.__enter__.return_value.send_message.return_value = {}
            mail.send(dict(self.settings, mode="tls"), self.admin["email"], "Subject", "Body")
        self.assertEqual(smtp.call_args.kwargs["context"].verify_mode, ssl.CERT_REQUIRED)
        smtp.return_value.__enter__.return_value.starttls.assert_not_called()

    def test_send_rejects_plain_mode_and_subject_injection(self):
        with self.assertRaises(ValueError):
            mail.send(dict(self.settings, mode="plain"), self.admin["email"], "Subject", "Body")
        with self.assertRaises(ValueError):
            mail.send(self.settings, self.admin["email"], "Hi\nBcc: x@example.com", "Body")

    def test_html_templates_escape_content(self):
        html = mail.render_email("<script>bad</script>", "<img src=x>", "jobs_failed")
        self.assertNotIn("<script>", html)
        self.assertNotIn("<img src=x>", html)
        self.assertIn("&lt;img", html)
        self.assertIn("/settings/email-notifications", html)

    def test_welcome_template_contains_no_password(self):
        html = mail.render_email("Welcome to Warden", "Body", "security", "welcome", mail.base_url()+"/login")
        self.assertIn("administrator account is ready", html)
        self.assertIn("Forgot password?", html)
        self.assertNotIn("Manage email notifications", html)

    def test_reset_template_has_expiry_and_preserves_mfa(self):
        html = mail.render_email("Reset", "Body", "security", "password_reset", mail.base_url()+"/auth/reset-password#token=x")
        self.assertIn("30 minutes", html)
        self.assertIn("MFA", html)
        self.assertIn("#token=x", html)

    def test_template_rejects_external_actions(self):
        with self.assertRaises(ValueError):
            mail.render_email("Subject", "Body", "security", action_url="https://attacker.example.com")
        with self.assertRaises(ValueError):
            mail.render_email("Subject", "Body", "security", template="../login")

    def test_queued_body_is_encrypted(self):
        with mock.patch.object(mail, "get_settings", return_value=self.settings), mock.patch.object(mail.db, "_post") as post, \
             mock.patch.object(mail, "encrypt_platform_field", return_value="cipher") as enc:
            self.assertTrue(mail.enqueue(self.admin, "security", "Subject", "Sensitive body"))
        record = post.call_args.args[1]
        self.assertEqual(record["payload_encrypted"], "cipher")
        self.assertNotIn("Sensitive body", json.dumps(record))
        self.assertIn("html", json.loads(enc.call_args.args[2]))

    def test_disabled_smtp_does_not_enqueue(self):
        with mock.patch.object(mail, "get_settings", return_value=None), mock.patch.object(mail.db, "_post") as post:
            self.assertFalse(mail.enqueue(self.admin, "security", "Subject", "Body"))
        post.assert_not_called()

    def test_reset_only_hash_saved_link_uses_fragment(self):
        with mock.patch.object(mail, "get_settings", return_value=self.settings), mock.patch.object(mail.db, "_rpc", return_value=True) as rpc, \
             mock.patch.object(mail, "enqueue", return_value=True) as queue, mock.patch.object(mail.secrets, "token_urlsafe", return_value="a"*43):
            self.assertTrue(mail.request_reset(self.admin))
        params = rpc.call_args.args[1]
        self.assertEqual(params["p_token_hash"], hashlib.sha256(("a"*43).encode()).hexdigest())
        self.assertNotIn("a"*43, json.dumps(params))
        self.assertIn("/auth/reset-password#token="+"a"*43, queue.call_args.args[3])

    def test_reset_inactive_not_issued(self):
        with mock.patch.object(mail.db, "_rpc") as rpc:
            self.assertFalse(mail.request_reset(dict(self.admin, is_active=False)))
        rpc.assert_not_called()

    def _delivery(self, exception=None, changed=False, category="security", attempts=1):
        row = dict(id="m1", admin_id="a1", company_id="c1", branch_id=None, category=category, attempts=attempts,
                   payload_encrypted="cipher")
        payload = json.dumps(dict(to=self.admin["email"], subject="Subject", text="Body", html="<p>Body</p>"))
        with mock.patch.object(mail.db, "_rpc", return_value=[row]), mock.patch.object(mail, "decrypt_platform_field", return_value=payload), \
             mock.patch.object(mail.db, "get_admin_by_id", return_value=dict(self.admin, email="new@example.com") if changed else self.admin), \
             mock.patch.object(mail, "get_settings", return_value=self.settings), mock.patch.object(mail, "send", side_effect=exception) as send, \
             mock.patch.object(mail, "_finish") as finish:
            self.assertTrue(mail.deliver_one())
            return send, finish

    def test_delivery_marks_smtp_accepted(self):
        send, finish = self._delivery()
        send.assert_called_once()
        self.assertEqual(finish.call_args.args[2:4], ("sent", "smtp_accepted"))

    def test_changed_email_skips_pending_message(self):
        send, finish = self._delivery(changed=True)
        send.assert_not_called()
        self.assertEqual(finish.call_args.args[2], "skipped")

    def test_opt_out_rechecked_before_delivery(self):
        send, finish = self._delivery(category="jobs_completed")
        send.assert_not_called()
        self.assertEqual(finish.call_args.args[2], "skipped")

    def test_temporary_failure_retries_without_provider_text(self):
        _, finish = self._delivery(OSError("sensitive details"))
        self.assertEqual(finish.call_args.args[2:4], ("pending", "delivery_failed"))
        self.assertGreater(finish.call_args.args[4], 0)

    def test_auth_failure_permanent_and_sanitized(self):
        _, finish = self._delivery(smtplib.SMTPAuthenticationError(535, b"secret"))
        self.assertEqual(finish.call_args.args[2:4], ("failed", "authentication_failed"))

    def test_retry_budget_is_bounded(self):
        _, finish = self._delivery(OSError("offline"), attempts=6)
        self.assertEqual(finish.call_args.args[2], "failed")

    def test_terminal_status_clears_body_and_uses_claim_guard(self):
        with mock.patch.object(mail.db, "_patch") as patch:
            mail._finish({"id":"m1"}, "claim", "sent", "smtp_accepted")
        self.assertIn("claim_token=eq.claim", patch.call_args.args[0])
        self.assertIsNone(patch.call_args.args[1]["payload_encrypted"])

    def test_fanout_durable_recipient_dedup_key(self):
        event = dict(id="event1", category="jobs_failed", kind="job_failed", company_id="c1", branch_id=None,
                     record_id="job1", expires_at="2099-01-01T00:00:00Z")
        with mock.patch.object(mail.db, "_rpc", return_value=[event]), mock.patch.object(mail.db, "_get", return_value=[self.admin]), \
             mock.patch.object(mail.db, "_patch") as patch, mock.patch.object(mail, "enqueue") as queue:
            mail.fanout_one()
        self.assertEqual(queue.call_args.kwargs["event_key"], "event1:a1")
        self.assertTrue(patch.call_args.args[1]["processed"])

    def test_legacy_in_app_preferences_preserve_email_categories(self):
        from routes import settings
        app = Flask(__name__)
        with app.test_request_context("/settings/notifications", method="POST", data={"in_app":"1"}):
            g.admin = dict(self.admin, notification_prefs={"email_categories":{"jobs_failed":False}})
            with mock.patch.object(settings.db, "update_admin") as update:
                raw(settings.update_notifications)()
        self.assertEqual(update.call_args.args[1]["notification_prefs"]["email_categories"], {"jobs_failed":False})

    def test_smtp_route_role_boundary(self):
        app = Flask(__name__)
        app.register_blueprint(routes.bp)
        @app.before_request
        def context():
            g.admin = dict(self.admin, role="technician", mfa_enabled=True)
            g.company = {"id":"c1"}
            g.is_superadmin = False
        path = "/settings/mail" if mail.SCOPE_MODE == "company" else "/admin/mail"
        with mock.patch.object(mail, "get_settings") as settings:
            self.assertEqual(app.test_client().get(path).status_code, 403)
        settings.assert_not_called()

    def test_forgot_response_identical_for_missing_and_existing_account(self):
        app = Flask(__name__)
        app.secret_key = "test"
        results = []
        for target in (None, self.admin):
            with app.test_request_context("/auth/forgot-password", method="POST", data={"email":"owner@example.com"}), \
                 mock.patch.object(routes, "check_rate_limit", return_value=True), mock.patch.object(routes.db, "get_admin_by_email", return_value=target), \
                 mock.patch.object(mail, "request_reset", return_value=True), mock.patch.object(routes, "render_template", return_value="generic") as render:
                response = routes.forgot_password()
                results.append((response.status_code, response.get_data(), render.call_args.kwargs))
                self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(results[0], results[1])

    def test_expired_reset_does_not_login(self):
        app = Flask(__name__)
        with app.test_request_context("/auth/reset-password", method="POST", data={
                "token":"a"*43,"password":"a-long-safe-password","confirm_password":"a-long-safe-password"}), \
             mock.patch.object(routes, "check_rate_limit", return_value=True), mock.patch.object(routes.db, "_rpc", return_value=None), \
             mock.patch("routes.auth._hash_password", return_value="hash"), mock.patch.object(routes, "render_template", return_value="error") as render:
            response = routes.reset_password()
        self.assertFalse(render.call_args.kwargs["completed"])
        self.assertIn("already used", render.call_args.kwargs["error"])
        self.assertNotIn("Set-Cookie", response.headers)

    def test_real_encryption_binds_record_and_purpose(self):
        import base64
        from cryptography.exceptions import InvalidTag
        with mock.patch.object(mail.config, "TENANT_MASTER_KEK_B64", base64.b64encode(b"x"*32).decode()):
            encrypted = mail.encrypt_platform_field("m1", "mail.payload", "private body")
            self.assertNotIn("private body", encrypted)
            self.assertEqual(mail.decrypt_platform_field("m1", "mail.payload", encrypted), "private body")
            with self.assertRaises(InvalidTag):
                mail.decrypt_platform_field("m2", "mail.payload", encrypted)
            with self.assertRaises(InvalidTag):
                mail.decrypt_platform_field("m1", "smtp.config", encrypted)

    def test_welcome_action_requires_tenant_match(self):
        app = Flask(__name__)
        with app.test_request_context("/users/a2/welcome-email", method="POST"):
            g.company, g.admin = {"id":"c1"}, self.admin
            with mock.patch.object(routes.db, "get_admin_by_id", return_value=dict(self.admin, company_id="other")), \
                 mock.patch.object(mail, "enqueue") as queue:
                from werkzeug.exceptions import NotFound
                with self.assertRaises(NotFound):
                    raw(routes.admin_welcome)("a2")
        queue.assert_not_called()

    def test_recovery_and_smtp_templates_render(self):
        from flask import render_template
        from jinja2 import ChoiceLoader, DictLoader
        template_dir = pathlib.Path(__file__).resolve().parents[1] / "templates"
        app = Flask(__name__, template_folder=str(template_dir))
        app.secret_key = "fixture"
        # Keep this contract focused on these pages, not the shared app shell.
        app.jinja_loader = ChoiceLoader([DictLoader({"base.html":"{% block content %}{% endblock %}"}), app.jinja_loader])
        app.jinja_env.filters["timeago"] = lambda value: value
        app.jinja_env.globals["csrf_token"] = lambda: "csrf-fixture"
        with app.test_request_context():
            for mode in ("forgot", "reset"):
                body = render_template("password_recovery.html", mode=mode, csp_nonce="nonce", asset_v="1")
                self.assertIn('name="csrf_token"', body)
                if mode == "reset":
                    self.assertIn("password-recovery.js", body)
            body = render_template("settings/mail.html", platform_mail=True, smtp=mail.public_settings(self.settings),
                                   mail_rows=[], mail_path="/admin/mail", company=None)
            self.assertIn("Send test to my email", body)
            self.assertNotIn('value="secret"', body)
            body = render_template("settings/email_notifications.html", company=None, categories=mail.CATEGORIES,
                                   email_prefs={"jobs_failed":True})
            self.assertIn("jobs_failed", body)

    def test_reset_rejects_password_mismatch_before_database_call(self):
        app = Flask(__name__)
        with app.test_request_context("/auth/reset-password", method="POST", data={
                "token":"a"*43,"password":"a-long-safe-password","confirm_password":"different"}), \
             mock.patch.object(routes, "check_rate_limit", return_value=True), mock.patch.object(routes.db, "_rpc") as rpc, \
             mock.patch.object(routes, "render_template", return_value="error"):
            routes.reset_password()
        rpc.assert_not_called()


if __name__ == "__main__":
    unittest.main()
