import pathlib
import sys
import unittest
from unittest import mock

from flask import Flask, g


SERVER_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from routes import auth


def _undecorated(view):
    while hasattr(view, "__wrapped__"):
        view = view.__wrapped__
    return view


class MfaSetupTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)

    def test_setup_mfa_renders_a_png_qr_code_and_sets_setup_cookie(self):
        with self.app.test_request_context("/setup-mfa"):
            g.admin = {"id": "admin-1", "email": "admin@example.com", "mfa_enabled": False}
            g.company_slug = "example"
            with mock.patch.object(auth, "render_template", return_value="ok") as render:
                response = _undecorated(auth.setup_mfa)()

        self.assertEqual(response.status_code, 200)
        self.assertIn("warden_mfa_setup=", response.headers["Set-Cookie"])
        context = render.call_args.kwargs
        self.assertTrue(context["qr_b64"].startswith("iVBOR"))
        self.assertEqual(len(context["backup_codes"]), 10)

    def test_invalid_mfa_code_keeps_the_qr_and_backup_codes_visible(self):
        claims = {
            "sub": "admin-1",
            "secret": "JBSWY3DPEHPK3PXP",
            "backup_codes": ["BACKUPCODE"],
        }
        with self.app.test_request_context(
            "/setup-mfa", method="POST", data={"code": "000000"},
            headers={"Cookie": "warden_mfa_setup=test-token"},
        ):
            g.admin = {"id": "admin-1", "email": "admin@example.com", "mfa_enabled": False}
            g.company_slug = "example"
            with mock.patch("jwt.decode", return_value=claims), \
                 mock.patch("pyotp.TOTP.verify", return_value=False), \
                 mock.patch.object(auth, "render_template", return_value="invalid") as render:
                response, status = _undecorated(auth.setup_mfa_confirm)()

        self.assertEqual(status, 400)
        self.assertEqual(response, "invalid")
        self.assertTrue(render.call_args.kwargs["qr_b64"].startswith("iVBOR"))
        self.assertEqual(render.call_args.kwargs["backup_codes"], ["BACKUPCODE"])
        self.assertEqual(render.call_args.kwargs["error"], "Invalid code. Try again.")


if __name__ == "__main__":
    unittest.main()
