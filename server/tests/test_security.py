import pathlib
import sys
import unittest
from unittest import mock

from flask import Flask, Response

SERVER_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from middleware import security


class RateLimitTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        security._rate_buckets.clear()

    def tearDown(self):
        security._rate_buckets.clear()

    def test_limit_records_first_request_and_rejects_over_limit(self):
        with self.app.test_request_context(
            "/login", environ_base={"REMOTE_ADDR": "203.0.113.10"}
        ), mock.patch("db.consume_rate_limit", side_effect=[True, True, True, False]) as consume:
            self.assertTrue(security.check_rate_limit("login", 3))
            self.assertTrue(security.check_rate_limit("login", 3))
            self.assertTrue(security.check_rate_limit("login", 3))
            self.assertFalse(security.check_rate_limit("login", 3))
            self.assertEqual(consume.call_count, 4)
            bucket_key, limit, window = consume.call_args.args
            self.assertEqual(len(bucket_key), 64)
            self.assertEqual((limit, window), (3, 60))

    def test_limits_are_independent_by_ip(self):
        with mock.patch("db.consume_rate_limit", return_value=True) as consume:
            with self.app.test_request_context(
                "/login", environ_base={"REMOTE_ADDR": "203.0.113.11"}
            ):
                self.assertTrue(security.check_rate_limit("login", 1))
            first_key = consume.call_args.args[0]
            with self.app.test_request_context(
                "/login", environ_base={"REMOTE_ADDR": "203.0.113.12"}
            ):
                self.assertTrue(security.check_rate_limit("login", 1))
            self.assertNotEqual(first_key, consume.call_args.args[0])

    def test_database_failure_uses_local_fallback(self):
        with self.app.test_request_context(
            "/login", environ_base={"REMOTE_ADDR": "203.0.113.20"}
        ), mock.patch("db.consume_rate_limit", side_effect=OSError("offline")):
            self.assertTrue(security.check_rate_limit("login", 1))
            self.assertFalse(security.check_rate_limit("login", 1))


class SecurityHeaderTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)

    def test_default_referrer_policy_is_applied(self):
        with self.app.test_request_context("/"):
            response = security.apply_security_headers(Response("ok"))
        self.assertEqual(response.headers["Referrer-Policy"], "strict-origin-when-cross-origin")

    def test_stricter_route_referrer_policy_is_preserved(self):
        with self.app.test_request_context("/identity/setup/token"):
            response = Response("ok", headers={"Referrer-Policy": "no-referrer"})
            response = security.apply_security_headers(response)
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")


if __name__ == "__main__":
    unittest.main()
