import os
import pathlib
import sys
import unittest
from unittest.mock import patch

os.environ["WERKZEUG_RUN_MAIN"] = "true"

SERVER_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

import app as warden_app


class HealthTests(unittest.TestCase):
    def setUp(self):
        self.client = warden_app.app.test_client()

    @patch("services.ws_proxy.is_ready", return_value=True)
    @patch("db.healthcheck", return_value=True)
    def test_health_requires_database_and_relay(self, healthcheck, relay_ready):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"status": "ok"})
        healthcheck.assert_called_once_with()
        relay_ready.assert_called_once_with()

    @patch("services.ws_proxy.is_ready", return_value=True)
    @patch("db.healthcheck", side_effect=OSError("database unavailable"))
    def test_health_is_unavailable_when_database_query_fails(self, _healthcheck, _relay_ready):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json(), {"status": "unavailable"})

    @patch("services.ws_proxy.is_ready", return_value=False)
    @patch("db.healthcheck", return_value=True)
    def test_health_is_unavailable_when_relay_is_down(self, _healthcheck, _relay_ready):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json(), {"status": "unavailable"})

    def test_internal_errors_are_json_for_json_clients(self):
        with warden_app.app.test_request_context(
            "/endpoints/example/experience", headers={"Accept": "application/json"}
        ):
            response, status = warden_app.server_error(RuntimeError("test failure"))
        self.assertEqual(status, 500)
        self.assertEqual(response.get_json(), {
            "error": "The server could not complete this request. Please retry."
        })

    def test_internal_errors_are_json_for_fetch_requests(self):
        with warden_app.app.test_request_context(
            "/endpoints/example/action", headers={"Sec-Fetch-Dest": "empty"}
        ):
            response, status = warden_app.server_error(RuntimeError("test failure"))
        self.assertEqual(status, 500)
        self.assertTrue(response.is_json)


if __name__ == "__main__":
    unittest.main()
