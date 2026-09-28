import pathlib
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

SERVER_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from services import alert_engine


class AlertEngineTests(unittest.TestCase):
    @patch.object(alert_engine, "_check_endpoint")
    @patch.object(alert_engine.db, "get_endpoints_for_alert_check")
    @patch.object(alert_engine.db, "get_all_companies")
    @patch.object(alert_engine.db, "get_all_alert_configs", return_value=[])
    def test_default_thresholds_apply_without_config_row(
        self, _configs, companies, endpoints, check_endpoint,
    ):
        companies.return_value = [{"id": "company-1", "is_active": True}]
        endpoints.return_value = [{"id": "endpoint-1"}]

        alert_engine._check_once()

        check_endpoint.assert_called_once_with(
            {"id": "endpoint-1"}, "company-1", 90, 90, 5, 5,
        )

    @patch.object(alert_engine, "_check_connection_anomalies")
    @patch.object(alert_engine, "_resolve_if_open")
    @patch.object(alert_engine.db, "get_open_alert", return_value=None)
    @patch.object(alert_engine.db, "create_alert")
    def test_offline_alert_respects_configured_last_seen_age(
        self, create_alert, _get_open, _resolve, _anomalies,
    ):
        two_minutes_ago = (
            datetime.now(timezone.utc) - timedelta(minutes=2)
        ).isoformat()
        endpoint = {
            "id": "endpoint-1", "branch_id": "branch-1", "hostname": "PC",
            "status": "offline", "last_seen": two_minutes_ago,
            "cpu_pct": None, "ram_used_pct": None, "disk_free_gb": None,
        }

        alert_engine._check_endpoint(endpoint, "company-1", 90, 90, 5, 10)

        create_alert.assert_not_called()
        _resolve.assert_any_call("endpoint-1", "endpoint_offline", "Endpoint is online again")


if __name__ == "__main__":
    unittest.main()
