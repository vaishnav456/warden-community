import unittest
from unittest.mock import MagicMock

from services import notify_svc


class NotificationServiceTests(unittest.TestCase):
    def test_push_inserts_scoped_notification_and_commits(self):
        conn = MagicMock()
        cursor = conn.cursor.return_value.__enter__.return_value

        notify_svc.push(
            conn, admin_id="admin-1", company_id="company-1",
            type_="warning", title="Disk low", body="5 GB left",
            link="/alerts", ref_id="alert-1",
        )

        cursor.execute.assert_called_once()
        params = cursor.execute.call_args.args[1]
        self.assertEqual(
            params,
            ("admin-1", "company-1", "warning", "Disk low", "5 GB left", "/alerts", "alert-1"),
        )
        conn.commit.assert_called_once_with()

    def test_unread_count_returns_database_count(self):
        conn = MagicMock()
        cursor = conn.cursor.return_value.__enter__.return_value
        cursor.fetchone.return_value = (7,)

        self.assertEqual(notify_svc.unread_count(conn, "admin-1"), 7)


if __name__ == "__main__":
    unittest.main()
