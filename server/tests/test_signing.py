import time
import unittest
from unittest.mock import patch

from services import signing


class SigningClockSkewTests(unittest.TestCase):
    @patch.object(signing, "_get_private_key")
    def test_fresh_jobs_are_backdated_for_slow_windows_guests(self, private_key):
        private_key.return_value.sign.return_value = b"signature"
        with patch.object(time, "time", return_value=2_000_000_000):
            envelope = signing.sign_job(
                "job-1", "COLLECT_SYSINFO", {}, "company-1", "endpoint-1",
            )

        self.assertEqual(envelope["issued_at"], 2_000_000_000 - 7200)
        self.assertEqual(
            envelope["expires_at"],
            2_000_000_000 + signing.config.COMMAND_MAX_AGE_SEC,
        )
        self.assertEqual(envelope["company_id"], "company-1")
        self.assertEqual(envelope["endpoint_id"], "endpoint-1")


if __name__ == "__main__":
    unittest.main()
