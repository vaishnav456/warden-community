import os
import unittest
from unittest.mock import patch
from services.http_capacity import http_threads
from services.load_control import LoadController


class HttpCapacityTests(unittest.TestCase):
    def test_admission_uses_the_same_configured_thread_capacity(self):
        with patch.dict(os.environ, {"WARDEN_HTTP_THREADS": "64"}):
            self.assertEqual(http_threads(), 64)
            control = LoadController()
            self.assertEqual(control.http_capacity, 64)
            control.active_http = 63
            for _ in range(3):
                control.http_latency = 2
                control.observe()
            self.assertFalse(control.busy)
            control.active_http = 64
            for _ in range(3):
                control.http_latency = 2
                control.observe()
            self.assertTrue(control.busy)

    def test_invalid_thread_counts_fail_configuration(self):
        for value in ("0", "3", "129", "unlimited"):
            with patch.dict(os.environ, {"WARDEN_HTTP_THREADS": value}):
                with self.assertRaises(ValueError):
                    http_threads()
