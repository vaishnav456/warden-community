import unittest
from unittest.mock import patch
from services.load_control import LoadController


class LoadControlTests(unittest.TestCase):
    def test_slow_http_does_not_block_idle_relay(self):
        control = LoadController()
        control.active_http = 4
        for _ in range(60):
            control.http_latency = 1.9
            control.observe(cpu=.01, memory=.21, lag=.001)
            self.assertFalse(control.reject_remote([], None))
        self.assertLess(control.pressure, .8)
        self.assertGreater(control.snapshot()['http_latency_seconds'], 1)

    def test_http_saturation_requires_full_pool_and_recovers_with_spare_capacity(self):
        control = LoadController(http_capacity=8)
        control.active_http = 7
        for _ in range(10):
            control.http_latency = 2
            control.observe()
        self.assertFalse(control.busy)
        control.active_http = 8
        for sample in range(3):
            control.http_latency = 2
            control.observe()
            self.assertEqual(control.busy, sample == 2)
        control.active_http = 4
        for _ in range(10):
            control.http_latency = 2
            control.observe(cpu=.01, memory=.21)
        self.assertFalse(control.busy)

    def test_slow_http_still_protects_against_real_resource_pressure(self):
        for signals in (dict(cpu=.9), dict(memory=.9), dict(lag=.2)):
            with self.subTest(signals=signals):
                control = LoadController()
                for _ in range(3):
                    control.http_latency = 2
                    control.observe(**signals)
                self.assertTrue(control.reject_remote([], None))

    def test_pressure_hysteresis_and_recovery(self):
        control = LoadController()
        for _ in range(2):
            control.observe(cpu=.9)
        self.assertFalse(control.busy)
        control.observe(cpu=.9)
        self.assertTrue(control.reject_remote([], "new"))
        for _ in range(9):
            control.observe()
        self.assertTrue(control.busy)
        control.observe()
        self.assertFalse(control.busy)

    def test_memory_emergency(self):
        control = LoadController()
        control.observe(memory=.96)
        self.assertTrue(control.busy)

    def test_memory_recovery_does_not_require_unrealistically_empty_host(self):
        control = LoadController()
        control.observe(memory=.96)
        for _ in range(10):
            control.observe(memory=.79)
        self.assertFalse(control.busy)

    def test_idle_capacity_is_borrowable(self):
        control = LoadController()
        self.assertFalse(control.reject_remote(["a"] * 100, "a"))

    def test_fairness_only_when_contended(self):
        control = LoadController()
        control.pressure = .9
        self.assertFalse(control.reject_remote(["a"] * 10, "a"))
        self.assertTrue(control.reject_remote(["a"] * 10 + ["b"], "a"))
        self.assertFalse(control.reject_remote(["a"] * 10 + ["b"], "b"))

    def test_metric_sampling_recovers_without_dropping_heartbeat(self):
        control = LoadController()
        control.busy = True
        with patch("services.load_control.time.monotonic", return_value=100):
            self.assertTrue(control.allow_metric("a"))
            self.assertFalse(control.allow_metric("a"))
            self.assertTrue(control.allow_metric("b"))
        with patch("services.load_control.time.monotonic", return_value=160):
            self.assertTrue(control.allow_metric("a"))
        control.busy = False
        self.assertTrue(control.allow_metric("a"))

    def test_bad_samples_are_ignored_and_http_recovers(self):
        control = LoadController()
        control.observe(cpu=float("nan"))
        self.assertEqual(control.pressure, 0)
        control.http_latency = 3
        for _ in range(30):
            control.observe()
        self.assertFalse(control.busy)
