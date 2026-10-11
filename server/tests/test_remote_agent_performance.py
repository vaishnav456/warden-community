import json
import math
import unittest
from unittest.mock import patch

from services.remote_performance import (validate_agent_performance, TIMING_FIELDS,
                                          COUNTER_FIELDS, DIMENSION_FIELDS)
from services import ws_proxy


def window():
    result = dict(window_ms=5000, input_queue_max=2, encoded_bytes=100,
                  timings={key: dict(samples=1, mean_ms=1.5, max_ms=2) for key in TIMING_FIELDS})
    result.update({key: 1 for key in COUNTER_FIELDS})
    result.update({key: 1920 if key.endswith('_w') else 1080 for key in DIMENSION_FIELDS})
    return result


def report():
    return dict(type='remote_agent_performance', version=1, service=window(), helper=window(), helper_age_ms=5)


class AgentPerformanceValidationTests(unittest.TestCase):
    def test_valid_report_is_copied_with_no_content_fields(self):
        original = report()
        value = validate_agent_performance(original)
        self.assertEqual(value, original)
        original['service']['timings']['input_queue']['max_ms'] = 5000
        self.assertEqual(value['service']['timings']['input_queue']['max_ms'], 2)
        self.assertEqual(validate_agent_performance(dict(type='remote_agent_performance', version=1, service=window()))['service'], window())

    def test_nonfinite_boolean_negative_and_overflow_values_are_rejected(self):
        for value in (True, 'secret-content', -1, math.nan, math.inf, 10**1000):
            for path in ('window_ms', 'input_queue_max', 'encoded_bytes', 'native_w'):
                with self.subTest(value_type=type(value).__name__, path=path):
                    candidate = report()
                    candidate['service'][path] = value
                    self.assertIsNone(validate_agent_performance(candidate))

    def test_integer_fields_and_numeric_bounds_are_enforced(self):
        for path, value in (('input_queue_max', 129), ('native_w', 16385), ('full_frames', 1000001),
                            ('encoded_bytes', 1073741825), ('window_ms', 60001), ('partial_frames', 1.5)):
            candidate = report()
            candidate['helper'][path] = value
            self.assertIsNone(validate_agent_performance(candidate))

    def test_unknown_nested_fields_and_inconsistent_timings_are_rejected(self):
        mutations = [lambda r: r.update(secret='contents'),
                     lambda r: r['service'].update(coordinates='contents'),
                     lambda r: r['service']['timings'].update(other=dict(samples=0, mean_ms=0, max_ms=0)),
                     lambda r: r['service']['timings']['ws_write'].update(text='contents'),
                     lambda r: r['service']['timings']['ws_write'].update(samples=0),
                     lambda r: r['service']['timings']['ws_write'].update(mean_ms=3),
                     lambda r: r['service']['timings']['ws_write'].update(samples=True),
                     lambda r: r['service']['timings']['ws_write'].update(max_ms=math.inf)]
        for mutate in mutations:
            candidate = report()
            mutate(candidate)
            self.assertIsNone(validate_agent_performance(candidate))

    def test_helper_age_requires_matching_helper_and_supported_schema(self):
        for candidate in (dict(report(), version=True), dict(report(), version=2),
                          dict(report(), helper_age_ms=-1), dict(report(), helper_age_ms=math.nan),
                          dict(report(), helper_age_ms=60001), [], None):
            self.assertIsNone(validate_agent_performance(candidate))
        candidate = report()
        del candidate['helper_age_ms']
        self.assertIsNone(validate_agent_performance(candidate))


class Stream:
    def __init__(self, messages=()):
        self.messages = iter(messages)
        self.sent = []

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return next(self.messages)
        except StopIteration:
            raise StopAsyncIteration

    async def send(self, value):
        self.sent.append(value)


class AgentPerformanceRelayTests(unittest.IsolatedAsyncioTestCase):
    async def test_report_relay_preserves_frames_without_database_queries(self):
        candidate = report()
        packets = [b'\x00full', json.dumps(candidate), b'\x01partial', '{"type":"init","w":1920,"h":1080}']
        destination = Stream()
        counters = ws_proxy._RemoteRelayPerformance()
        with patch.object(ws_proxy.db, '_get') as read, patch.object(ws_proxy.db, '_patch') as write:
            await ws_proxy._relay(Stream(packets), destination, {'bytes_to_browser': 0}, counters)
        self.assertEqual(destination.sent[0], packets[0])
        self.assertEqual(json.loads(destination.sent[1]), candidate)
        self.assertEqual(destination.sent[2:], packets[2:])
        self.assertEqual(counters.snapshot()['frame_messages'], 2)
        self.assertEqual(counters.snapshot()['agent_performance'], candidate)
        read.assert_not_called()
        write.assert_not_called()

    async def test_invalid_or_oversized_reports_are_dropped_without_stalling_frames(self):
        invalid = report()
        invalid['helper']['native_w'] = 'screen contents'
        destination = Stream()
        packets = [json.dumps(invalid), json.dumps(report())+' '*8192, b'\x00fresh']
        counters = ws_proxy._RemoteRelayPerformance()
        await ws_proxy._relay(Stream(packets), destination, None, counters)
        self.assertEqual(destination.sent, [b'\x00fresh'])
        self.assertNotIn('agent_performance', counters.snapshot())

    def test_latest_report_storage_is_session_scoped_and_expires(self):
        clock = [0.0]
        counters = ws_proxy._RemoteRelayPerformance(clock=lambda: clock[0])
        for number in range(1000):
            candidate = report()
            candidate['service']['full_frames'] = number
            counters.observe_agent(candidate)
        self.assertEqual(counters.snapshot()['agent_performance']['service']['full_frames'], 999)
        self.assertNotIn('agent_performance', ws_proxy._RemoteRelayPerformance().snapshot())
        clock[0] = 20.001
        self.assertNotIn('agent_performance', counters.snapshot())


if __name__ == '__main__':
    unittest.main()
