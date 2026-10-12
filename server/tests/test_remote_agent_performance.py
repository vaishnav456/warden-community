import asyncio
import json
import math
import unittest
from unittest.mock import patch

from services.remote_performance import (validate_agent_performance, TIMING_FIELDS,
                                          COUNTER_FIELDS, DIMENSION_FIELDS, INPUT_OUTCOME_FIELDS)
from services import ws_proxy


def window():
    result = dict(window_ms=5000, input_queue_max=2, encoded_bytes=100,
                  timings={key: dict(samples=1, mean_ms=1.5, max_ms=2) for key in TIMING_FIELDS})
    result.update({key: 1 for key in COUNTER_FIELDS})
    result.update({key: 1920 if key.endswith('_w') else 1080 for key in DIMENSION_FIELDS})
    return result


def report():
    return dict(type='remote_agent_performance', version=1, service=window(), helper=window(), helper_age_ms=5)


def outcome_report():
    result = report()
    result['version'] = 2
    result['service'].update(input_attempts=0, input_accepted=0, input_rejected=0)
    result['helper'].update(input_attempts=10, input_accepted=8, input_rejected=2)
    return result


class AgentPerformanceValidationTests(unittest.TestCase):
    def test_valid_report_is_copied_with_no_content_fields(self):
        original = report()
        value = validate_agent_performance(original)
        self.assertEqual(value, original)
        original['service']['timings']['input_queue']['max_ms'] = 5000
        self.assertEqual(value['service']['timings']['input_queue']['max_ms'], 2)
        self.assertEqual(validate_agent_performance(dict(type='remote_agent_performance', version=1, service=window()))['service'], window())

    def test_version_two_outcomes_are_copied_and_version_one_keeps_exact_old_schema(self):
        original = outcome_report()
        validated = validate_agent_performance(original)
        self.assertEqual(validated, original)
        original['helper']['input_rejected'] = 10
        self.assertEqual(validated['helper']['input_rejected'], 2)
        self.assertEqual(validate_agent_performance(dict(type='remote_agent_performance', version=2,
                         service=outcome_report()['service']))['service'], outcome_report()['service'])
        old = validate_agent_performance(report())
        self.assertFalse(set(INPUT_OUTCOME_FIELDS) & set(old['helper']))
        for field in INPUT_OUTCOME_FIELDS:
            candidate = report()
            candidate['helper'][field] = 0
            self.assertIsNone(validate_agent_performance(candidate))

    def test_version_two_requires_all_bounded_integer_outcomes_and_consistent_totals(self):
        for stage in ('service', 'helper'):
            for field in INPUT_OUTCOME_FIELDS:
                candidate = outcome_report()
                del candidate[stage][field]
                self.assertIsNone(validate_agent_performance(candidate))
                for value in (True, None, 'private-input', -1, 1.5, math.nan, math.inf, 1000001, 10**1000):
                    with self.subTest(stage=stage, field=field, value_type=type(value).__name__):
                        candidate = outcome_report()
                        candidate[stage][field] = value
                        self.assertIsNone(validate_agent_performance(candidate))
            candidate = outcome_report()
            candidate[stage]['input_attempts'] += 1
            self.assertIsNone(validate_agent_performance(candidate))
            candidate = outcome_report()
            candidate[stage].update(input_attempts=1000000, input_accepted=999999, input_rejected=1)
            self.assertEqual(validate_agent_performance(candidate), candidate)
            candidate[stage]['input_contents'] = 'private'
            self.assertIsNone(validate_agent_performance(candidate))

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
    async def test_version_two_round_trip_and_history_keep_only_validated_outcomes(self):
        candidate = outcome_report()
        invalid = outcome_report()
        invalid['helper']['input_rejected'] = 3
        destination = Stream()
        counters = ws_proxy._RemoteRelayPerformance(clock=lambda: 0.0)
        with patch.object(ws_proxy.db, '_get') as read, patch.object(ws_proxy.db, '_patch') as write:
            await ws_proxy._relay(Stream([json.dumps(candidate), json.dumps(invalid), b'\x00fresh']),
                                  destination, None, counters)
        self.assertEqual(json.loads(destination.sent[0]), candidate)
        self.assertEqual(destination.sent[1:], [b'\x00fresh'])
        history = counters.snapshot(include_history=True)['agent_performance_history']
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]['report']['helper']['input_rejected'], 2)
        read.assert_not_called()
        write.assert_not_called()

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
        self.assertEqual(counters.snapshot()['received_frame_messages'], 2)
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
        self.assertEqual(counters.snapshot(include_history=True)['agent_performance_history'], [])

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

    def test_numeric_history_has_stable_sequences_age_and_bounded_copies(self):
        clock = [0.0]
        counters = ws_proxy._RemoteRelayPerformance(clock=lambda: clock[0])
        candidate = report()
        for number in range(20):
            clock[0] = float(number * 5)
            counters.observe_agent(candidate)
        self.assertEqual(len(counters._agent_reports), counters.REPORT_LIMIT)
        snapshot = counters.snapshot(include_history=True)
        history = snapshot['agent_performance_history']
        self.assertEqual([entry['sequence'] for entry in history], list(range(9, 21)))
        self.assertEqual([entry['age_ms'] for entry in history], list(range(55000, -1, -5000)))
        self.assertEqual(snapshot['agent_performance_sequence'], 20)
        self.assertEqual(snapshot['agent_performance_age_ms'], 0)
        self.assertTrue(all(entry['report'] == candidate for entry in history))
        # Neither raw input, returned validation data nor snapshot consumers
        # may mutate the session's retained numeric report history.
        validated = counters.observe_agent(candidate)
        validated['helper']['timings']['input_dispatch']['max_ms'] = 100
        candidate['service']['timings']['input_queue']['max_ms'] = 200
        history[-1]['report']['helper']['native_w'] = 9999
        fresh = counters.snapshot(include_history=True)
        self.assertEqual(fresh['agent_performance_history'][-1]['report']['helper']['timings']['input_dispatch']['max_ms'], 2)
        self.assertEqual(fresh['agent_performance_history'][-1]['report']['service']['timings']['input_queue']['max_ms'], 2)
        self.assertEqual(fresh['agent_performance_history'][-2]['report']['helper']['native_w'], 1920)
        self.assertNotIn('agent_performance_history', counters.snapshot())
        clock[0] += 1.5
        later = counters.snapshot(include_history=True)
        self.assertEqual(later['agent_performance_history'][-1]['sequence'], 21)
        self.assertEqual(later['agent_performance_history'][-1]['age_ms'], 1500)

    def test_history_prunes_by_age_and_invalid_reports_never_enter(self):
        clock = [0.0]
        counters = ws_proxy._RemoteRelayPerformance(clock=lambda: clock[0])
        counters.observe_agent(report())
        invalid = report()
        invalid['service']['timings']['input_queue']['secret'] = 'private-input'
        clock[0] = 30.0
        self.assertIsNone(counters.observe_agent(invalid))
        snapshot = counters.snapshot(include_history=True)
        self.assertEqual(len(snapshot['agent_performance_history']), 1)
        self.assertEqual(snapshot['agent_performance_history'][0]['sequence'], 1)
        self.assertEqual(snapshot['agent_performance_history'][0]['age_ms'], 30000)
        self.assertNotIn('private-input', json.dumps(snapshot))
        self.assertNotIn('agent_performance', snapshot)
        clock[0] = 90.0
        self.assertEqual(len(counters.snapshot(include_history=True)['agent_performance_history']), 1)
        clock[0] = 90.001
        # Ordinary pongs also prune storage, without transmitting the history.
        self.assertNotIn('agent_performance_history', counters.snapshot())
        self.assertEqual(len(counters._agent_reports), 0)
        self.assertEqual(counters.snapshot(include_history=True)['agent_performance_history'], [])
        counters.observe_agent(report())
        self.assertEqual(counters.snapshot(include_history=True)['agent_performance_history'][0]['sequence'], 2)

    async def test_ordinary_pong_excludes_history_but_existing_quality_write_retains_it(self):
        from types import SimpleNamespace
        from unittest.mock import AsyncMock
        counters = ws_proxy._RemoteRelayPerformance(clock=lambda: 0.0)
        counters.observe_agent(report())
        source = Stream(['{"type":"relay_ping","nonce":"fresh"}'])
        await ws_proxy._relay_browser_to_agent(source, Stream(),
            {'id': 'session', 'capabilities': {'view': True}}, counters, {'agent_rtt_ms': 1})
        performance = json.loads(source.sent[0])['performance']
        self.assertNotIn('agent_performance_history', performance)
        self.assertEqual(performance['agent_performance_sequence'], 1)
        pong = asyncio.get_running_loop().create_future()
        pong.set_result(None)
        agent = SimpleNamespace(ping=AsyncMock(return_value=pong))
        writes = []
        def save(path, data):
            writes.append(data)
        async def end_iteration(_):
            raise asyncio.CancelledError()
        with patch.object(ws_proxy.db, '_patch', side_effect=save), \
                patch.object(ws_proxy.asyncio, 'sleep', new=end_iteration):
            with self.assertRaises(asyncio.CancelledError):
                await ws_proxy._measure_remote_quality(agent, {'id': 'session', 'company_id': 'tenant'},
                    {'transport': 'server_relay', 'bytes_to_browser': 0}, counters)
        self.assertEqual(len(writes), 1)
        self.assertEqual(len(writes[0]['connection_quality']['performance']['agent_performance_history']), 1)


if __name__ == '__main__':
    unittest.main()
