import asyncio
import json
import math
import pathlib
import sys
import socket
import threading
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

SERVER_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from services import ws_proxy


class FakeWebSocket:
    def __init__(self):
        self.closed_with = None
        self.request = SimpleNamespace(headers={})

    async def close(self, code, reason=""):
        self.closed_with = (code, reason)


class MessageStream:
    def __init__(self, messages=()):
        self.messages = list(messages)
        self.sent = []

    def __aiter__(self):
        self._iter = iter(self.messages)
        return self

    async def __anext__(self):
        try:
            return next(self._iter)
        except StopIteration:
            raise StopAsyncIteration

    async def send(self, message):
        self.sent.append(message)


class RemoteRelayPerformanceTests(unittest.IsolatedAsyncioTestCase):
    async def test_send_sampling_counts_binary_frames_and_preserves_every_message(self):
        clock = [0.0]
        performance = ws_proxy._RemoteRelayPerformance(clock=lambda: clock[0])
        packets = [b'\x00full-jpeg', '{"type":"init"}', b'\x01partial-jpeg']
        waits = iter([0.010, 0.020, 0.030])
        class TimedDestination(MessageStream):
            async def send(self, message):
                clock[0] += next(waits)
                await super().send(message)
        destination = TimedDestination()
        quality = {'bytes_to_browser': 0}
        await ws_proxy._relay(MessageStream(packets), destination, quality, performance)
        snapshot = performance.snapshot()
        self.assertEqual(destination.sent, packets)
        self.assertEqual(quality['bytes_to_browser'], sum(len(packet.encode()) if isinstance(packet, str) else len(packet) for packet in packets))
        self.assertEqual(snapshot['frame_messages'], 2)
        self.assertEqual(snapshot['frame_bytes'], len(packets[0]) + len(packets[2]))
        self.assertEqual(snapshot['received_frame_messages'], 2)
        self.assertEqual(snapshot['received_frame_bytes'], len(packets[0]) + len(packets[2]))
        self.assertEqual(snapshot['send_samples'], 3)
        self.assertEqual(snapshot['send_wait_current_ms'], 0)
        self.assertEqual(snapshot['send_wait_latest_ms'], 30)
        self.assertEqual(snapshot['send_wait_mean_ms'], 20)
        self.assertEqual(snapshot['send_wait_max_ms'], 30)
        self.assertTrue(all(value is None or type(value) in (int, float) for value in snapshot.values()))

    async def test_in_progress_send_wait_is_visible_before_the_frame_is_accepted(self):
        clock = [10.0]
        performance = ws_proxy._RemoteRelayPerformance(clock=lambda: clock[0])
        started, finish = asyncio.Event(), asyncio.Event()
        packet = b'\x00jpeg'
        class BlockedDestination(MessageStream):
            async def send(self, message):
                started.set()
                await finish.wait()
                await super().send(message)
        destination = BlockedDestination()
        task = asyncio.create_task(ws_proxy._relay(MessageStream([packet]), destination, None, performance))
        try:
            await asyncio.wait_for(started.wait(), 1)
            clock[0] += 0.519
            snapshot = performance.snapshot()
            self.assertEqual(snapshot['send_wait_current_ms'], 519)
            self.assertEqual(snapshot['frame_messages'], 0)
            self.assertEqual(snapshot['received_frame_messages'], 1)
            self.assertEqual(snapshot['received_frame_bytes'], len(packet))
            self.assertEqual(snapshot['send_samples'], 0)
            finish.set()
            await asyncio.wait_for(task, 1)
            snapshot = performance.snapshot()
            self.assertEqual(snapshot['send_wait_current_ms'], 0)
            self.assertEqual(snapshot['send_wait_latest_ms'], 519)
            self.assertEqual(snapshot['frame_messages'], 1)
            self.assertEqual(destination.sent, [packet])
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    def test_send_history_is_bounded_and_samples_track_recent_waits(self):
        clock = [0.0]
        performance = ws_proxy._RemoteRelayPerformance(clock=lambda: clock[0])
        packet = b'\x00synthetic-jpeg'
        for number in range(1, 1001):
            performance.begin_send()
            clock[0] += number / 1000
            performance.finish_send(packet, True)
        snapshot = performance.snapshot()
        self.assertEqual(snapshot['send_samples'], 120)
        self.assertEqual(len(performance._send_waits), performance.SAMPLE_LIMIT)
        self.assertEqual(snapshot['send_wait_latest_ms'], 1000)
        self.assertEqual(snapshot['send_wait_max_ms'], 1000)
        self.assertEqual(snapshot['send_wait_mean_ms'], 940.5)
        self.assertEqual(snapshot['frame_messages'], 1000)
        self.assertEqual(snapshot['frame_bytes'], 1000 * len(packet))
        self.assertTrue(all(type(value) is float for value in performance._send_waits))

    async def test_failed_or_cancelled_send_does_not_count_an_accepted_frame(self):
        for failure in (OSError('write failed'), asyncio.CancelledError()):
            clock = [0.0]
            performance = ws_proxy._RemoteRelayPerformance(clock=lambda: clock[0])
            quality = {'bytes_to_browser': 0}
            class FailedDestination(MessageStream):
                async def send(self, message):
                    clock[0] += 0.250
                    raise failure
            with self.subTest(failure=type(failure).__name__), self.assertRaises(type(failure)):
                await ws_proxy._relay(MessageStream([b'\x00jpeg']), FailedDestination(), quality, performance)
            snapshot = performance.snapshot()
            self.assertEqual(snapshot['frame_messages'], 0)
            self.assertEqual(snapshot['frame_bytes'], 0)
            self.assertEqual(snapshot['received_frame_messages'], 1)
            self.assertEqual(snapshot['received_frame_bytes'], 5)
            self.assertEqual(quality['bytes_to_browser'], 0)
            self.assertEqual(snapshot['send_wait_current_ms'], 0)
            self.assertEqual(snapshot['send_wait_latest_ms'], 250)

    async def test_pong_performance_stays_rate_limited_and_read_only(self):
        performance = ws_proxy._RemoteRelayPerformance(clock=lambda: 0.0)
        performance.begin_send()
        performance.finish_send(b'\x00jpeg', True)
        source = MessageStream(['{"type":"relay_ping","nonce":"first"}', '{"type":"relay_ping","nonce":"too-soon"}'])
        destination = MessageStream()
        with patch.object(ws_proxy.load_controller, 'snapshot', return_value={'loop_lag_seconds': 0.125}), \
                patch.object(ws_proxy.db, '_get') as read, patch.object(ws_proxy.db, '_patch') as write:
            await ws_proxy._relay_browser_to_agent(source, destination,
                {'id': 'session', 'capabilities': {'view': True}}, performance, {'agent_rtt_ms': 619})
        self.assertEqual(destination.sent, [])
        self.assertEqual(len(source.sent), 1)
        pong = json.loads(source.sent[0])
        self.assertEqual(pong['nonce'], 'first')
        self.assertEqual(pong['performance']['agent_rtt_ms'], 619)
        self.assertEqual(pong['performance']['relay_loop_lag_ms'], 125)
        self.assertEqual(pong['performance']['frame_messages'], 1)
        self.assertTrue(all(value is None or type(value) in (int, float) for value in pong['performance'].values()))
        read.assert_not_called()
        write.assert_not_called()

    async def test_telemetry_is_not_returned_without_view_capability(self):
        source = MessageStream(['{"type":"relay_ping","nonce":"first"}'])
        performance = ws_proxy._RemoteRelayPerformance()
        await ws_proxy._relay_browser_to_agent(source, MessageStream(),
            {'id': 'session', 'capabilities': {'view': False}}, performance, {'agent_rtt_ms': 1})
        self.assertEqual(source.sent, [])

    def test_optional_metrics_cannot_expose_strings_or_nonfinite_values(self):
        performance = ws_proxy._RemoteRelayPerformance()
        for value in ('sensitive-text', True, -1, math.nan, math.inf, 10**1000):
            with self.subTest(value_type=type(value).__name__):
                snapshot = performance.snapshot(value, value)
                self.assertIsNone(snapshot['agent_rtt_ms'])
                self.assertIsNone(snapshot['relay_loop_lag_ms'])
        with patch.object(ws_proxy.load_controller, 'snapshot', side_effect=RuntimeError('unavailable')):
            snapshot = ws_proxy._remote_performance_snapshot(performance, {'agent_rtt_ms': 7})
        self.assertEqual(snapshot['agent_rtt_ms'], 7)
        self.assertIsNone(snapshot['relay_loop_lag_ms'])
        self.assertIsNone(performance.snapshot(relay_loop_lag_seconds=1e308)['relay_loop_lag_ms'])

    async def test_existing_quality_receipt_includes_numeric_aggregates_with_one_write(self):
        from unittest.mock import AsyncMock
        performance = ws_proxy._RemoteRelayPerformance(clock=lambda: 0.0)
        performance.begin_send()
        performance.finish_send(b'\x00jpeg', True)
        pong = asyncio.get_running_loop().create_future()
        pong.set_result(None)
        agent = SimpleNamespace(ping=AsyncMock(return_value=pong))
        quality = {'transport': 'server_relay', 'bytes_to_browser': 5, 'agent_rtt_ms': None}
        calls = []
        async def off_loop(function, *args):
            calls.append(function)
            return function(*args)
        with patch.object(ws_proxy.asyncio, 'to_thread', new=off_loop), \
                patch.object(ws_proxy.asyncio, 'sleep', new=AsyncMock(side_effect=asyncio.CancelledError)) as sleep, \
                patch.object(ws_proxy.load_controller, 'snapshot', return_value={'loop_lag_seconds': 0.025}), \
                patch.object(ws_proxy.db, '_get') as read, patch.object(ws_proxy.db, '_patch') as write:
            with self.assertRaises(asyncio.CancelledError):
                await ws_proxy._measure_remote_quality(agent, {'id': 'session', 'company_id': 'tenant'}, quality, performance)
        write.assert_called_once()
        receipt = write.call_args.args[1]['connection_quality']
        self.assertEqual(receipt['performance']['frame_messages'], 1)
        self.assertEqual(receipt['performance']['frame_bytes'], 5)
        self.assertEqual(receipt['performance']['relay_loop_lag_ms'], 25)
        self.assertIsInstance(receipt['performance']['agent_rtt_ms'], int)
        self.assertNotIn('performance', quality)
        self.assertEqual(receipt['performance']['agent_performance_history'], [])
        self.assertTrue(all(value is None or type(value) in (int, float)
                            for key, value in receipt['performance'].items()
                            if key != 'agent_performance_history'))
        self.assertEqual(len(calls), 1)
        read.assert_not_called()
        sleep.assert_awaited_once_with(15)

    async def test_only_authorized_control_inputs_count_and_successful_sends_are_timed(self):
        clock = [0.0]
        counters = ws_proxy._RemoteRelayPerformance(clock=lambda: clock[0])
        packets = ['{"type":"mousemove","x":51,"y":52}',
                   '{"type":"keydown","key":"private-input"}',
                   '{"type":"viewport_size","w":1024,"h":768}',
                   '{"type":"unknown","contents":"private-input"}',
                   b'private-input', 'invalid-json']
        class TimedDestination(MessageStream):
            async def send(self, message):
                clock[0] += 0.012
                await super().send(message)
        destination = TimedDestination()
        with patch.object(ws_proxy.db, '_get') as read, patch.object(ws_proxy.db, '_patch') as write:
            await ws_proxy._relay_browser_to_agent(MessageStream(packets), destination,
                {'id': 'session', 'capabilities': {'control': True, 'view': True}}, counters)
        self.assertEqual(destination.sent, packets[:3])
        snapshot = counters.snapshot()
        self.assertEqual(snapshot['accepted_input_messages'], 2)
        self.assertEqual(snapshot['forwarded_input_messages'], 2)
        self.assertEqual(snapshot['input_send_samples'], 2)
        self.assertEqual(snapshot['input_send_wait_mean_ms'], 12)
        self.assertEqual(snapshot['input_send_wait_max_ms'], 12)
        self.assertNotIn('private-input', json.dumps(snapshot))
        self.assertTrue(all(value is None or type(value) in (int, float) for value in snapshot.values()))
        read.assert_not_called()
        write.assert_not_called()

    async def test_rejected_control_input_never_counts_or_reaches_agent(self):
        counters = ws_proxy._RemoteRelayPerformance()
        destination = MessageStream()
        await ws_proxy._relay_browser_to_agent(MessageStream(['{"type":"mousedown","x":1,"y":2}']),
            destination, {'id': 'session', 'capabilities': {'view': True, 'control': False}}, counters)
        self.assertEqual(destination.sent, [])
        self.assertEqual(counters.snapshot()['accepted_input_messages'], 0)
        self.assertEqual(counters.snapshot()['forwarded_input_messages'], 0)
        self.assertEqual(counters.snapshot()['input_send_samples'], 0)

    async def test_blocked_control_send_counts_acceptance_before_completion(self):
        clock = [10.0]
        counters = ws_proxy._RemoteRelayPerformance(clock=lambda: clock[0])
        entered, release = asyncio.Event(), asyncio.Event()
        class BlockedDestination(MessageStream):
            async def send(self, message):
                entered.set()
                await release.wait()
        task = asyncio.create_task(ws_proxy._relay_browser_to_agent(
            MessageStream(['{"type":"scroll","dy":1}']), BlockedDestination(),
            {'id': 'session', 'capabilities': {'control': True}}, counters))
        try:
            await asyncio.wait_for(entered.wait(), 1)
            clock[0] += 0.250
            snapshot = counters.snapshot()
            self.assertEqual(snapshot['accepted_input_messages'], 1)
            self.assertEqual(snapshot['forwarded_input_messages'], 0)
            self.assertEqual(snapshot['input_send_wait_current_ms'], 250)
            release.set()
            await asyncio.wait_for(task, 1)
            snapshot = counters.snapshot()
            self.assertEqual(snapshot['forwarded_input_messages'], 1)
            self.assertEqual(snapshot['input_send_wait_current_ms'], 0)
            self.assertEqual(snapshot['input_send_wait_latest_ms'], 250)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def test_failed_control_send_retains_acceptance_without_success(self):
        for failure in (OSError('write failed'), asyncio.CancelledError()):
            clock = [0.0]
            counters = ws_proxy._RemoteRelayPerformance(clock=lambda: clock[0])
            class FailedDestination(MessageStream):
                async def send(self, message):
                    clock[0] += 0.100
                    raise failure
            with self.subTest(failure=type(failure).__name__), self.assertRaises(type(failure)):
                await ws_proxy._relay_browser_to_agent(MessageStream(['{"type":"mouseup"}']),
                    FailedDestination(), {'id': 'session', 'capabilities': {'control': True}}, counters)
            snapshot = counters.snapshot()
            self.assertEqual(snapshot['accepted_input_messages'], 1)
            self.assertEqual(snapshot['forwarded_input_messages'], 0)
            self.assertEqual(snapshot['input_send_wait_current_ms'], 0)
            self.assertEqual(snapshot['input_send_wait_latest_ms'], 100)

    def test_control_send_timing_ring_is_bounded_and_contains_only_numbers(self):
        clock = [0.0]
        counters = ws_proxy._RemoteRelayPerformance(clock=lambda: clock[0])
        for number in range(1, 1001):
            counters.begin_input_send()
            clock[0] += number / 1000
            counters.finish_input_send(True)
        snapshot = counters.snapshot()
        self.assertEqual(snapshot['accepted_input_messages'], 1000)
        self.assertEqual(snapshot['forwarded_input_messages'], 1000)
        self.assertEqual(snapshot['input_send_samples'], counters.SAMPLE_LIMIT)
        self.assertEqual(snapshot['input_send_wait_mean_ms'], 940.5)
        self.assertTrue(all(type(value) is float for value in counters._input_send_waits))


class RemoteAuthorityProjectionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.session = dict(id="session /&one", endpoint_id="endpoint /&one", company_id="tenant /&one",
                            admin_id="admin /&one", status="active", owner_access_token_version=3,
                            consent_required=True, consent_status="approved")
        self.owner = dict(id=self.session["admin_id"], company_id=self.session["company_id"],
                          role="technician", is_active=True, access_token_version=3)

    def test_live_authority_selects_only_required_fields_and_scopes_the_session(self):
        with patch.object(ws_proxy.db, "_get", side_effect=[[dict(self.session)], [dict(self.owner)]]) as read, \
                patch.object(ws_proxy.db, "get_remote_session") as full_session, \
                patch.object(ws_proxy.db, "get_admin_by_id") as full_admin:
            self.assertTrue(ws_proxy._remote_authority_current(self.session, True))
        session_path, admin_path = [call.args[0] for call in read.call_args_list]
        session_query, admin_query = [parse_qs(urlsplit(path).query) for path in (session_path, admin_path)]
        self.assertEqual(urlsplit(session_path).path, "remote_sessions")
        self.assertEqual(session_query, {
            "select": ["id,endpoint_id,company_id,admin_id,status,owner_access_token_version,consent_required,consent_status"],
            "id": ["eq." + self.session["id"]], "company_id": ["eq." + self.session["company_id"]],
            "endpoint_id": ["eq." + self.session["endpoint_id"]], "limit": ["1"],
        })
        self.assertEqual(urlsplit(admin_path).path, "admin_users")
        self.assertEqual(admin_query, {"select": ["id,is_active,role,company_id,access_token_version"],
                                      "id": ["eq." + self.owner["id"]], "limit": ["1"]})
        full_session.assert_not_called()
        full_admin.assert_not_called()

    def test_projection_keeps_owner_scope_version_role_and_consent_checks(self):
        cases = [
            (None, self.owner, True, False),
            (dict(self.session, status="closed"), self.owner, True, False),
            (dict(self.session, endpoint_id="other"), self.owner, True, False),
            (dict(self.session, company_id="other"), self.owner, True, False),
            (dict(self.session, admin_id="other"), self.owner, True, False),
            (dict(self.session, admin_id=None), self.owner, True, False),
            (self.session, None, True, False),
            (self.session, dict(self.owner, is_active=False), True, False),
            (self.session, dict(self.owner, role="viewer"), True, False),
            (self.session, dict(self.owner, company_id="other"), True, False),
            (self.session, dict(self.owner, access_token_version=4), True, False),
            (dict(self.session, owner_access_token_version=2), self.owner, True, False),
            (dict(self.session, consent_status="pending"), self.owner, True, False),
            (dict(self.session, consent_status="denied"), self.owner, True, False),
            (dict(self.session, consent_status="pending"), self.owner, False, True),
            (dict(self.session, consent_required=False, consent_status="not_required"), self.owner, True, True),
        ]
        cases.extend((self.session, dict(self.owner, role=role), True, True)
                     for role in ("technician", "branch_admin", "company_admin"))
        cases.append((self.session, dict(self.owner, role="superadmin", company_id=None), True, True))
        for current, owner, require_consent, expected in cases:
            with self.subTest(current=current, owner=owner, require_consent=require_consent), \
                    patch.object(ws_proxy.db, "_get", side_effect=[[] if current is None else [dict(current)],
                                                                  [] if owner is None else [dict(owner)]]):
                self.assertEqual(ws_proxy._remote_authority_current(self.session, require_consent), expected)

    def test_each_authority_check_reads_fresh_owner_state_without_cache(self):
        with patch.object(ws_proxy.db, "_get", side_effect=[
                [dict(self.session)], [dict(self.owner)],
                [dict(self.session)], [dict(self.owner, access_token_version=4)],
        ]) as read:
            self.assertTrue(ws_proxy._remote_authority_current(self.session, True))
            self.assertFalse(ws_proxy._remote_authority_current(self.session, True))
        self.assertEqual(read.call_count, 4)

    async def test_periodic_authority_projection_observes_later_session_revocation(self):
        with patch.object(ws_proxy.db, "_get", side_effect=[
                [dict(self.session)], [dict(self.owner)], [dict(self.session, status="closed")],
        ]) as read, patch.object(ws_proxy, "REMOTE_AUTH_CHECK_SECONDS", 0.001):
            await asyncio.wait_for(ws_proxy._watch_remote_authority(self.session), timeout=1)
        self.assertEqual(read.call_count, 3)

    async def test_projected_authority_store_failures_remain_fail_closed(self):
        for results in ([RuntimeError("session read unavailable")],
                        [[dict(self.session)], RuntimeError("owner read unavailable")]):
            with self.subTest(results=results), patch.object(ws_proxy.db, "_get", side_effect=results):
                await asyncio.wait_for(ws_proxy._watch_remote_authority(self.session), timeout=1)


class RelayLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        ws_proxy._pairs.clear()
        ws_proxy._home_pairs.clear()

    async def asyncTearDown(self):
        ws_proxy._pairs.clear()
        ws_proxy._home_pairs.clear()

    def test_pair_timeout_covers_heartbeat_consent_and_helper_startup(self):
        self.assertGreaterEqual(ws_proxy.PAIR_TIMEOUT, 30 + 60 + 20)

    async def test_buffered_frame_burst_leaves_time_for_other_remote_tasks(self):
        packets = [bytes([number]) * 100 for number in range(20)]
        source, destination = MessageStream(packets), MessageStream()
        progress = []
        async def observe():
            while len(destination.sent) < len(packets):
                progress.append(len(destination.sent))
                await asyncio.sleep(0)
        observer = asyncio.create_task(observe())
        quality = {'bytes_to_browser': 0}
        await ws_proxy._relay(source, destination, quality)
        await observer
        self.assertEqual(destination.sent, packets)
        self.assertEqual(quality['bytes_to_browser'], sum(map(len, packets)))
        self.assertTrue(any(0 < count < len(packets) for count in progress))

    async def test_buffered_control_burst_leaves_time_for_other_remote_tasks(self):
        messages = ['{"type":"monitor_select","id":0}'] * 20
        source, destination = MessageStream(messages), MessageStream()
        progress = []
        async def observe():
            while len(destination.sent) < len(messages):
                progress.append(len(destination.sent))
                await asyncio.sleep(0)
        observer = asyncio.create_task(observe())
        await ws_proxy._relay_browser_to_agent(source, destination,
            {'id': 'session', 'capabilities': {'view': True}})
        await observer
        self.assertEqual(destination.sent, messages)
        self.assertTrue(any(0 < count < len(messages) for count in progress))

    def test_relay_compression_default_opt_out_and_invalid_configuration(self):
        with patch.dict(ws_proxy.os.environ):
            ws_proxy.os.environ.pop('WARDEN_REMOTE_WS_COMPRESSION', None)
            self.assertEqual(ws_proxy._relay_compression(), 'deflate')
        with patch.dict(ws_proxy.os.environ, {'WARDEN_REMOTE_WS_COMPRESSION': 'none'}):
            self.assertIsNone(ws_proxy._relay_compression())
        with patch.dict(ws_proxy.os.environ, {'WARDEN_REMOTE_WS_COMPRESSION': ' deflate '}):
            self.assertEqual(ws_proxy._relay_compression(), 'deflate')
        with patch.dict(ws_proxy.os.environ, {'WARDEN_REMOTE_WS_COMPRESSION': 'invalid'}):
            with self.assertRaises(ValueError):
                ws_proxy._relay_compression()

    async def test_live_listener_preserves_binary_frames_with_negotiated_compression(self):
        import websockets
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        stop = threading.Event()
        async def echo(connection):
            async for message in connection:
                await connection.send(message)
        ws_proxy._ready.clear()
        with patch.object(ws_proxy, 'PROXY_HOST', '127.0.0.1'), \
                patch.object(ws_proxy, 'PROXY_PORT', port), \
                patch.object(ws_proxy, '_handle', echo), \
                patch('services.lifecycle.stopping', stop), \
                patch.object(ws_proxy.load_controller, 'sample'), \
                patch.dict(ws_proxy.os.environ, {'WARDEN_REMOTE_WS_COMPRESSION': 'deflate'}):
            ws_proxy.start()
            try:
                self.assertTrue(await asyncio.to_thread(ws_proxy._ready.wait, 3))
                for compression in ['deflate', None]:
                    with self.subTest(client_compression=compression):
                        async with websockets.connect(f'ws://127.0.0.1:{port}', compression=compression) as client:
                            self.assertEqual(bool(client.protocol.extensions), compression == 'deflate')
                            packet = bytes(range(256)) * 64
                            await client.send(packet)
                            self.assertEqual(await client.recv(), packet)
            finally:
                stop.set()
                async def closed():
                    while ws_proxy._ready.is_set():
                        await asyncio.sleep(.01)
                await asyncio.wait_for(closed(), 3)

    @patch.object(ws_proxy.db, "get_remote_session")
    @patch.object(ws_proxy.db, "get_endpoint_by_api_key_hash")
    async def test_agent_cannot_attach_to_closed_session(self, get_endpoint, get_session):
        get_endpoint.return_value = {"id": "endpoint-1"}
        get_session.return_value = {
            "id": "session-1", "endpoint_id": "endpoint-1", "status": "closed",
        }
        websocket = FakeWebSocket()

        await ws_proxy._handle_agent(websocket, "session-1", "key")

        self.assertEqual(websocket.closed_with, (1008, "session not active"))
        self.assertNotIn("session-1", ws_proxy._pairs)

    @patch.object(ws_proxy.db, "mark_remote_session_failed")
    @patch.object(ws_proxy.db, "get_remote_session")
    @patch.object(ws_proxy.db, "get_endpoint_by_api_key_hash")
    async def test_agent_cannot_attach_before_required_consent(
        self, get_endpoint, get_session, mark_failed,
    ):
        get_endpoint.return_value = {"id": "endpoint-1"}
        get_session.return_value = {
            "id": "session-1", "endpoint_id": "endpoint-1", "status": "active",
            "consent_required": True, "consent_status": "pending",
        }
        websocket = FakeWebSocket()
        await ws_proxy._handle_agent(websocket, "session-1", "key")
        self.assertEqual(websocket.closed_with, (1008, "consent required"))
        mark_failed.assert_called_once_with(
            "session-1", "remote user consent was not approved",
        )

    async def test_browser_relay_enforces_session_capabilities(self):
        source = MessageStream([
            '{"type":"viewport_size","width":100}',
            '{"type":"mousemove","x":1}',
            '{"type":"clipboard_write","text":"secret"}',
            '{"type":"process_kill","pid":1}',
            '{"type":"unknown_future_operation"}',
        ])
        destination = MessageStream()
        session = {
            "id": "session-1",
            "capabilities": {
                "view": True, "control": False, "clipboard": False,
                "process_manager": False, "file_transfer": False, "reboot": False,
            },
        }
        await ws_proxy._relay_browser_to_agent(source, destination, session)
        self.assertEqual(destination.sent, ['{"type":"viewport_size","width":100}'])

    async def test_relay_ping_is_read_only_and_not_forwarded(self):
        source=MessageStream(['{"type":"relay_ping","nonce":"sample"}','{"type":"relay_ping","nonce":"duplicate"}'])
        destination=MessageStream()
        await ws_proxy._relay_browser_to_agent(source,destination,dict(id='session',capabilities=dict(view=True)))
        self.assertEqual(destination.sent,[])
        self.assertEqual(len(source.sent),1)
        self.assertIn('relay_pong',source.sent[0])

    async def test_quality_probe_failure_does_not_end_relay(self):
        from unittest.mock import AsyncMock
        browser=FakeWebSocket();agent=FakeWebSocket()
        pair=ws_proxy._Pair();pair.agent_ws=agent;pair.ready.set()
        async def failed_probe(*args):raise RuntimeError('probe failed')
        async def relay(*args):await asyncio.sleep(0.01)
        session=dict(id='session',endpoint_id='endpoint',company_id='tenant',status='active')
        self.enterContext(patch.object(ws_proxy, "_remote_authority_current", return_value=True))
        with patch.object(ws_proxy.db,'get_remote_session_by_token',return_value=session),patch.object(ws_proxy,'_attach_peer',new=AsyncMock(return_value=pair)),patch.object(ws_proxy,'_measure_remote_quality',new=failed_probe),patch.object(ws_proxy,'_relay_browser_to_agent',new=relay),patch.object(ws_proxy,'_relay',new=relay),patch.object(ws_proxy,'_close_session'),patch.object(ws_proxy,'_cleanup_pair',new=AsyncMock()):
            await ws_proxy._handle_browser(browser,'endpoint','token')
        self.assertTrue(pair.done.is_set())
        self.assertEqual(browser.closed_with,(1000,''))

    @patch.object(ws_proxy, "PAIR_TIMEOUT", 0.001)
    @patch.object(ws_proxy.db, "mark_remote_session_failed")
    @patch.object(ws_proxy.db, "get_remote_session")
    @patch.object(ws_proxy.db, "get_endpoint_by_api_key_hash")
    async def test_agent_wait_timeout_closes_session_and_cleans_pair(
        self, get_endpoint, get_session, mark_failed,
    ):
        get_endpoint.return_value = {"id": "endpoint-1"}
        get_session.return_value = {
            "id": "session-1", "endpoint_id": "endpoint-1", "status": "active",
        }
        websocket = FakeWebSocket()

        await ws_proxy._handle_agent(websocket, "session-1", "key")

        mark_failed.assert_called_once_with(
            "session-1", "browser did not connect in time",
        )
        self.assertEqual(websocket.closed_with, (1011, "browser did not connect in time"))
        self.assertNotIn("session-1", ws_proxy._pairs)

    @patch.object(ws_proxy.db, "get_home_node_by_key_hash")
    @patch.object(ws_proxy.db, "get_home_p2p_session")
    async def test_home_target_key_must_match_session_node(self, get_session, get_node):
        get_session.return_value = {
            "id": "home-session", "node_id": "node-a", "status": "answered",
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat(),
        }
        get_node.return_value = {"id": "node-b"}
        websocket = FakeWebSocket()
        await ws_proxy._handle_home_target(websocket, "home-session", "node-key")
        self.assertEqual(websocket.closed_with, (1008, "unauthorized"))
        self.assertNotIn("home-session", ws_proxy._home_pairs)

    @patch.object(ws_proxy.db, "get_endpoint_by_api_key_hash")
    @patch.object(ws_proxy.db, "get_home_p2p_session")
    async def test_expired_home_session_rejects_endpoint(self, get_session, get_endpoint):
        get_session.return_value = {
            "id": "home-session", "endpoint_id": "endpoint-a", "status": "answered",
            "expires_at": (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
        }
        get_endpoint.return_value = {"id": "endpoint-a"}
        websocket = FakeWebSocket()
        await ws_proxy._handle_home_initiator(
            websocket, "home-session", "endpoint", "agent-key",
        )
        self.assertEqual(websocket.closed_with, (1008, "expired or invalid session"))


if __name__ == "__main__":
    unittest.main()
