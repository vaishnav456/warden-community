import asyncio
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
