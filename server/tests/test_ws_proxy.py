import asyncio
import pathlib
import sys
import unittest
from types import SimpleNamespace
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


class RelayLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        ws_proxy._pairs.clear()

    async def asyncTearDown(self):
        ws_proxy._pairs.clear()

    def test_pair_timeout_covers_heartbeat_consent_and_helper_startup(self):
        self.assertGreaterEqual(ws_proxy.PAIR_TIMEOUT, 30 + 60 + 20)

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


if __name__ == "__main__":
    unittest.main()
