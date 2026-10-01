"""
ws_proxy.py — WebSocket relay for remote screen-sharing sessions
-----------------------------------------------------------------
Listens on HOST:35021 (see config.py — 127.0.0.1 for a same-host reverse
proxy, 0.0.0.0 if fronted over a Docker network instead).
No VPN required. Both sides connect outbound to this relay:

  Browser → wss://<slug>.warden.example.com/remote-ws/<endpoint_id>
            with an HttpOnly, path-scoped warden_remote cookie
  Agent   → wss://warden.example.com/agent-relay/<session_id>
            with X-Agent-Key header

The reverse proxy (Caddy, nginx, ...) forwards both paths → ws://<HOST>:35021

Session pairing:
  Whichever side connects first waits long enough for the endpoint's normal
  heartbeat plus the attended-access consent window.
  Once both are live, frames and input events relay bidirectionally.
"""
import asyncio
import hashlib
import json
import logging
import threading
import time
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from urllib.parse import urlparse

import os

import websockets
import websockets.exceptions

import config
import db
import services.health_tracker as health_tracker

log = logging.getLogger("warden.ws_proxy")

# Same HOST env var gunicorn.conf.py binds to — keep both sockets on the
# same interface (loopback for the Caddy-fronted deployment, 0.0.0.0 when
# fronted by a reverse proxy over a Docker network instead).
PROXY_HOST = os.environ.get("HOST", "127.0.0.1")
PROXY_PORT = 35021
# An attended session can legitimately take one heartbeat (up to 30s), a
# 60-second local consent prompt, and remote-helper startup (up to 20s).
# The former 60-second pairing timeout closed the browser/session while the
# user was still deciding, which made the agent's later consent report fail
# with session_not_active. Keep a small network margin above that 110s path.
PAIR_TIMEOUT = 135
_ready = threading.Event()
_startup_error = None


# ── Session registry ──────────────────────────────────────────────────────────

class _Pair:
    __slots__ = ("browser_ws", "agent_ws", "ready", "done")

    def __init__(self):
        self.browser_ws = None
        self.agent_ws   = None
        self.ready      = asyncio.Event()
        self.done       = asyncio.Event()  # fired by browser side when relay ends


_pairs: dict[str, _Pair] = {}   # session_id → _Pair
_pairs_lock = asyncio.Lock()


class _HomePair:
    __slots__ = ("initiator_ws", "target_ws", "ready", "done")

    def __init__(self):
        self.initiator_ws = None
        self.target_ws = None
        self.ready = asyncio.Event()
        self.done = asyncio.Event()


_home_pairs: dict[str, _HomePair] = {}
_home_pairs_lock = asyncio.Lock()
_MAX_HOME_RELAY_PAIRS = 256


async def _get_or_create_pair(session_id: str) -> _Pair:
    async with _pairs_lock:
        if session_id not in _pairs:
            _pairs[session_id] = _Pair()
        return _pairs[session_id]


async def _cleanup_pair(session_id: str) -> None:
    async with _pairs_lock:
        _pairs.pop(session_id, None)


def _mark_session_failed(session_id: str, reason: str) -> None:
    """Best-effort status update; relay sockets must still be cleaned up if
    PostgREST is temporarily unavailable."""
    try:
        db.mark_remote_session_failed(session_id, reason)
    except Exception:
        log.exception("Could not mark remote session %s failed", session_id)


def _close_session(session_id: str) -> None:
    try:
        db.close_remote_session(session_id)
    except Exception:
        log.exception("Could not close remote session %s", session_id)


async def _attach_peer(session_id: str, side: str, websocket):
    """Atomically attach one peer; never overwrite a live authenticated peer."""
    async with _pairs_lock:
        pair = _pairs.setdefault(session_id, _Pair())
        attr = f"{side}_ws"
        existing = getattr(pair, attr)
        if existing is not None and not getattr(existing, "closed", False):
            return None
        setattr(pair, attr, websocket)
        return pair


async def _attach_home_peer(session_id: str, side: str, websocket):
    async with _home_pairs_lock:
        pair = _home_pairs.get(session_id)
        if pair is None:
            if len(_home_pairs) >= _MAX_HOME_RELAY_PAIRS:
                return None
            pair = _HomePair()
            _home_pairs[session_id] = pair
        attr = f"{side}_ws"
        existing = getattr(pair, attr)
        if existing is not None and not getattr(existing, "closed", False):
            return None
        setattr(pair, attr, websocket)
        return pair


async def _cleanup_home_pair(session_id: str) -> None:
    async with _home_pairs_lock:
        _home_pairs.pop(session_id, None)


# ── Relay helpers ─────────────────────────────────────────────────────────────

async def _relay(src, dst, quality=None) -> None:
    """Forward all messages from src → dst until the connection closes."""
    async for msg in src:
        await dst.send(msg)
        if quality is not None:
            quality['bytes_to_browser']+=len(msg.encode('utf-8') if isinstance(msg,str) else msg)


_REMOTE_MESSAGE_CAPABILITY = {
    "mousemove": "control", "mousedown": "control", "mouseup": "control",
    "scroll": "control", "keydown": "control", "keyup": "control",
    "ctrl_alt_del": "control", "monitor_select": "view",
    "viewport_size": "view", "clipboard_write": "clipboard",
    "process_list": "process_manager", "process_kill": "process_manager",
    "reboot_reconnect": "reboot", "drop_target_request": "file_transfer",
    "support_chat": "view",
}


async def _relay_browser_to_agent(src, dst, session) -> None:
    """Relay only operations granted to this immutable remote session.

    Hiding a toolbar button is not authorization: a browser can construct its
    own WebSocket frames.  This boundary sits directly in front of the agent.
    """
    capabilities = session.get("capabilities") or {
        "view": True, "control": True, "clipboard": True,
        "file_transfer": True, "process_manager": True, "reboot": True,
    }
    last_ping=0.0
    async for msg in src:
        if not isinstance(msg, str):
            log.warning("Dropped binary browser message for session %s", session.get("id"))
            continue
        try:
            payload = json.loads(msg)
            message_type = str(payload.get("type") or "")
        except (ValueError, TypeError, AttributeError):
            log.warning("Dropped malformed browser message for session %s", session.get("id"))
            continue
        if message_type=='relay_ping' and capabilities.get('view',False):
            nonce=payload.get('nonce')
            if isinstance(nonce,str) and len(nonce)<=64 and time.monotonic()-last_ping>=5:
                last_ping=time.monotonic()
                await src.send(json.dumps({'type':'relay_pong','nonce':nonce}))
            continue
        required = _REMOTE_MESSAGE_CAPABILITY.get(message_type)
        if not required or not capabilities.get(required, False):
            log.warning(
                "Blocked remote operation %s without %s capability (session %s)",
                message_type or "<missing>", required or "known-operation", session.get("id"),
            )
            continue
        await dst.send(msg)


# ── Browser-side handler ──────────────────────────────────────────────────────

async def _measure_remote_quality(agent_ws,session,quality):
    while True:
        try:
            start=time.monotonic()
            pong=await agent_ws.ping()
            await asyncio.wait_for(pong,5)
            quality['agent_rtt_ms']=round((time.monotonic()-start)*1000)
        except asyncio.CancelledError:
            raise
        except Exception:
            quality['agent_rtt_ms']=None
        quality['measured_at']=datetime.now(timezone.utc).isoformat()
        try:
            await asyncio.to_thread(db._patch,f"remote_sessions?id=eq.{db._q(session['id'])}&company_id=eq.{db._q(session['company_id'])}",{'connection_quality':dict(quality)})
        except asyncio.CancelledError:
            raise
        except Exception:
            log.warning('Remote quality receipt deferred for session %s',session['id'])
        await asyncio.sleep(15)

async def _handle_browser(websocket, endpoint_id: str, token: str) -> None:
    # Validate vnc_token against active session
    session = db.get_remote_session_by_token(token)
    if not session or str(session.get("endpoint_id", "")) != endpoint_id:
        log.warning("Invalid vnc_token for endpoint %s", endpoint_id)
        await websocket.close(1008, "invalid token")
        return

    if session.get("status") != "active":
        await websocket.close(1008, "session not active")
        return

    session_id = str(session["id"])
    pair = await _attach_peer(session_id, "browser", websocket)
    if pair is None:
        log.warning("Rejected duplicate browser peer for session %s", session_id)
        await websocket.close(1008, "browser already connected")
        return

    if pair.agent_ws:
        pair.ready.set()

    # Wait for the agent to connect
    try:
        await asyncio.wait_for(pair.ready.wait(), timeout=PAIR_TIMEOUT)
    except asyncio.TimeoutError:
        log.warning("Browser waiting for agent timed out (session %s)", session_id)
        # Wake an agent that attached first; otherwise it can remain parked
        # on pair.done for the full one-hour relay timeout after the browser
        # has already given up.
        pair.done.set()
        _mark_session_failed(session_id, "agent did not connect in time")
        await _cleanup_pair(session_id)
        try:
            await websocket.close(1011, "agent did not connect in time")
        except Exception:
            pass
        return

    agent_ws = pair.agent_ws
    if not agent_ws:
        # Rare: agent connected, signalled ready, then immediately closed
        await _cleanup_pair(session_id)
        try:
            await websocket.close(1011, "agent disconnected")
        except Exception:
            pass
        return

    log.info("Relay active: browser ↔ agent (session %s)", session_id)

    health_tracker.increment_connections()
    quality={'transport':'server_relay','bytes_to_browser':0,'agent_rtt_ms':None}
    quality_task=asyncio.create_task(_measure_remote_quality(agent_ws,session,quality))
    relay_tasks=[asyncio.create_task(_relay_browser_to_agent(websocket, agent_ws, session)),
                 asyncio.create_task(_relay(agent_ws, websocket,quality))]
    try:
        done, pending = await asyncio.wait(
            relay_tasks,
            return_when=asyncio.FIRST_COMPLETED,
        )
        for t in pending:
            t.cancel()
    except (OSError, websockets.exceptions.WebSocketException) as exc:
        log.warning("Relay error (session %s): %s", session_id, exc)
    finally:
        for task in relay_tasks:task.cancel()
        await asyncio.gather(*relay_tasks, return_exceptions=True)
        quality_task.cancel()
        await asyncio.gather(quality_task, return_exceptions=True)
        health_tracker.decrement_connections()
        # Signal agent side that relay is done before cleanup
        pair.done.set()
        _close_session(session_id)
        await _cleanup_pair(session_id)
        for ws in (websocket, agent_ws):
            try:
                await ws.close(1000)
            except Exception:
                pass


# ── Agent-side handler ────────────────────────────────────────────────────────

async def _handle_agent(websocket, session_id: str, api_key: str) -> None:
    # Validate API key
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    endpoint = db.get_endpoint_by_api_key_hash(key_hash)
    if not endpoint:
        log.warning("Agent relay: invalid api_key for session %s", session_id)
        await websocket.close(1008, "unauthorized")
        return

    # Match agent_auth_required's certificate boundary. Without this, turning
    # on REQUIRE_CLIENT_CERT protected HTTP agent APIs but left the privileged
    # remote-control WebSocket authenticating with the API key alone.
    if config.REQUIRE_CLIENT_CERT:
        if not config.TRUST_CLOUDFLARE:
            log.error("Agent relay mTLS requires trusted Cloudflare ingress")
            await websocket.close(1011, "relay certificate policy unavailable")
            return
        expected_fp = (endpoint.get("client_cert_fingerprint") or "").lower().replace(":", "")
        presented_fp = (
            websocket.request.headers.get("Cf-Client-Cert-Sha256", "")
            .lower().replace(":", "")
        )
        if not expected_fp or not presented_fp or expected_fp != presented_fp:
            log.warning("Agent relay: client certificate mismatch for endpoint %s", endpoint["id"])
            await websocket.close(1008, "unauthorized")
            return

    # A valid API key only proves WHICH endpoint is calling — it doesn't
    # prove that endpoint is the one this session_id was actually created
    # for. Without this check, any endpoint's valid key could attach as
    # the agent side of ANY session_id and receive the browser operator's
    # input / substitute whatever desktop it sends back, hijacking a
    # remote-support session meant for a different machine entirely.
    session = db.get_remote_session(session_id)
    if not session or str(session.get("endpoint_id")) != str(endpoint["id"]):
        log.warning(
            "Agent relay: endpoint %s attempted to attach to session %s "
            "belonging to a different endpoint", endpoint["id"], session_id,
        )
        await websocket.close(1008, "unauthorized")
        return
    if session.get("status") != "active":
        log.warning("Agent relay rejected non-active session %s", session_id)
        await websocket.close(1008, "session not active")
        return
    if session.get("consent_required") and session.get("consent_status") != "approved":
        log.warning("Agent relay rejected session %s without endpoint consent", session_id)
        _mark_session_failed(session_id, "remote user consent was not approved")
        await websocket.close(1008, "consent required")
        return

    pair = await _attach_peer(session_id, "agent", websocket)
    if pair is None:
        log.warning("Rejected duplicate agent peer for session %s", session_id)
        await websocket.close(1008, "agent already connected")
        return

    if pair.browser_ws:
        pair.ready.set()

    # If the agent arrives first, bound how long it can occupy a socket/pair
    # without a browser. Previously this path waited for pair.done for an
    # hour, and timed-out pairs were never removed from the registry.
    try:
        await asyncio.wait_for(pair.ready.wait(), timeout=PAIR_TIMEOUT)
    except asyncio.TimeoutError:
        log.warning("Agent waiting for browser timed out (session %s)", session_id)
        pair.done.set()
        _mark_session_failed(session_id, "browser did not connect in time")
        await _cleanup_pair(session_id)
        try:
            await websocket.close(1011, "browser did not connect in time")
        except Exception:
            pass
        return

    # Once paired, the browser-side relay owns the agent websocket reader.
    # Hold this handler until that relay finishes, then always remove the
    # registry entry so stale sockets never block a later valid peer.
    try:
        await asyncio.wait_for(pair.done.wait(), timeout=3600)
    except asyncio.TimeoutError:
        log.warning("Agent relay reached hard timeout (session %s)", session_id)
        pair.done.set()
        _mark_session_failed(session_id, "remote relay reached time limit")
        for ws in (websocket, pair.browser_ws):
            if ws is not None:
                try:
                    await ws.close(1000, "remote relay reached time limit")
                except Exception:
                    pass
    finally:
        await _cleanup_pair(session_id)


def _home_session_active(session) -> bool:
    if not session or session.get("status") not in {"offered", "answered", "failed"}:
        return False
    try:
        expires = datetime.fromisoformat(str(session.get("expires_at") or "").replace("Z", "+00:00"))
        return expires > datetime.now(timezone.utc)
    except (TypeError, ValueError):
        return False


async def _handle_home_initiator(websocket, session_id: str, kind: str, key: str) -> None:
    session = db.get_home_p2p_session(session_id)
    if not _home_session_active(session):
        await websocket.close(1008, "expired or invalid session")
        return
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    if kind == "endpoint":
        principal = db.get_endpoint_by_api_key_hash(key_hash)
        expected = session.get("endpoint_id")
    else:
        principal = db.get_home_node_by_key_hash(key_hash)
        expected = session.get("initiator_node_id")
    if not principal or str(principal.get("id")) != str(expected):
        await websocket.close(1008, "unauthorized")
        return
    pair = await _attach_home_peer(session_id, "initiator", websocket)
    if pair is None:
        await websocket.close(1013, "relay capacity or duplicate peer")
        return
    if pair.target_ws:
        pair.ready.set()
    try:
        await asyncio.wait_for(pair.ready.wait(), timeout=PAIR_TIMEOUT)
        target = pair.target_ws
        if target is None:
            raise asyncio.TimeoutError
        log.info("Encrypted Home relay active (%s session %s)", kind, session_id)
        health_tracker.increment_connections()
        done, pending = await asyncio.wait(
            [asyncio.ensure_future(_relay(websocket, target)),
             asyncio.ensure_future(_relay(target, websocket))],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
    except asyncio.TimeoutError:
        log.warning("Home relay pairing timed out (session %s)", session_id)
    except (OSError, websockets.exceptions.WebSocketException) as exc:
        log.warning("Home relay error (session %s): %s", session_id, exc)
    finally:
        if pair.ready.is_set():
            health_tracker.decrement_connections()
        pair.done.set()
        await _cleanup_home_pair(session_id)
        for ws in (websocket, pair.target_ws):
            if ws is not None:
                try:
                    await ws.close(1000)
                except Exception:
                    pass


async def _handle_home_target(websocket, session_id: str, key: str) -> None:
    session = db.get_home_p2p_session(session_id)
    if not _home_session_active(session):
        await websocket.close(1008, "expired or invalid session")
        return
    node = db.get_home_node_by_key_hash(hashlib.sha256(key.encode()).hexdigest())
    if not node or str(node.get("id")) != str(session.get("node_id")):
        await websocket.close(1008, "unauthorized")
        return
    pair = await _attach_home_peer(session_id, "target", websocket)
    if pair is None:
        await websocket.close(1013, "relay capacity or duplicate peer")
        return
    if pair.initiator_ws:
        pair.ready.set()
    try:
        await asyncio.wait_for(pair.done.wait(), timeout=PAIR_TIMEOUT + 600)
    except asyncio.TimeoutError:
        pair.done.set()
    finally:
        await _cleanup_home_pair(session_id)


# ── Main dispatcher ───────────────────────────────────────────────────────────

async def _handle(websocket) -> None:
    raw_path = websocket.request.path
    parsed   = urlparse(raw_path)
    parts    = [p for p in parsed.path.strip("/").split("/") if p]

    # /remote-ws/<endpoint_id> with a short-lived, HttpOnly, path-scoped
    # cookie. Keeping bearer material out of the URL prevents disclosure in
    # reverse-proxy, browser-history and edge request logs.
    if len(parts) >= 2 and parts[0] == "remote-ws":
        endpoint_id = parts[1]
        cookies = SimpleCookie()
        try:
            cookies.load(websocket.request.headers.get("Cookie", ""))
        except Exception:
            cookies = SimpleCookie()
        token_cookie = cookies.get("warden_remote")
        token = token_cookie.value if token_cookie else ""
        if not token:
            await websocket.close(1008, "missing token")
            return
        await _handle_browser(websocket, endpoint_id, token)

    # /agent-relay/<session_id> with X-Agent-Key header
    elif len(parts) >= 2 and parts[0] == "agent-relay":
        session_id = parts[1]
        api_key = websocket.request.headers.get("X-Agent-Key", "")
        if not api_key:
            await websocket.close(1008, "missing key")
            return
        await _handle_agent(websocket, session_id, api_key)

    # Warden Home direct-first fallback. The relay sees only the already
    # encrypted inner mTLS byte stream; endpoint/node credentials are bound
    # to the short-lived rendezvous row before either socket can attach.
    elif len(parts) >= 3 and parts[0] == "home-relay":
        side, session_id = parts[1], parts[2]
        if side == "endpoint":
            key = websocket.request.headers.get("X-Agent-Key", "")
            if not key:
                await websocket.close(1008, "missing key")
                return
            await _handle_home_initiator(websocket, session_id, "endpoint", key)
        elif side == "source":
            key = websocket.request.headers.get("X-Warden-Home-Key", "")
            if not key:
                await websocket.close(1008, "missing key")
                return
            await _handle_home_initiator(websocket, session_id, "source", key)
        elif side == "node":
            key = websocket.request.headers.get("X-Warden-Home-Key", "")
            if not key:
                await websocket.close(1008, "missing key")
                return
            await _handle_home_target(websocket, session_id, key)
        else:
            await websocket.close(1008, "bad relay side")

    else:
        log.warning("WS relay: unrecognised path %s", raw_path)
        await websocket.close(1008, "bad path")


# ── Startup ───────────────────────────────────────────────────────────────────

def start() -> None:
    """Start the WebSocket relay in a background daemon thread."""

    def _run() -> None:
        global _startup_error
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def _main() -> None:
            async with websockets.serve(_handle, PROXY_HOST, PROXY_PORT):
                log.info("WS relay listening on %s:%d", PROXY_HOST, PROXY_PORT)
                _startup_error = None
                _ready.set()
                await asyncio.Future()

        try:
            loop.run_until_complete(_main())
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            _startup_error = str(exc)
            _ready.clear()
            log.exception("WS relay failed")
        finally:
            _ready.clear()
            loop.close()

    t = threading.Thread(target=_run, daemon=True, name="warden-ws-relay")
    t.start()
    log.info("WebSocket relay thread started")


def is_ready() -> bool:
    """True only after port 35021 has been bound successfully."""
    return _ready.is_set() and _startup_error is None
