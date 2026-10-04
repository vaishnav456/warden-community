"""Remote sessions database operations."""


def create_remote_session(endpoint_id, admin_id, company_id):
    import db as _db
    return _db._rpc("create_or_get_remote_session", {
        "p_endpoint_id": str(endpoint_id),
        "p_company_id": str(company_id),
        "p_admin_id": str(admin_id) if admin_id else None,
    })

def update_remote_session_controls(session_id, access_mode, capabilities, reason, consent_required):
    import db as _db
    remote = _db.get_remote_session(session_id)
    owner = _db.get_admin_by_id(remote.get("admin_id")) if remote and remote.get("admin_id") else None
    if not owner or not owner.get("is_active"):
        raise ValueError("Remote session owner is not active")
    from flask import g, has_request_context
    authenticated = getattr(g, "admin", None) if has_request_context() else None
    if authenticated:
        if str(authenticated.get("id")) != str(remote.get("admin_id")):
            raise ValueError("Remote session owner does not match requester")
        if int(authenticated.get("access_token_version") or 0) != int(owner.get("access_token_version") or 0):
            raise ValueError("Remote requester was revoked during session creation")
    rows = _db._patch(f"remote_sessions?id=eq.{_db._q(session_id)}", {
        "access_mode": access_mode,
        "capabilities": capabilities,
        "reason": reason or None,
        "consent_required": bool(consent_required),
        "consent_status": "pending" if consent_required else "not_required",
        "owner_access_token_version": int(owner.get("access_token_version") or 0),
    })
    return rows[0] if isinstance(rows, list) and rows else None

def close_remote_session(session_id):
    import db as _db
    _db._patch(f"remote_sessions?id=eq.{_db._q(session_id)}", {
        "status": "closed",
        "ended_at": _db._now_iso(),
        "vnc_token": None,
    })

def get_remote_sessions(endpoint_id, limit=20):
    import db as _db
    return _db._get(
        f"remote_sessions?select=*,admin_users(full_name,email)"
        f"&endpoint_id=eq.{_db._q(endpoint_id)}"
        f"&order=started_at.desc&limit={limit}"
    )

def get_remote_session(session_id):
    import db as _db
    rows = _db._get(f"remote_sessions?id=eq.{_db._q(session_id)}&limit=1")
    return rows[0] if rows else None

def get_active_remote_session(endpoint_id, max_age_seconds=3700):
    """Return a plausible active session for an endpoint.

    The relay has a one-hour hard limit, so an older row cannot still be live.
    The former two-minute cutoff was much too short and created conflicting
    sessions during normal support calls; having no cutoff at all made rows
    left by an old crash reusable forever.
    """
    import db as _db
    rows = _db._get(
        f"remote_sessions?endpoint_id=eq.{_db._q(endpoint_id)}&status=eq.active"
        f"&order=started_at.desc&limit=1"
    )
    if not rows:
        return None
    session = rows[0]
    started = _db._parse_dt_iso(session.get("started_at"))
    if not started:
        return None
    age = (_db.datetime.now(_db.timezone.utc) - started).total_seconds()
    if age > max_age_seconds:
        _db.mark_remote_session_failed(session["id"], "stale remote session expired")
        return None
    return session

def close_all_active_remote_sessions(reason="remote relay restarted"):
    """Invalidate relay rows on process start.

    WebSocket pairs live only in this process, so none can survive a server
    restart. Leaving their bearer tokens active makes the UI reuse sessions
    that have no corresponding relay or agent connection.
    """
    import db as _db
    return _db._patch("remote_sessions?status=eq.active", {
        "status": "closed",
        "ended_at": _db._now_iso(),
        "fail_reason": reason,
        "vnc_token": None,
    })

def _parse_dt_iso(dt_str):
    import db as _db
    if not dt_str:
        return None
    try:
        return _db.datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
    except Exception:
        return None

def update_remote_session_token(session_id, vnc_token, novnc_path):
    import db as _db
    _db._patch(f"remote_sessions?id=eq.{_db._q(session_id)}", {
        "vnc_token":    vnc_token,
        "novnc_path":   novnc_path,
    })

def get_remote_session_by_token(token: str):
    import db as _db
    rows = _db._get(f"remote_sessions?vnc_token=eq.{_db._q(token)}&limit=1")
    return rows[0] if rows else None

def mark_remote_session_failed(session_id, reason):
    """Called when the agent reports its side of a remote-desktop pairing
    attempt failed (see routes/agent_api.py's remote_relay_failed()) — closes
    the session with the real reason recorded, so the viewer can show it
    within a few seconds instead of only finding out via ws_proxy's 60s
    PAIR_TIMEOUT generic timeout message."""
    import db as _db
    _db._patch(f"remote_sessions?id=eq.{_db._q(session_id)}", {
        "status": "closed",
        "fail_reason": reason,
        "ended_at": _db._now_iso(),
        "vnc_token": None,
    })

def create_remote_session_event(session_id, company_id, admin_id, event_type, body, metadata=None):
    import db as _db
    rows = _db._post("remote_session_events", {
        "session_id": session_id,
        "company_id": company_id,
        "admin_id": admin_id,
        "event_type": event_type,
        "body": body,
        "metadata": metadata or {},
    })
    return rows[0] if isinstance(rows, list) and rows else rows

def get_remote_session_events(session_id, limit=200):
    import db as _db
    return _db._get(
        f"remote_session_events?session_id=eq.{_db._q(session_id)}"
        f"&order=created_at.asc&limit={int(limit)}"
    )

def update_remote_session_support_state(session_id, **fields):
    import db as _db
    allowed = {"consent_status", "recording_status", "reconnect_until"}
    data = {key: value for key, value in fields.items() if key in allowed}
    if data:
        _db._patch(f"remote_sessions?id=eq.{_db._q(session_id)}", data)

def create_remote_support_link(endpoint_id, company_id, created_by, token_hash, expires_at, max_uses=1):
    import db as _db
    rows = _db._post("remote_support_links", {
        "endpoint_id": endpoint_id,
        "company_id": company_id,
        "created_by": created_by,
        "token_hash": token_hash,
        "expires_at": expires_at,
        "max_uses": max_uses,
    })
    return rows[0] if isinstance(rows, list) and rows else rows

def get_remote_support_link_by_hash(token_hash):
    import db as _db
    rows = _db._get(f"remote_support_links?token_hash=eq.{_db._q(token_hash)}&limit=1")
    return rows[0] if rows else None

def claim_remote_support_link(token_hash):
    import db as _db
    rows = _db._rpc("claim_remote_support_link", {"p_token_hash": token_hash})
    return rows[0] if isinstance(rows, list) and rows else None

def release_remote_support_link_claim(link_id):
    """Return one claimed support-link use if session/job creation fails."""
    import db as _db
    return bool(_db._rpc("release_remote_support_link_claim", {"p_link_id": link_id}))
