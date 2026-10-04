"""Home storage database operations."""


def get_home_nodes(company_id):
    import db as _db
    return _db._get(f"home_storage_nodes?company_id=eq.{_db._q(company_id)}&order=priority.asc,name.asc")

def create_home_node(data):
    import db as _db
    rows = _db._post("home_storage_nodes", data)
    return rows[0] if rows else None

def update_home_node(node_id, company_id, data):
    import db as _db
    rows = _db._patch(
        f"home_storage_nodes?id=eq.{_db._q(node_id)}&company_id=eq.{_db._q(company_id)}",
        {**data, "updated_at": _db._now_iso()},
    )
    return rows[0] if rows else None

def get_home_node_by_key_hash(key_hash):
    import db as _db
    rows = _db._get(f"home_storage_nodes?node_key_hash=eq.{_db._q(key_hash)}&limit=1")
    return rows[0] if rows else None

def update_home_node_heartbeat(node_id, fields):
    import db as _db
    return _db._patch(f"home_storage_nodes?id=eq.{_db._q(node_id)}", {
        **fields, "status": "online", "last_seen": _db._now_iso(), "updated_at": _db._now_iso(),
    })

def create_home_p2p_session(company_id, endpoint_id, node_id, offer_sdp):
    # Rendezvous rows contain short-lived network candidates, never file data,
    # credentials, grants, or encryption keys.
    import db as _db
    _db._delete(f"home_p2p_sessions?expires_at=lt.{_db._q(_db._now_iso())}")
    _db._delete(
        f"home_p2p_sessions?endpoint_id=eq.{_db._q(endpoint_id)}&node_id=eq.{_db._q(node_id)}"
        "&status=eq.offered"
    )
    rows = _db._post("home_p2p_sessions", {
        "company_id": company_id, "endpoint_id": endpoint_id,
        "node_id": node_id, "offer_sdp": offer_sdp,
        "expires_at": (_db.datetime.now(_db.timezone.utc) + _db.timedelta(minutes=2)).isoformat(),
    })
    return rows[0] if rows else None

def create_home_node_p2p_session(company_id, initiator_node_id, node_id, offer_sdp):
    import db as _db
    _db._delete(f"home_p2p_sessions?expires_at=lt.{_db._q(_db._now_iso())}")
    _db._delete(
        f"home_p2p_sessions?initiator_node_id=eq.{_db._q(initiator_node_id)}"
        f"&node_id=eq.{_db._q(node_id)}&status=eq.offered"
    )
    rows = _db._post("home_p2p_sessions", {
        "company_id": company_id, "initiator_node_id": initiator_node_id,
        "node_id": node_id, "offer_sdp": offer_sdp,
        "expires_at": (_db.datetime.now(_db.timezone.utc) + _db.timedelta(minutes=2)).isoformat(),
    })
    return rows[0] if rows else None

def get_home_p2p_session(session_id, endpoint_id=None, node_id=None, initiator_node_id=None):
    import db as _db
    query = f"home_p2p_sessions?id=eq.{_db._q(session_id)}"
    if endpoint_id:
        query += f"&endpoint_id=eq.{_db._q(endpoint_id)}"
    if node_id:
        query += f"&node_id=eq.{_db._q(node_id)}"
    if initiator_node_id:
        query += f"&initiator_node_id=eq.{_db._q(initiator_node_id)}"
    rows = _db._get(query + "&limit=1")
    return rows[0] if rows else None

def get_home_p2p_offers(node_id, limit=8):
    import db as _db
    _db._delete(f"home_p2p_sessions?expires_at=lt.{_db._q(_db._now_iso())}")
    return _db._get(
        f"home_p2p_sessions?node_id=eq.{_db._q(node_id)}&status=eq.offered"
        f"&expires_at=gt.{_db._q(_db._now_iso())}"
        "&select=id,endpoint_id,initiator_node_id,offer_sdp,expires_at"
        f"&order=created_at.asc&limit={max(1, min(int(limit), 20))}"
    )

def answer_home_p2p_session(session_id, node_id, answer_sdp):
    import db as _db
    rows = _db._patch(
        f"home_p2p_sessions?id=eq.{_db._q(session_id)}&node_id=eq.{_db._q(node_id)}"
        "&status=eq.offered",
        {"answer_sdp": answer_sdp, "status": "answered", "answered_at": _db._now_iso()},
    )
    return rows[0] if rows else None

def fail_home_p2p_session(session_id, node_id, message):
    import db as _db
    rows = _db._patch(
        f"home_p2p_sessions?id=eq.{_db._q(session_id)}&node_id=eq.{_db._q(node_id)}"
        "&status=eq.offered",
        {"status": "failed", "error_message": str(message or "P2P negotiation failed")[:500]},
    )
    return rows[0] if rows else None

def get_home_spaces(company_id):
    import db as _db
    return _db._get(
        f"home_spaces?company_id=eq.{_db._q(company_id)}"
        "&select=*,home_space_nodes(priority,writable,role,home_storage_nodes(*))&order=name.asc"
    )

def get_home_space(space_id):
    import db as _db
    rows = _db._get(
        f"home_spaces?id=eq.{_db._q(space_id)}"
        "&select=*,home_space_nodes(priority,writable,role,home_storage_nodes(*))&limit=1"
    )
    return rows[0] if rows else None

def create_home_space(data, memberships):
    import db as _db
    rows = _db._post("home_spaces", data)
    space = rows[0] if rows else None
    if space and memberships:
        _db._post("home_space_nodes", [
            {"space_id": space["id"], **membership}
            for membership in memberships
        ], prefer="return=minimal")
    return space

def update_home_space_topology(space_id, company_id, state):
    import db as _db
    rows = _db._patch(
        f"home_spaces?id=eq.{_db._q(space_id)}&company_id=eq.{_db._q(company_id)}",
        {"active_writer_state": state, "updated_at": _db._now_iso()},
    )
    return rows[0] if rows else None

def get_home_assignments(company_id):
    import db as _db
    return _db._get(
        f"home_assignments?company_id=eq.{_db._q(company_id)}"
        "&select=*,home_spaces(id,name)&order=created_at.desc"
    )

def create_home_assignment(data):
    import db as _db
    rows = _db._post("home_assignments", data)
    return rows[0] if rows else None

def update_home_assignment(assignment_id, company_id, data):
    import db as _db
    rows = _db._patch(
        f"home_assignments?id=eq.{_db._q(assignment_id)}&company_id=eq.{_db._q(company_id)}",
        data,
    )
    return rows[0] if rows else None

def delete_home_assignment(assignment_id, company_id):
    import db as _db
    _db._delete(f"home_assignments?id=eq.{_db._q(assignment_id)}&company_id=eq.{_db._q(company_id)}")

def log_home_access(company_id, endpoint_id, identity_id, space_id, node_id, action, detail=None):
    import db as _db
    return _db._post("home_access_log", {
        "company_id": company_id, "endpoint_id": endpoint_id,
        "identity_id": identity_id, "space_id": space_id, "node_id": node_id,
        "action": action, "detail": detail or {},
    }, prefer="return=minimal")
