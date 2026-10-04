"""Sessions database operations."""


def create_refresh_token(admin_id, token_hash, ip, user_agent, expires_at,
                         absolute_expires_at):
    import db as _db
    rows = _db._rpc("create_refresh_session", {
        "p_admin_id": admin_id,
        "p_token_hash": token_hash,
        "p_ip_address": ip,
        "p_user_agent": (user_agent or "")[:500],
        "p_expires_at": expires_at,
        "p_absolute_expires_at": absolute_expires_at,
        "p_max_sessions": _db.config.MAX_CONCURRENT_SESSIONS,
    })
    return rows[0] if (rows and isinstance(rows, list)) else rows

def rotate_refresh_token(old_token_hash, new_token_hash, ip, user_agent, expires_at):
    import db as _db
    rows = _db._rpc("rotate_refresh_session", {
        "p_old_token_hash": old_token_hash,
        "p_new_token_hash": new_token_hash,
        "p_ip_address": ip,
        "p_user_agent": (user_agent or "")[:500],
        "p_expires_at": expires_at,
        "p_idle_minutes": _db.config.SESSION_IDLE_MINUTES,
    })
    return rows[0] if (rows and isinstance(rows, list)) else rows

def get_refresh_token(token_hash):
    import db as _db
    rows = _db._get(f"refresh_tokens?token_hash=eq.{_db._q(token_hash)}&revoked=eq.false&limit=1")
    return rows[0] if rows else None

def revoke_refresh_token(token_id):
    import db as _db
    _db._patch(f"refresh_tokens?id=eq.{_db._q(token_id)}", {
        "revoked": True,
        "revoked_at": _db._now_iso(),
    })

def revoke_all_tokens_for_admin(admin_id):
    import db as _db
    _db._rpc("revoke_admin_sessions", {"p_admin_id": str(admin_id)})

def count_active_sessions(admin_id):
    import db as _db
    rows = _db._get(
        f"refresh_tokens?admin_id=eq.{_db._q(admin_id)}&revoked=eq.false"
        f"&expires_at=gt.{_db._q(_db._now_iso())}&select=id"
    )
    return len(rows)
