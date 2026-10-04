"""Windows users database operations."""


def get_windows_users(endpoint_id):
    import db as _db
    return _db._get(
        "windows_users?select=id,endpoint_id,username,display_name,sid,principal_name,"
        "account_type,domain_name,is_admin,is_enabled,present,first_seen,last_synced,"
        f"profile_photo_mime&endpoint_id=eq.{_db._q(endpoint_id)}"
        f"&present=eq.true&order=username.asc"
    )

def get_windows_user(user_id):
    import db as _db
    rows = _db._get(f"windows_users?id=eq.{_db._q(user_id)}&limit=1")
    return rows[0] if rows else None

def get_company_windows_users(company_id, branch_id=None):
    """Return current Windows accounts with endpoint context in one query."""
    import db as _db
    company = _db.get_company_by_id(company_id)
    endpoint_filter = f"endpoints.company_id=eq.{_db._q(company_id)}"
    if branch_id:
        endpoint_filter += f"&endpoints.branch_id=eq.{_db._q(branch_id)}"
    rows = _db._get(
        "windows_users?select=id,endpoint_id,username,display_name,sid,"
        "principal_name,account_type,domain_name,is_admin,is_enabled,"
        "first_seen,last_synced,profile_photo_mime,endpoints!inner(id,hostname,display_name,"
        f"branch_id,status,company_id,is_active)&present=eq.true&{endpoint_filter}"
        "&endpoints.is_active=eq.true"
        "&order=username.asc"
    )
    for row in rows:
        if row.get("endpoints"):
            row["endpoints"] = _db._decrypt_endpoint(row["endpoints"], company)
    return rows

def replace_windows_users(endpoint_id, users):
    """Atomically mark missing accounts absent and upsert the current scan."""
    import db as _db
    return _db._rpc("replace_windows_users", {
        "p_endpoint_id": endpoint_id,
        "p_users": users,
    })

def upsert_windows_user(endpoint_id, username, is_admin, is_enabled, display_name=None,
                        profile_photo=None):
    import db as _db
    rows = _db._get(f"windows_users?endpoint_id=eq.{_db._q(endpoint_id)}&username=eq.{_db._q(username)}&limit=1")
    data = {
        "is_admin": is_admin,
        "is_enabled": is_enabled,
        "present": True,
        "last_synced": _db._now_iso(),
    }
    if display_name:
        data["display_name"] = display_name
    if profile_photo:
        data["profile_photo"] = profile_photo
        data["profile_photo_mime"] = "image/png"
    if rows:
        _db._patch(f"windows_users?endpoint_id=eq.{_db._q(endpoint_id)}&username=eq.{_db._q(username)}", data)
    else:
        data.update({"endpoint_id": endpoint_id, "username": username})
        _db._post("windows_users", data)

def delete_windows_user(endpoint_id, username):
    import db as _db
    _db._delete(f"windows_users?endpoint_id=eq.{_db._q(endpoint_id)}&username=eq.{_db._q(username)}")

def set_windows_user_state(endpoint_id, username, is_enabled=None, is_admin=None):
    """Optimistic update after a CREATE_USER/DISABLE_USER/ENABLE_USER/
    GRANT_ELEVATION/REVOKE_ELEVATION job completes, so the Users tab
    reflects Warden's own action immediately without waiting on a separate
    COLLECT_USERS scan. Only patches the row if it already exists — a full
    COLLECT_USERS scan is still what establishes a row's existence and
    other real fields (display_name) in the first place."""
    import db as _db
    rows = _db._get(f"windows_users?endpoint_id=eq.{_db._q(endpoint_id)}&username=eq.{_db._q(username)}&limit=1")
    if not rows:
        return
    data = {}
    if is_enabled is not None:
        data["is_enabled"] = is_enabled
    if is_admin is not None:
        data["is_admin"] = is_admin
    if data:
        _db._patch(f"windows_users?endpoint_id=eq.{_db._q(endpoint_id)}&username=eq.{_db._q(username)}", data)
