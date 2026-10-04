"""Identities database operations."""


def get_warden_identities(company_id):
    import db as _db
    rows = _db._get(
        "warden_identities?select=id,company_id,username,login_email,display_name,is_admin,"
        "is_enabled,password_version,password_setup_required,offline_access_hours,session_version,conditional_access,profile_photo_mime,"
        "created_at,updated_at,password_changed_at,"
        "warden_identity_assignments(id,endpoint_id,status,password_version,"
        "last_job_id,last_error,assigned_at,updated_at,last_synced_at,"
        "endpoints(id,hostname,display_name,status,branch_id,is_active))"
        f"&company_id=eq.{_db._q(company_id)}&order=display_name.asc,username.asc"
    )
    company = _db.get_company_by_id(company_id)
    for row in rows:
        for assignment in row.get("warden_identity_assignments") or []:
            if assignment.get("endpoints"):
                assignment["endpoints"] = _db._decrypt_endpoint(
                    assignment["endpoints"], company,
                )
    return rows

def get_warden_identity(identity_id, company_id):
    import db as _db
    rows = _db._get(
        f"warden_identities?id=eq.{_db._q(identity_id)}&company_id=eq.{_db._q(company_id)}"
        "&select=*&limit=1"
    )
    return rows[0] if rows else None

def get_warden_identity_for_login(company_id, endpoint_id, username):
    import db as _db
    login = _db._q(username)
    rows = _db._get(
        "warden_identities?select=id,company_id,username,login_email,display_name,password_hash,"
        "is_admin,is_enabled,password_version,password_setup_required,offline_access_hours,session_version,"
        "failed_attempts,locked_until,conditional_access,"
        "warden_identity_assignments!inner(id,endpoint_id,status,password_version)"
        f"&company_id=eq.{_db._q(company_id)}&or=(username.ilike.{login},login_email.ilike.{login})"
        f"&warden_identity_assignments.endpoint_id=eq.{_db._q(endpoint_id)}&limit=1"
    )
    return rows[0] if rows else None

def record_warden_login_failure(identity_id, lock_after=5, lock_minutes=15):
    import db as _db
    return _db._rpc("record_warden_login_failure", {
        "p_identity_id": str(identity_id), "p_lock_after": int(lock_after),
        "p_lock_minutes": int(lock_minutes),
    })

def record_warden_login_success(identity_id):
    import db as _db
    return _db._rpc("record_warden_login_success", {"p_identity_id": str(identity_id)})

def log_warden_identity_login(company_id, endpoint_id, username, outcome,
                              identity_id=None, reason=None, source_ip=None,
                              offline_grant_hours=None):
    import db as _db
    return _db._post("warden_identity_login_events", {
        "company_id": company_id, "identity_id": identity_id,
        "endpoint_id": endpoint_id, "username": username,
        "outcome": outcome, "reason": reason,
        "source_ip": source_ip or None,
        "offline_grant_hours": offline_grant_hours,
    }, prefer="return=minimal")

def get_warden_identity_login_events(company_id, limit=50):
    import db as _db
    rows = _db._get(
        "warden_identity_login_events?select=id,identity_id,endpoint_id,username,"
        "outcome,reason,source_ip,offline_grant_hours,created_at,"
        "endpoints(hostname,display_name)&company_id=eq."
        f"{_db._q(company_id)}&order=created_at.desc&limit={max(1, min(int(limit), 200))}"
    )
    company = _db.get_company_by_id(company_id)
    for row in rows:
        if row.get("endpoints"):
            row["endpoints"] = _db._decrypt_endpoint(row["endpoints"], company)
    return rows

def create_warden_identity(company_id, username, display_name, password_hash,
                           is_admin, created_by):
    import db as _db
    rows = _db._post("warden_identities", {
        "company_id": company_id,
        "username": username,
        "display_name": display_name or None,
        "password_hash": password_hash,
        "is_admin": bool(is_admin),
        "created_by": created_by,
    })
    return rows[0] if rows else None

def create_warden_identity_with_jobs(company, username, display_name, password_hash,
                                     is_admin, created_by, endpoint_ids, payload,
                                     profile_photo="", profile_photo_mime=""):
    import db as _db
    rows = _db._rpc("create_warden_identity_and_jobs", {
        "p_company_id": str(company["id"]), "p_username": username,
        "p_display_name": display_name, "p_password_hash": password_hash,
        "p_is_admin": bool(is_admin), "p_created_by": str(created_by),
        "p_endpoint_ids": [str(value) for value in endpoint_ids],
        "p_profile_photo": profile_photo or None,
        "p_profile_photo_mime": profile_photo_mime or None,
        "p_encrypted_payload": _db.encrypt_field(company, payload, "job.payload"),
    }) or []
    return rows[0] if rows else None

def create_warden_identity_with_setup_and_jobs(
    company, username, login_email, display_name, placeholder_password_hash, is_admin,
    created_by, endpoint_ids, payload, setup_token_hash, setup_expires_at,
    profile_photo="", profile_photo_mime="",
):
    import db as _db
    rows = _db._rpc("create_warden_identity_with_setup_and_jobs", {
        "p_company_id": str(company["id"]), "p_username": username,
        "p_login_email": login_email,
        "p_display_name": display_name,
        "p_placeholder_password_hash": placeholder_password_hash,
        "p_is_admin": bool(is_admin), "p_created_by": str(created_by),
        "p_endpoint_ids": [str(value) for value in endpoint_ids],
        "p_profile_photo": profile_photo or None,
        "p_profile_photo_mime": profile_photo_mime or None,
        "p_encrypted_payload": _db.encrypt_field(company, payload, "job.payload"),
        "p_setup_token_hash": setup_token_hash,
        "p_setup_expires_at": setup_expires_at,
    }) or []
    return rows[0] if rows else None

def get_warden_identity_for_password_setup(token_hash):
    import db as _db
    rows = _db._get(
        "warden_identities?select=id,username,login_email,display_name,password_setup_required,"
        "password_setup_expires_at&password_setup_token_hash=eq."
        f"{_db._q(token_hash)}&limit=1"
    )
    return rows[0] if rows else None

def complete_warden_identity_password_setup(token_hash, password_hash):
    import db as _db
    rows = _db._rpc("complete_warden_identity_password_setup", {
        "p_token_hash": token_hash, "p_password_hash": password_hash,
    }) or []
    return rows[0] if rows else None

def rotate_warden_identity_password(company, identity_id, password_hash,
                                    created_by, payload):
    import db as _db
    return _db._rpc("rotate_warden_identity_password", {
        "p_company_id": str(company["id"]), "p_identity_id": str(identity_id),
        "p_password_hash": password_hash, "p_created_by": str(created_by),
        "p_encrypted_payload": _db.encrypt_field(company, payload, "job.payload"),
    })

def set_warden_identity_enabled(company, identity_id, enabled, created_by, payload):
    import db as _db
    return _db._rpc("set_warden_identity_enabled", {
        "p_company_id": str(company["id"]), "p_identity_id": str(identity_id),
        "p_enabled": bool(enabled), "p_created_by": str(created_by),
        "p_encrypted_payload": _db.encrypt_field(company, payload, "job.payload"),
    })

def reassign_warden_identity(company, identity_id, endpoint_ids, created_by,
                             provision_payload, revoke_payload):
    import db as _db
    rows = _db._rpc("reassign_warden_identity", {
        "p_company_id": str(company["id"]), "p_identity_id": str(identity_id),
        "p_endpoint_ids": [str(value) for value in endpoint_ids],
        "p_created_by": str(created_by),
        "p_provision_payload": _db.encrypt_field(company, provision_payload, "job.payload"),
        "p_revoke_payload": _db.encrypt_field(company, revoke_payload, "job.payload"),
    }) or []
    return rows[0] if rows else None

def update_warden_identity(identity_id, company_id, fields):
    import db as _db
    return _db._patch(
        f"warden_identities?id=eq.{_db._q(identity_id)}&company_id=eq.{_db._q(company_id)}",
        {**fields, "updated_at": _db._now_iso()},
    )

def get_warden_identity_assignment(identity_id, endpoint_id):
    import db as _db
    rows = _db._get(
        f"warden_identity_assignments?identity_id=eq.{_db._q(identity_id)}"
        f"&endpoint_id=eq.{_db._q(endpoint_id)}&limit=1"
    )
    return rows[0] if rows else None

def get_active_warden_usernames_for_endpoint(endpoint_id):
    import db as _db
    rows = _db._get(
        "warden_identity_assignments?select=status,warden_identities(username,is_enabled)"
        f"&endpoint_id=eq.{_db._q(endpoint_id)}&status=eq.active"
    )
    usernames = []
    for row in rows:
        identity = row.get("warden_identities") or {}
        if identity.get("is_enabled", True) and identity.get("username"):
            usernames.append(str(identity["username"]))
    return list(dict.fromkeys(usernames))

def get_managed_warden_usernames_for_endpoint(endpoint_id):
    """Return every non-revoked centralized identity on an endpoint.

    This intentionally includes disabled and pending assignments. Those local
    shadow accounts remain directory-owned and must not be modified through
    the endpoint's ordinary local-user controls.
    """
    import db as _db
    rows = _db._get(
        "warden_identity_assignments?select=status,warden_identities(username)"
        f"&endpoint_id=eq.{_db._q(endpoint_id)}&status=neq.revoked"
    )
    usernames = []
    for row in rows:
        identity = row.get("warden_identities") or {}
        if identity.get("username"):
            usernames.append(str(identity["username"]))
    return list(dict.fromkeys(usernames))

def upsert_warden_identity_assignment(identity_id, endpoint_id, status,
                                      password_version, job_id=None, error=None):
    import db as _db
    existing = _db.get_warden_identity_assignment(identity_id, endpoint_id)
    data = {
        "status": status,
        "password_version": int(password_version),
        "last_job_id": job_id,
        "last_error": error,
        "updated_at": _db._now_iso(),
    }
    if status == "active":
        data["last_synced_at"] = _db._now_iso()
    if existing:
        rows = _db._patch(f"warden_identity_assignments?id=eq.{_db._q(existing['id'])}", data)
        return rows[0] if rows else None
    data.update({"identity_id": identity_id, "endpoint_id": endpoint_id})
    rows = _db._post("warden_identity_assignments", data)
    return rows[0] if rows else None

def mark_warden_assignment_job_result(job_id, succeeded, error=None, success_status="active"):
    import db as _db
    rows = _db._get(
        f"warden_identity_assignments?last_job_id=eq.{_db._q(job_id)}&select=id&limit=1"
    )
    if not rows:
        return None
    data = {
        "status": success_status if succeeded else "failed",
        "last_error": None if succeeded else str(error or "Agent operation failed")[:1000],
        "updated_at": _db._now_iso(),
    }
    if succeeded:
        data["last_synced_at"] = _db._now_iso()
    return _db._patch(f"warden_identity_assignments?id=eq.{_db._q(rows[0]['id'])}", data)
