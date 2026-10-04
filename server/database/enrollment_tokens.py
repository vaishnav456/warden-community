"""Enrollment tokens database operations."""


def create_enrollment_token(company_id, branch_id, created_by, expires_hours=24, max_uses=1,
                            profile_id=None):
    """max_uses=1 (the default) is single-use: burned after exactly one
    enrollment, same as this always behaved. A larger integer allows that
    many enrollments before the token deactivates; max_uses=None means
    unlimited enrollments until expires_hours — e.g. a GPO/SCCM/Intune-
    deployed MSI meant to enroll many machines from one reusable token."""
    import db as _db
    token = _db.secrets.token_urlsafe(32)
    token_hash = _db.hashlib.sha256(token.encode()).hexdigest()
    expires_at = (
        _db.datetime.now(_db.timezone.utc) + _db.timedelta(hours=expires_hours)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    data = {
        "company_id": company_id,
        "branch_id": branch_id,
        "token_hash": token_hash,
        "expires_at": expires_at,
        "created_by": created_by,
        "max_uses": max_uses,
    }
    if profile_id:
        data["profile_id"] = profile_id
    rows = _db._post("enrollment_tokens", data)
    rec = rows[0] if (rows and isinstance(rows, list)) else rows
    return token, rec

def get_enrollment_token_by_hash(token_hash, include_inactive=False):
    import db as _db
    path = f"enrollment_tokens?token_hash=eq.{_db._q(token_hash)}&limit=1"
    if not include_inactive:
        path += f"&is_active=eq.true&expires_at=gt.{_db._q(_db._now_iso())}"
    rows = _db._get(path)
    return rows[0] if rows else None

def get_enrollment_tokens(company_id, limit=50):
    import db as _db
    return _db._get(
        f"enrollment_tokens?company_id=eq.{_db._q(company_id)}"
        f"&order=created_at.desc&limit={limit}"
    )

def get_enrollment_token(token_id):
    import db as _db
    rows = _db._get(f"enrollment_tokens?id=eq.{_db._q(token_id)}&limit=1")
    return rows[0] if rows else None

def claim_enrollment_token(token_id):
    """Atomically claim one use of an enrollment token via the
    claim_enrollment_token_use() Postgres function (db-init/02-schema.sql),
    which row-locks the token for the duration of the check-and-increment
    so concurrent /enroll requests against the SAME token — expected and
    normal for a reusable, GPO/SCCM/Intune-deployed token enrolling many
    machines in a tight window — serialize correctly instead of racing
    past each other's use_count read. Returns True if this call actually
    won a use, False if the token is exhausted/expired/inactive — the
    caller must treat that as "invalid token", not proceed to create an
    endpoint."""
    import db as _db
    return bool(_db._rpc("claim_enrollment_token_use", {"p_token_id": token_id}))

def release_enrollment_token(token_id):
    """Return a claimed token use after enrollment fails before an endpoint
    is created. The database function serializes this with concurrent claims
    and safely reactivates the token when capacity remains."""
    import db as _db
    return bool(_db._rpc("release_enrollment_token_use", {"p_token_id": token_id}))

def deactivate_enrollment_token(token_id):
    """Prevent use of a token whose installer/build request could not be
    created. Keep the row for audit/history instead of deleting it."""
    import db as _db
    return _db._patch(
        f"enrollment_tokens?id=eq.{_db._q(token_id)}",
        {"is_active": False},
    )

def burn_enrollment_token(token_id, endpoint_id):
    """Record which endpoint actually used this (already-claimed — see
    claim_enrollment_token) token. Not itself racy: is_active was already
    flipped exclusively by the winning claim_enrollment_token() call."""
    import db as _db
    _db._patch(f"enrollment_tokens?id=eq.{_db._q(token_id)}", {
        "used_by_endpoint_id": str(endpoint_id),
    })
