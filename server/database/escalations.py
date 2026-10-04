"""Escalations database operations."""


def _decrypt_escalation(esc, company=None):
    import db as _db
    if esc is None:
        return None
    company = company or _db.get_company_by_id(esc["company_id"])
    if esc.get("payload") is not None:
        esc["payload"] = _db.decrypt_field(company, esc["payload"], "escalation.payload")
    if esc.get("reason") is not None:
        esc["reason"] = _db.decrypt_field(company, esc["reason"], "escalation.reason")
    if esc.get("result_log") is not None:
        esc["result_log"] = _db.decrypt_field(company, esc["result_log"], "escalation.result-log")
    return esc

def get_escalation_requests(company_id, status=None, branch_id=None, limit=50, offset=0):
    import db as _db
    path = (
        f"escalation_requests?company_id=eq.{_db._q(company_id)}"
        f"&order=requested_at.desc&limit={limit}&offset={offset}"
    )
    if status == "waiting":
        path += "&status=in.(pending,pending_secondary)"
        path += f"&expires_at=gt.{_db._q(_db._now_iso())}"
    elif status:
        path += f"&status=eq.{_db._q(status)}"
    if branch_id:
        path += f"&branch_id=eq.{_db._q(branch_id)}"
    rows = _db._get(path)
    company = _db.get_company_by_id(company_id)
    return [_db._decrypt_escalation(e, company) for e in rows]

def get_escalation_request(req_id):
    import db as _db
    rows = _db._get(f"escalation_requests?id=eq.{_db._q(req_id)}&limit=1")
    if not rows:
        return None
    return _db._decrypt_escalation(rows[0])

def create_escalation_request(company_id, branch_id, endpoint_id, windows_user,
                               operation, payload, reason, requires_dual=False,
                               requested_by=None):
    import db as _db
    company = _db.get_company_by_id(company_id)
    expires_at = (
        _db.datetime.now(_db.timezone.utc) +
        _db.timedelta(minutes=_db.config.ESCALATION_WINDOW_MINUTES)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    data = {
        "company_id": company_id,
        "branch_id": branch_id,
        "endpoint_id": endpoint_id,
        "windows_user": windows_user,
        "operation": operation,
        "payload": _db.encrypt_field(company, payload, "escalation.payload") if payload is not None else None,
        "reason": _db.encrypt_field(company, reason, "escalation.reason") if reason is not None else None,
        "status": "pending",
        "expires_at": expires_at,
        "requires_dual_approval": requires_dual,
        "requested_by": requested_by,
    }
    if operation == "INSTALL_APP":
        from services.package_storage import installation
        with installation(company_id, payload):
            rows = _db._post("escalation_requests", data)
    elif operation == "FILE_PUSH":
        from services.tenant_storage import admission
        with admission(company_id, len((data["payload"] or "").encode("utf-8")) + 4096):
            rows = _db._post("escalation_requests", data)
    else:
        rows = _db._post("escalation_requests", data)
    esc = rows[0] if (rows and isinstance(rows, list)) else rows
    if esc:
        esc["payload"] = payload
        esc["reason"] = reason
    return esc

def approve_escalation(req_id, admin_id, expected_status, is_secondary=False):
    """Approve an escalation request, but only if it is still in
    `expected_status`. This is a compare-and-swap guard: two concurrent
    approve requests can both read the same pre-approval status and both
    pass the caller's status check before either write commits — without
    the `status=eq.<expected_status>` filter below, both would then also
    both see status=='approved' afterward and both create a job for a
    single approval action.

    Returns (token, updated_row) on success, or (None, None) if another
    request already changed the status first (the filtered PATCH matched
    zero rows) — the caller should treat that as "lost the race", not
    retry-and-approve-again.
    """
    import db as _db
    import secrets as _s, hashlib as _hl
    token = _s.token_urlsafe(32)
    token_hash = _hl.sha256(token.encode()).hexdigest()
    token_expires = (
        _db.datetime.now(_db.timezone.utc) + _db.timedelta(minutes=30)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    req = _db.get_escalation_request(req_id)
    if req and req.get("requested_by") and str(req["requested_by"]) == str(admin_id):
        return None, None
    if is_secondary and req and req.get("reviewed_by") and str(req["reviewed_by"]) == str(admin_id):
        return None, None
    # The database function locks the row and repeats both independence
    # checks. Application checks above give callers a clean response; the DB
    # guard prevents a race or alternate code path bypassing the rule.
    rows = _db._rpc("approve_escalation_request", {
        "p_request_id": req_id,
        "p_admin_id": admin_id,
        "p_expected_status": expected_status,
        "p_is_secondary": is_secondary,
        "p_token_hash": token_hash,
        "p_token_expires_at": token_expires,
    })
    if not rows:
        return None, None
    # rows[0] comes straight back from PostgREST with payload/reason still
    # ciphertext — decrypt before handing it to callers (e.g. the
    # escalation_card.html partial renders req.payload/req.reason directly).
    company = _db.get_company_by_id(req["company_id"]) if req else None
    return token, _db._decrypt_escalation(rows[0], company)

def deny_escalation(req_id, admin_id):
    import db as _db
    _db._patch(f"escalation_requests?id=eq.{_db._q(req_id)}", {
        "status": "denied",
        "reviewed_by": admin_id,
        "reviewed_at": _db._now_iso(),
    })

def complete_escalation(req_id, result_log, exit_code):
    import db as _db
    company = _db._get_escalation_company(req_id)
    _db._patch(f"escalation_requests?id=eq.{_db._q(req_id)}", {
        "status": "completed",
        "result_log": _db.encrypt_field(company, result_log, "escalation.result-log") if result_log is not None else None,
        "result_exit": exit_code,
    })

def _get_escalation_company(req_id):
    import db as _db
    rows = _db._get(f"escalation_requests?id=eq.{_db._q(req_id)}&select=company_id&limit=1")
    if not rows:
        return None
    return _db.get_company_by_id(rows[0]["company_id"])

def expire_stale_escalations():
    import db as _db
    _db._patch(
        f"escalation_requests?status=in.(pending,pending_secondary)&expires_at=lt.{_db._q(_db._now_iso())}",
        {"status": "expired"}
    )

def count_pending_escalations(company_id, branch_id=None):
    import db as _db
    path = f"escalation_requests?company_id=eq.{_db._q(company_id)}&status=eq.pending&select=id"
    if branch_id:
        path += f"&branch_id=eq.{_db._q(branch_id)}"
    rows = _db._get(path)
    return len(rows)
