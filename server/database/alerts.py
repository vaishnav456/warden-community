"""Alerts database operations."""


def get_alerts(company_id, resolved=False, branch_id=None, limit=50, offset=0, snoozed=False, severity=None, endpoint_id=None):
    import db as _db
    path = (
        f"alerts?company_id=eq.{_db._q(company_id)}"
        f"&is_resolved=eq.{str(resolved).lower()}"
        f"&order=created_at.desc&limit={limit}&offset={offset}"
    )
    path += "&select=*,endpoints(id,hostname,display_name)"
    if severity:
        path += f"&severity=eq.{_db._q(severity)}"
    if endpoint_id:
        path += f"&endpoint_id=eq.{_db._q(endpoint_id)}"
    if branch_id:
        path += f"&branch_id=eq.{_db._q(branch_id)}"
    if snoozed and not resolved:
        path += f"&snoozed_until=gt.{_db._q(_db._now_iso())}"
    elif not resolved:
        path += f"&or=(snoozed_until.is.null,snoozed_until.lte.{_db._q(_db._now_iso())})"
    company = _db.get_company_by_id(company_id)
    return [_db._decrypt_alert(row, company) for row in _db._get(path)]

def get_alert(alert_id):
    import db as _db
    rows = _db._get(f"alerts?id=eq.{_db._q(alert_id)}&select=*,endpoints(id,hostname,display_name)&limit=1")
    return _db._decrypt_alert(rows[0]) if rows else None

def _decrypt_alert(row, company=None):
    import db as _db
    if not row:
        return row
    company = company or _db.get_company_by_id(row["company_id"])
    result = dict(row)
    for field in ("title", "message", "resolution_note"):
        result[field] = _db._endpoint_decrypt(
            company, f"alert.{field}", result.get(field),
        )
    # Alert titles created before endpoint records were consistently
    # decrypted may contain the encrypted hostname as their first word.
    # Recover that embedded hostname so existing alerts remain readable.
    title = result.get("title")
    if isinstance(title, str) and title.startswith("v2:") and result.get("endpoint_id"):
        encrypted_hostname, separator, remainder = title.partition(" ")
        hostname = _db._endpoint_decrypt(company, "hostname", encrypted_hostname)
        if hostname != encrypted_hostname:
            result["title"] = f"{hostname}{separator}{remainder}"
    encrypted = result.pop("detail_encrypted", None)
    if encrypted:
        result["detail"] = _db._endpoint_decrypt(company, "alert.detail", encrypted)
    if result.get("endpoints"):
        endpoint = _db._decrypt_endpoint(result.pop("endpoints"), company)
        result["_endpoint"] = endpoint
        label = endpoint.get("display_name") or endpoint.get("hostname")
        title = result.get("title") or ""
        hostname = endpoint.get("hostname") or ""
        if label and hostname and title.startswith(hostname + " "):
            result["title"] = label + title[len(hostname):]
        elif label and title.endswith(" is offline"):
            result["title"] = label + " is offline"
    return result

def create_alert(company_id, branch_id, endpoint_id, alert_type, severity, title, message, detail=None):
    import db as _db
    company = _db.get_company_by_id(company_id)
    rows = _db._post("alerts", {
        "company_id": company_id,
        "branch_id": branch_id,
        "endpoint_id": endpoint_id,
        "type": alert_type,
        "severity": severity,
        "title": _db._endpoint_encrypt(company, "alert.title", title),
        "message": _db._endpoint_encrypt(company, "alert.message", message),
        "detail": {},
        "detail_encrypted": _db._endpoint_encrypt(company, "alert.detail", detail or {}),
        "is_resolved": False,
    })
    row = rows[0] if (rows and isinstance(rows, list)) else rows
    return _db._decrypt_alert(row, company)

def get_open_enrollment_alert(company_id, profile_id, hostname):
    """Find a matching unresolved enrollment failure to avoid retry spam."""
    import db as _db
    rows = _db._get(
        f"alerts?company_id=eq.{_db._q(company_id)}"
        "&type=eq.enrollment_rejected&is_resolved=eq.false"
        "&order=created_at.desc&limit=100"
    ) or []
    company = _db.get_company_by_id(company_id)
    rows = [_db._decrypt_alert(row, company) for row in rows]
    wanted_profile = str(profile_id or "")
    wanted_hostname = str(hostname or "").casefold()
    for row in rows:
        detail = row.get("detail") or {}
        if (str(detail.get("profile_id") or "") == wanted_profile
                and str(detail.get("hostname") or "").casefold() == wanted_hostname):
            return row
    return None

def resolve_alert(alert_id, admin_id, note=None):
    import db as _db
    raw = _db._get(f"alerts?id=eq.{_db._q(alert_id)}&select=company_id&limit=1")
    company = _db.get_company_by_id(raw[0]["company_id"]) if raw else None
    _db._patch(f"alerts?id=eq.{_db._q(alert_id)}", {
        "is_resolved": True,
        "resolved_by": admin_id,
        "resolved_at": _db._now_iso(),
        "resolution_note": (
            _db._endpoint_encrypt(company, "alert.resolution_note", note)
            if company and note is not None else None
        ),
        "snoozed_until": None,
    })

def reopen_alert(alert_id):
    import db as _db
    _db._patch(f"alerts?id=eq.{_db._q(alert_id)}", {
        "is_resolved": False,
        "resolved_by": None,
        "resolved_at": None,
        "resolution_note": None,
    })

def assign_alert(alert_id, admin_id=None):
    import db as _db
    _db._patch(f"alerts?id=eq.{_db._q(alert_id)}", {"assigned_to": admin_id})

def snooze_alert(alert_id, until):
    import db as _db
    _db._patch(f"alerts?id=eq.{_db._q(alert_id)}", {"snoozed_until": until})

def count_open_alerts(company_id, branch_id=None):
    import db as _db
    path = f"alerts?company_id=eq.{_db._q(company_id)}&is_resolved=eq.false&select=id"
    if branch_id:
        path += f"&branch_id=eq.{_db._q(branch_id)}"
    path += f"&or=(snoozed_until.is.null,snoozed_until.lte.{_db._q(_db._now_iso())})"
    return _db._count(path)
