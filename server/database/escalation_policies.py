"""Escalation policies database operations."""


def get_saved_escalations(company_id):
    import db as _db
    return _db._get(
        f"saved_escalations?company_id=eq.{_db._q(company_id)}"
        f"&revoked_at=is.null&order=approved_at.desc"
    )

def get_saved_escalation(policy_id):
    import db as _db
    rows = _db._get(f"saved_escalations?id=eq.{_db._q(policy_id)}&limit=1")
    return rows[0] if rows else None

def create_saved_escalation(company_id, scope, operation, payload_match,
                             approved_by, valid_days=None, note=None,
                             branch_id=None, endpoint_id=None, windows_user=None):
    import db as _db
    data = {
        "company_id": company_id,
        "scope": scope,
        "operation": operation,
        "payload_match": payload_match,
        "approved_by": approved_by,
        "approved_at": _db._now_iso(),
        "valid_from": _db._now_iso(),
        "note": note,
    }
    if valid_days:
        data["valid_until"] = (
            _db.datetime.now(_db.timezone.utc) + _db.timedelta(days=valid_days)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
    if branch_id:
        data["branch_id"] = branch_id
    if endpoint_id:
        data["endpoint_id"] = endpoint_id
    if windows_user:
        data["windows_user"] = windows_user
    rows = _db._post("saved_escalations", data)
    return rows[0] if (rows and isinstance(rows, list)) else rows

def revoke_saved_escalation(policy_id, admin_id):
    import db as _db
    _db._patch(f"saved_escalations?id=eq.{_db._q(policy_id)}", {
        "revoked_by": admin_id,
        "revoked_at": _db._now_iso(),
    })

def find_matching_policy(company_id, endpoint_id, windows_user, operation, payload):
    import db as _db
    if not isinstance(payload, dict):
        return None
    now = _db._now_iso()
    rows = _db._get(
        f"saved_escalations?company_id=eq.{_db._q(company_id)}&operation=eq.{_db._q(operation)}"
        f"&revoked_at=is.null&or=(valid_until.is.null,valid_until.gt.{_db._q(now)})"
    )
    endpoint = None
    endpoint_loaded = False
    for p in rows:
        scope = p.get("scope", "")
        if scope not in {
            "this_user_this_endpoint", "this_user_all_endpoints",
            "any_user_this_endpoint", "any_user_this_branch", "company_wide",
        }:
            continue
        if "this_endpoint" in scope and (
            not p.get("endpoint_id") or str(p["endpoint_id"]) != str(endpoint_id)
        ):
            continue
        if "this_user" in scope and (
            not p.get("windows_user") or p["windows_user"] != windows_user
        ):
            continue
        if scope == "any_user_this_branch" or p.get("branch_id"):
            if not endpoint_loaded:
                endpoint = _db.get_endpoint(endpoint_id)
                endpoint_loaded = True
            if (
                not endpoint or not p.get("branch_id")
                or str(endpoint.get("company_id")) != str(company_id)
                or str(endpoint.get("branch_id")) != str(p["branch_id"])
            ):
                continue
        match = p.get("payload_match") or {}
        if not isinstance(match, dict):
            continue
        if all(str(payload.get(k)) == str(v) for k, v in match.items()):
            return p
    return None
