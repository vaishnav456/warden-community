"""Policies database operations."""


def get_policy_templates(company_id):
    import db as _db
    return _db._get(f"policy_templates?company_id=eq.{_db._q(company_id)}&order=name.asc")

def get_policy_template(template_id):
    import db as _db
    rows = _db._get(f"policy_templates?id=eq.{_db._q(template_id)}&limit=1")
    return rows[0] if rows else None

def create_policy_template(company_id, name, description, settings, created_by):
    import db as _db
    data = {
        "company_id": company_id,
        "name": name,
        "description": description or None,
        "settings": settings,
        "created_by": created_by,
    }
    rows = _db._post("policy_templates", data)
    return rows[0] if (rows and isinstance(rows, list)) else rows

def update_policy_template(template_id, name, description, settings):
    import db as _db
    rows = _db._patch(f"policy_templates?id=eq.{_db._q(template_id)}", {
        "name": name,
        "description": description or None,
        "settings": settings,
    })
    return rows[0] if rows else None

def delete_policy_template(template_id):
    import db as _db
    _db._delete(f"policy_templates?id=eq.{_db._q(template_id)}")

def get_policy_assignments(company_id):
    import db as _db
    rows = _db._get(
        f"policy_assignments?company_id=eq.{_db._q(company_id)}"
        "&select=*,policy_templates(id,name,settings)&order=scope_type.asc,priority.asc,created_at.asc"
    )
    for row in rows:
        row["template"] = row.pop("policy_templates", None) or {}
    return rows

def create_policy_assignment(company_id, template_id, scope_type, scope_value, priority, created_by):
    import db as _db
    rows = _db._post("policy_assignments", {
        "company_id": company_id, "template_id": template_id,
        "scope_type": scope_type, "scope_value": scope_value,
        "priority": int(priority), "created_by": created_by,
    })
    return rows[0] if rows else None

def delete_policy_assignment(assignment_id, company_id):
    import db as _db
    _db._delete(f"policy_assignments?id=eq.{_db._q(assignment_id)}&company_id=eq.{_db._q(company_id)}")

def record_policy_drift_check(endpoint_id, current_values):
    """Compare a CHECK_POLICY_DRIFT job's reported current values against
    policy_state's last-known-applied values, for every key Warden has
    actually pushed before — a setting never pushed has nothing to drift
    from, so it's left untouched rather than flagged. Read-only settings
    (e.g. BitLocker status — see policy_settings.POLICY_SETTINGS's
    "readonly" flag) can never be pushed at all, so they'd never get an
    entry this way; record their current value as status-only instead
    (no drift comparison, since there's nothing to compare against).
    Returns the list of setting keys found drifted, for the caller to alert on."""
    import db as _db
    import policy_settings

    accepted = {
        key: value for key, value in current_values.items()
        if key in policy_settings.POLICY_SETTINGS
    }
    readonly = [
        key for key in accepted
        if policy_settings.POLICY_SETTINGS[key].get("readonly")
    ]
    if not accepted:
        return []
    result = _db._rpc("record_endpoint_policy_observations", {
        "p_endpoint_id": str(endpoint_id),
        "p_values": accepted,
        "p_readonly_keys": readonly,
    })
    return result or []

def update_endpoint_policy_state(endpoint_id, settings, policy_version=None):
    """Atomically persist desired/effective policy values per setting.

    The database RPC also updates the legacy JSON document for rolling-agent
    and UI compatibility, without a race-prone Python read/modify/write.
    """
    import db as _db
    if not settings:
        return
    _db._rpc("apply_endpoint_policy_settings", {
        "p_endpoint_id": str(endpoint_id),
        "p_settings": settings,
        "p_policy_version": policy_version,
    })
