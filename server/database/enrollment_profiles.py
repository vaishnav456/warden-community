"""Enrollment profiles database operations."""


def create_enrollment_profile(company_id, branch_id, name, deployment_method,
                              hostname_pattern, domain_suffix,
                              require_pre_registration, reclaim_existing,
                              created_by, warden_only_mode=True,
                              lockdown_config=None, post_enrollment=None):
    import db as _db
    company = _db.get_company_by_id(company_id)
    rows = _db._post("enrollment_profiles", {
        "company_id": company_id,
        "branch_id": branch_id,
        "name": name,
        "deployment_method": deployment_method,
        "hostname_pattern": hostname_pattern or None,
        "domain_suffix": domain_suffix.lower() if domain_suffix else None,
        "require_pre_registration": bool(require_pre_registration),
        "reclaim_existing": bool(reclaim_existing),
        "warden_only_mode": bool(warden_only_mode),
        "lockdown_config": (
            _db.encrypt_field(company, lockdown_config, "enrollment-profile.lockdown")
            if warden_only_mode and lockdown_config else None
        ),
        "post_enrollment": post_enrollment or {},
        "created_by": created_by,
    })
    row = rows[0] if (rows and isinstance(rows, list)) else rows
    return _db._decrypt_enrollment_profile(row, company)

def _decrypt_enrollment_profile(profile, company=None):
    import db as _db
    if not profile:
        return profile
    profile = dict(profile)
    if profile.get("lockdown_config") is not None:
        company = company or _db.get_company_by_id(profile["company_id"])
        profile["lockdown_config"] = _db.decrypt_field(
            company, profile["lockdown_config"], "enrollment-profile.lockdown"
        )
    return profile

def get_enrollment_profile(profile_id):
    import db as _db
    rows = _db._get(f"enrollment_profiles?id=eq.{_db._q(profile_id)}&limit=1")
    return _db._decrypt_enrollment_profile(rows[0]) if rows else None

def get_enrollment_profiles(company_id, active_only=False):
    import db as _db
    path = f"enrollment_profiles?company_id=eq.{_db._q(company_id)}"
    if active_only:
        path += "&is_active=eq.true"
    company = _db.get_company_by_id(company_id)
    return [
        _db._decrypt_enrollment_profile(profile, company)
        for profile in _db._get(path + "&order=created_at.desc")
    ]

def deactivate_enrollment_profile(profile_id):
    import db as _db
    return _db._patch(
        f"enrollment_profiles?id=eq.{_db._q(profile_id)}",
        {"is_active": False, "updated_at": _db._now_iso()},
    )

def update_enrollment_profile_preparation(profile_id, post_enrollment):
    import db as _db
    return _db._patch(
        f"enrollment_profiles?id=eq.{_db._q(profile_id)}",
        {"post_enrollment": post_enrollment or {}, "updated_at": _db._now_iso()},
    )

def add_enrollment_device_claim(company_id, profile_id, hardware_id=None,
                                expected_hostname=None, provider_device_id=None,
                                assigned_user=None, serial_number=None,
                                entra_device_id=None):
    import db as _db
    data = {
        "company_id": company_id,
        "profile_id": profile_id,
        "hardware_id": hardware_id or None,
        "serial_number": serial_number or None,
        "entra_device_id": entra_device_id or None,
        "expected_hostname": expected_hostname or None,
        "provider_device_id": provider_device_id or None,
        "assigned_user": assigned_user or None,
    }
    rows = _db._post("enrollment_device_claims", data)
    return rows[0] if (rows and isinstance(rows, list)) else rows

def get_enrollment_device_claim(company_id, hardware_id):
    import db as _db
    rows = _db._get(
        f"enrollment_device_claims?company_id=eq.{_db._q(company_id)}"
        f"&hardware_id=ilike.{_db._q(hardware_id)}&limit=1"
    )
    return rows[0] if rows else None

def get_enrollment_device_claim_for_identity(company_id, hardware_id=None,
                                             serial_number=None, entra_device_id=None,
                                             provider_device_id=None):
    import db as _db
    lookups = (
        ("hardware_id", hardware_id, True),
        ("serial_number", serial_number, True),
        ("entra_device_id", entra_device_id, True),
        ("provider_device_id", provider_device_id, False),
    )
    for column, value, case_insensitive in lookups:
        value = str(value or "").strip()
        if not value:
            continue
        operator = "ilike" if case_insensitive else "eq"
        rows = _db._get(
            f"enrollment_device_claims?company_id=eq.{_db._q(company_id)}"
            f"&{column}={operator}.{_db._q(value)}&limit=1"
        )
        if rows:
            return rows[0]
    return None

def upsert_autopilot_device_claim(company_id, profile_id, device):
    import db as _db
    existing = _db.get_enrollment_device_claim_for_identity(
        company_id,
        serial_number=device.get("serial_number"),
        entra_device_id=device.get("entra_device_id"),
        provider_device_id=device.get("provider_device_id"),
    )
    fields = {
        "profile_id": profile_id,
        "serial_number": device.get("serial_number") or None,
        "entra_device_id": device.get("entra_device_id") or None,
        "provider_device_id": device.get("provider_device_id") or None,
        # Autopilot displayName is descriptive metadata, not a guaranteed
        # Windows hostname. Do not turn it into an enrollment rejection rule.
        "expected_hostname": None,
    }
    if existing:
        if existing.get("status") == "released":
            fields["status"] = "pending"
            fields["endpoint_id"] = None
            fields["enrolled_at"] = None
        rows = _db._patch(f"enrollment_device_claims?id=eq.{_db._q(existing['id'])}", fields)
        return (rows[0] if rows else existing), False
    claim = _db.add_enrollment_device_claim(
        company_id, profile_id,
        serial_number=fields["serial_number"],
        entra_device_id=fields["entra_device_id"],
        provider_device_id=fields["provider_device_id"],
        expected_hostname=fields["expected_hostname"],
    )
    return claim, True

def sync_autopilot_device_claims(company_id, profile_id, devices):
    import db as _db
    result = _db._rpc("sync_autopilot_device_claims", {
        "p_company_id": company_id,
        "p_profile_id": profile_id,
        "p_devices": devices,
    })
    return result or {"added": 0, "updated": 0}

def get_enrollment_device_claims(profile_id):
    import db as _db
    return _db._get(
        f"enrollment_device_claims?profile_id=eq.{_db._q(profile_id)}"
        "&order=created_at.desc"
    )

def mark_enrollment_device_claim_enrolled(claim_id, endpoint_id, device_identity=None):
    import db as _db
    identity = device_identity or {}
    fields = {
        "status": "enrolled",
        "endpoint_id": endpoint_id,
        "enrolled_at": _db._now_iso(),
    }
    if identity.get("hardware_id"):
        fields["hardware_id"] = identity["hardware_id"]
    if identity.get("serial_number"):
        fields["serial_number"] = identity["serial_number"]
    if identity.get("entra_device_id"):
        fields["entra_device_id"] = identity["entra_device_id"]
    _db._patch(f"enrollment_device_claims?id=eq.{_db._q(claim_id)}", fields)
