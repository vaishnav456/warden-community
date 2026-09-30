"""
Warden Server — Database layer
Uses urllib only (no external HTTP libraries) — same pattern as printer-agent.
All queries go to a PostgREST API (self-hosted, plain Postgres — see
db-init/) using a service_role JWT. Schema: endpt
"""
import urllib.request
import urllib.parse
import urllib.error
import json
import ssl
import hashlib
import secrets
import logging
from datetime import datetime, timezone, timedelta

import config

log = logging.getLogger("warden.audit")

# http:// is only safe here because the Postgres/PostgREST containers are
# never reachable outside this project's private Docker network (no
# published port, no nginx route) — the service_role key never crosses a
# network boundary an attacker could observe. Any URL reachable off-host
# must still be https://.
if not (config.SUPABASE_URL.startswith("https://") or config.SUPABASE_URL.startswith("http://")):
    raise RuntimeError(f"SUPABASE_URL must be http:// or https://, got: {config.SUPABASE_URL!r}")

_SSL_CTX = ssl.create_default_context()

_HEADERS = {
    "apikey": config.SUPABASE_SERVICE_KEY,
    "Authorization": f"Bearer {config.SUPABASE_SERVICE_KEY}",
    "Content-Type": "application/json",
    "Prefer": "return=representation",
}

_RPC_HEADERS = {
    "apikey": config.SUPABASE_SERVICE_KEY,
    "Authorization": f"Bearer {config.SUPABASE_SERVICE_KEY}",
    "Content-Type": "application/json",
}


def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def consume_rate_limit(bucket_key, max_requests, window_seconds=60):
    """Atomically consume one request from a cross-process rate bucket."""
    result = _rpc("consume_rate_limit", {
        "p_bucket_key": str(bucket_key),
        "p_max_requests": max(1, int(max_requests)),
        "p_window_seconds": max(1, int(window_seconds)),
    })
    return bool(result)


def _get(path, schema="endpt"):
    url = f"{config.SUPABASE_URL}/{path}"
    headers = dict(_HEADERS)
    headers["Accept-Profile"] = schema
    req = urllib.request.Request(url, headers=headers)
    resp = urllib.request.urlopen(req, timeout=15, context=_SSL_CTX)
    return json.loads(resp.read())


def _post(path, data, schema="endpt", prefer="return=representation"):
    url = f"{config.SUPABASE_URL}/{path}"
    body = json.dumps(data).encode()
    headers = dict(_HEADERS)
    headers["Content-Profile"] = schema
    headers["Prefer"] = prefer
    req = urllib.request.Request(url, data=body, method="POST", headers=headers)
    resp = urllib.request.urlopen(req, timeout=15, context=_SSL_CTX)
    raw = resp.read()
    if raw:
        return json.loads(raw)
    return None


def _patch(path, data, schema="endpt"):
    url = f"{config.SUPABASE_URL}/{path}"
    body = json.dumps(data).encode()
    headers = dict(_HEADERS)
    headers["Content-Profile"] = schema
    req = urllib.request.Request(url, data=body, method="PATCH", headers=headers)
    resp = urllib.request.urlopen(req, timeout=15, context=_SSL_CTX)
    raw = resp.read()
    if raw:
        return json.loads(raw)
    return None


def _rpc(function_name, params, schema="endpt"):
    """Call a PostgREST-exposed Postgres function (POST /rpc/<name>). Used
    where an operation needs to be atomic in a way a single PATCH/POST
    can't express (e.g. claim_enrollment_token_use's "increment a counter
    but only if still under a cap" — see db-init/02-schema.sql)."""
    url = f"{config.SUPABASE_URL}/rpc/{function_name}"
    body = json.dumps(params).encode()
    headers = dict(_RPC_HEADERS)
    headers["Content-Profile"] = schema
    req = urllib.request.Request(url, data=body, method="POST", headers=headers)
    resp = urllib.request.urlopen(req, timeout=15, context=_SSL_CTX)
    raw = resp.read()
    if raw:
        return json.loads(raw)
    return None


def _delete(path, schema="endpt"):
    url = f"{config.SUPABASE_URL}/{path}"
    headers = dict(_HEADERS)
    headers["Content-Profile"] = schema
    req = urllib.request.Request(url, method="DELETE", headers=headers)
    urllib.request.urlopen(req, timeout=15, context=_SSL_CTX)


def _q(value):
    """URL-safe encode a query param value."""
    return urllib.parse.quote(str(value), safe="")


def healthcheck():
    """Verify that PostgREST can execute a real database query.

    A process-only health check can report healthy while PostgreSQL is still
    recovering (or PostgREST has lost its database connection), which causes
    dependent services to start against an unusable control plane.
    """
    _get("companies?select=id&limit=1")
    return True


# ─────────────────────────────────────────────────────────────────────────────
# Companies
# ─────────────────────────────────────────────────────────────────────────────

def get_company_by_id(company_id):
    rows = _get(f"companies?id=eq.{_q(company_id)}&limit=1")
    return rows[0] if rows else None


def get_single_company():
    """Return the one active community organization, failing closed if the
    database was populated with more than one. The schema's singleton column
    prevents this on fresh installations; the check protects upgraded data."""
    rows = _get("companies?is_active=eq.true&order=created_at.asc&limit=2")
    if len(rows) != 1:
        raise RuntimeError(
            "Warden Community requires exactly one active organization"
        )
    return rows[0]


def ensure_company_encryption(company):
    """Provision the single organization's managed DEK once, race-safely."""
    if company.get("wrapped_dek"):
        return company
    from services.tenant_crypto import provision_managed
    fields = provision_managed(company["id"])
    rows = _patch(
        f"companies?id=eq.{_q(company['id'])}&wrapped_dek=is.null", fields
    )
    return rows[0] if rows else get_company_by_id(company["id"])


def update_company(company_id, data):
    rows = _patch(f"companies?id=eq.{_q(company_id)}", data)
    return rows[0] if (rows and isinstance(rows, list)) else rows


def set_company_encryption(company_id, mode, wrapped_dek, byok_salt=None):
    return update_company(company_id, {
        "encryption_mode": mode,
        "wrapped_dek": wrapped_dek,
        "byok_salt": byok_salt,
    })


def set_company_auto_update(company_id, enabled):
    return update_company(company_id, {"auto_update_agents": bool(enabled)})


def get_auto_update_company():
    company = get_single_company()
    return company if company.get("auto_update_agents") else None


def set_company_dual_approval(company_id, required):
    return update_company(company_id, {"require_dual_approval": bool(required)})


def encrypt_field(company, plaintext, purpose="generic"):
    """Encrypt a value for storage, scoped to the given company dict
    (must include id/encryption_mode/wrapped_dek — e.g. from
    get_company_by_id()). Raises tenant_crypto.VaultLocked if the
    company is BYOK-mode and currently locked — callers must handle
    that explicitly rather than storing plaintext as a fallback."""
    from services.tenant_crypto import encrypt_value
    return encrypt_value(company["id"], company.get("encryption_mode", "managed"),
                         company.get("wrapped_dek"), plaintext, purpose)


def decrypt_field(company, ciphertext_b64, purpose="generic"):
    if ciphertext_b64 is None:
        return None
    # Rows created before tenant encryption may contain native JSON values or
    # plaintext strings. Keep modern v2 ciphertext fail-closed while allowing
    # those legacy rows to remain readable during a rolling migration.
    if not isinstance(ciphertext_b64, str):
        return ciphertext_b64
    import binascii
    from cryptography.exceptions import InvalidTag
    from services.tenant_crypto import decrypt_value
    try:
        return decrypt_value(company["id"], company.get("encryption_mode", "managed"),
                             company.get("wrapped_dek"), ciphertext_b64, purpose)
    except (binascii.Error, InvalidTag, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        # Short legacy messages can decode as base64 but cannot contain an
        # AES-GCM nonce. Versioned ciphertext must still fail closed.
        if ciphertext_b64.startswith("v2:"):
            raise
        return ciphertext_b64


_ENDPOINT_TEXT_FIELDS = {
    "hostname", "hardware_id", "installation_id", "vpn_ip",
    "last_seen_ip", "local_ip", "os_name", "os_version", "os_build",
    "os_edition", "arch", "cpu_model", "interactive_user", "notes",
    "asset_tag", "assigned_to", "display_name",
}
_ENDPOINT_JSON_FIELDS = {
    "device_identity": "device_identity_encrypted",
    "topology_telemetry": "topology_telemetry_encrypted",
    "capability_details": "capability_details_encrypted",
    "tags": "tags_encrypted",
    "asset_metadata": "asset_metadata_encrypted",
}


def blind_index(company, value, purpose):
    if value is None or str(value).strip() == "":
        return None
    from services.tenant_crypto import blind_index_value
    return blind_index_value(
        company["id"], company.get("encryption_mode", "managed"),
        company.get("wrapped_dek"), value, purpose,
    )


def _endpoint_encrypt(company, field, value):
    if value is None:
        return None
    return encrypt_field(company, value, f"endpoint.{field}")


def _endpoint_decrypt(company, field, value):
    if value is None:
        return None
    # Endpoint columns were historically plaintext. Only versioned values
    # are ciphertext, which keeps a rolling deployment and restartable
    # migration safe without ever treating a failed decrypt as plaintext.
    if not isinstance(value, str) or not value.startswith("v2:"):
        return value
    return decrypt_field(company, value, f"endpoint.{field}")


def _decrypt_endpoint(row, company=None):
    if not row:
        return row
    company = company or get_company_by_id(row["company_id"])
    result = dict(row)
    for field in _ENDPOINT_TEXT_FIELDS:
        if field in result:
            result[field] = _endpoint_decrypt(company, field, result.get(field))
    for field, encrypted_column in _ENDPOINT_JSON_FIELDS.items():
        encrypted = result.pop(encrypted_column, None)
        if encrypted:
            result[field] = _endpoint_decrypt(company, field, encrypted)
    return result


def _endpoint_company(endpoint_id):
    rows = _get(
        f"endpoints?id=eq.{_q(endpoint_id)}&select=company_id&limit=1"
    )
    return get_company_by_id(rows[0]["company_id"]) if rows else None


def _encrypt_endpoint_fields(company, fields):
    result = dict(fields)
    for field in _ENDPOINT_TEXT_FIELDS:
        if field in result:
            result[field] = _endpoint_encrypt(company, field, result[field])
    for field, encrypted_column in _ENDPOINT_JSON_FIELDS.items():
        if field in result:
            value = result.pop(field)
            result[encrypted_column] = _endpoint_encrypt(company, field, value)
            # Scrub the legacy JSON/array column while preserving its schema
            # type for older constraints and rolling deployments.
            result[field] = [] if field == "tags" else {}
    if "hardware_id" in fields:
        result["hardware_id_hash"] = blind_index(
            company, fields.get("hardware_id"), "endpoint.hardware-id",
        )
    if "installation_id" in fields:
        result["installation_id_hash"] = blind_index(
            company, fields.get("installation_id"), "endpoint.installation-id",
        )
    result["private_data_encryption_version"] = 1
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Tenant-owned third-party integrations
# ─────────────────────────────────────────────────────────────────────────────

def get_tenant_integration(company_id, provider):
    rows = _get(
        f"tenant_integrations?company_id=eq.{_q(company_id)}"
        f"&provider=eq.{_q(provider)}&limit=1"
    )
    return rows[0] if rows else None


def save_tenant_integration(company, provider, integration_config, created_by):
    encrypted = encrypt_field(company, integration_config, "integration.config")
    existing = get_tenant_integration(company["id"], provider)
    fields = {
        "config_encrypted": encrypted,
        "enabled": True,
        "status": "not_tested",
        "metadata": {},
        "last_tested_at": None,
        "last_error": None,
        "updated_at": _now_iso(),
    }
    if existing:
        rows = _patch(f"tenant_integrations?id=eq.{_q(existing['id'])}", fields)
    else:
        fields.update({
            "company_id": company["id"],
            "provider": provider,
            "created_by": created_by,
        })
        rows = _post("tenant_integrations", fields)
    return rows[0] if (rows and isinstance(rows, list)) else rows


def get_tenant_integration_config(company, provider):
    integration = get_tenant_integration(company["id"], provider)
    if not integration:
        return None, None
    return integration, decrypt_field(company, integration["config_encrypted"], "integration.config")


def update_tenant_integration_test(integration_id, connected, metadata=None, error=None):
    rows = _patch(f"tenant_integrations?id=eq.{_q(integration_id)}", {
        "status": "connected" if connected else "error",
        "metadata": metadata or {},
        "last_tested_at": _now_iso(),
        "last_error": None if connected else str(error or "Connection failed")[:500],
        "updated_at": _now_iso(),
    })
    return rows[0] if (rows and isinstance(rows, list)) else rows


def delete_tenant_integration(company_id, provider):
    return _delete(
        f"tenant_integrations?company_id=eq.{_q(company_id)}"
        f"&provider=eq.{_q(provider)}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Branches
# ─────────────────────────────────────────────────────────────────────────────

def get_branches(company_id):
    return _get(f"branches?company_id=eq.{_q(company_id)}&order=name.asc")


def get_branch(branch_id):
    rows = _get(f"branches?id=eq.{_q(branch_id)}&limit=1")
    return rows[0] if rows else None


def create_branch(company_id, name, city=None, timezone="UTC"):
    data = {"company_id": company_id, "name": name, "timezone": timezone}
    if city:
        data["city"] = city
    rows = _post("branches", data)
    return rows[0] if (rows and isinstance(rows, list)) else rows


def update_branch(branch_id, company_id, fields):
    rows = _patch(
        f"branches?id=eq.{_q(branch_id)}&company_id=eq.{_q(company_id)}",
        fields,
    )
    return rows[0] if rows else None


def delete_branch(branch_id):
    _delete(f"branches?id=eq.{_q(branch_id)}")


# ─────────────────────────────────────────────────────────────────────────────
# Policy templates & per-endpoint policy state
# ─────────────────────────────────────────────────────────────────────────────

def get_policy_templates(company_id):
    return _get(f"policy_templates?company_id=eq.{_q(company_id)}&order=name.asc")


def get_policy_template(template_id):
    rows = _get(f"policy_templates?id=eq.{_q(template_id)}&limit=1")
    return rows[0] if rows else None


def create_policy_template(company_id, name, description, settings, created_by):
    data = {
        "company_id": company_id,
        "name": name,
        "description": description or None,
        "settings": settings,
        "created_by": created_by,
    }
    rows = _post("policy_templates", data)
    return rows[0] if (rows and isinstance(rows, list)) else rows


def update_policy_template(template_id, name, description, settings):
    rows = _patch(f"policy_templates?id=eq.{_q(template_id)}", {
        "name": name,
        "description": description or None,
        "settings": settings,
    })
    return rows[0] if rows else None


def delete_policy_template(template_id):
    _delete(f"policy_templates?id=eq.{_q(template_id)}")


def get_policy_assignments(company_id):
    rows = _get(
        f"policy_assignments?company_id=eq.{_q(company_id)}"
        "&select=*,policy_templates(id,name,settings)&order=scope_type.asc,priority.asc,created_at.asc"
    )
    for row in rows:
        row["template"] = row.pop("policy_templates", None) or {}
    return rows


def create_policy_assignment(company_id, template_id, scope_type, scope_value, priority, created_by):
    rows = _post("policy_assignments", {
        "company_id": company_id, "template_id": template_id,
        "scope_type": scope_type, "scope_value": scope_value,
        "priority": int(priority), "created_by": created_by,
    })
    return rows[0] if rows else None


def delete_policy_assignment(assignment_id, company_id):
    _delete(f"policy_assignments?id=eq.{_q(assignment_id)}&company_id=eq.{_q(company_id)}")


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
    result = _rpc("record_endpoint_policy_observations", {
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
    if not settings:
        return
    _rpc("apply_endpoint_policy_settings", {
        "p_endpoint_id": str(endpoint_id),
        "p_settings": settings,
        "p_policy_version": policy_version,
    })


# ─────────────────────────────────────────────────────────────────────────────
# Admin Users
# ─────────────────────────────────────────────────────────────────────────────

def get_admin_by_email(email):
    rows = _get(f"admin_users?email=eq.{_q(email)}&limit=1")
    row = rows[0] if rows else None
    if row and row.get("mfa_secret"):
        from services.platform_secrets import decrypt_mfa_secret
        row["mfa_secret"] = decrypt_mfa_secret(row["id"], row["mfa_secret"])
    return row


def get_admin_by_id(admin_id):
    rows = _get(f"admin_users?id=eq.{_q(admin_id)}&limit=1")
    row = rows[0] if rows else None
    if row and row.get("mfa_secret"):
        from services.platform_secrets import decrypt_mfa_secret
        row["mfa_secret"] = decrypt_mfa_secret(row["id"], row["mfa_secret"])
    return row


def get_admins_for_company(company_id):
    return _get(f"admin_users?company_id=eq.{_q(company_id)}&order=full_name.asc")


def get_all_admins():
    return _get("admin_users?order=email.asc")


def create_admin_user(email, password_hash, full_name, role, company_id=None, branch_id=None, created_by=None):
    payload = {
        "email": email,
        "password_hash": password_hash,
        "full_name": full_name,
        "role": role,
    }
    if company_id:
        payload["company_id"] = company_id
    if branch_id:
        payload["branch_id"] = branch_id
    if created_by:
        payload["created_by"] = created_by
    rows = _post("admin_users", payload)
    return rows[0] if (rows and isinstance(rows, list)) else rows


def update_admin(admin_id, data):
    rows = _patch(f"admin_users?id=eq.{_q(admin_id)}", data)
    return rows[0] if (rows and isinstance(rows, list)) else rows


def update_admin_failed_attempts(admin_id, count, locked_until=None):
    data = {"failed_attempts": count}
    if locked_until:
        data["locked_until"] = locked_until
    _patch(f"admin_users?id=eq.{_q(admin_id)}", data)


def update_admin_last_login(admin_id, ip):
    _patch(f"admin_users?id=eq.{_q(admin_id)}", {
        "last_login_at": _now_iso(),
        "last_login_ip": ip,
        "failed_attempts": 0,
        "locked_until": None,
    })


def update_admin_mfa(admin_id, secret, backup_codes):
    from services.platform_secrets import encrypt_mfa_secret, hash_backup_code
    _patch(f"admin_users?id=eq.{_q(admin_id)}", {
        "mfa_secret": encrypt_mfa_secret(admin_id, secret),
        "mfa_enabled": True,
        "mfa_backup_codes": [hash_backup_code(code) for code in backup_codes],
    })


def disable_admin_mfa(admin_id):
    _patch(f"admin_users?id=eq.{_q(admin_id)}", {
        "mfa_secret": None,
        "mfa_enabled": False,
        "mfa_backup_codes": None,
    })


def update_admin_password(admin_id, new_hash):
    _patch(f"admin_users?id=eq.{_q(admin_id)}", {"password_hash": new_hash})


# ─────────────────────────────────────────────────────────────────────────────
# Refresh Tokens
# ─────────────────────────────────────────────────────────────────────────────

def create_refresh_token(admin_id, token_hash, ip, user_agent, expires_at,
                         absolute_expires_at):
    rows = _rpc("create_refresh_session", {
        "p_admin_id": admin_id,
        "p_token_hash": token_hash,
        "p_ip_address": ip,
        "p_user_agent": (user_agent or "")[:500],
        "p_expires_at": expires_at,
        "p_absolute_expires_at": absolute_expires_at,
        "p_max_sessions": config.MAX_CONCURRENT_SESSIONS,
    })
    return rows[0] if (rows and isinstance(rows, list)) else rows


def rotate_refresh_token(old_token_hash, new_token_hash, ip, user_agent, expires_at):
    rows = _rpc("rotate_refresh_session", {
        "p_old_token_hash": old_token_hash,
        "p_new_token_hash": new_token_hash,
        "p_ip_address": ip,
        "p_user_agent": (user_agent or "")[:500],
        "p_expires_at": expires_at,
        "p_idle_minutes": config.SESSION_IDLE_MINUTES,
    })
    return rows[0] if (rows and isinstance(rows, list)) else rows


def get_refresh_token(token_hash):
    rows = _get(f"refresh_tokens?token_hash=eq.{_q(token_hash)}&revoked=eq.false&limit=1")
    return rows[0] if rows else None


def revoke_refresh_token(token_id):
    _patch(f"refresh_tokens?id=eq.{_q(token_id)}", {
        "revoked": True,
        "revoked_at": _now_iso(),
    })


def revoke_all_tokens_for_admin(admin_id):
    _patch(f"refresh_tokens?admin_id=eq.{_q(admin_id)}&revoked=eq.false", {
        "revoked": True,
        "revoked_at": _now_iso(),
    })


def count_active_sessions(admin_id):
    rows = _get(
        f"refresh_tokens?admin_id=eq.{_q(admin_id)}&revoked=eq.false"
        f"&expires_at=gt.{_q(_now_iso())}&select=id"
    )
    return len(rows)


# ─────────────────────────────────────────────────────────────────────────────
# Enrollment Tokens
# ─────────────────────────────────────────────────────────────────────────────

def create_enrollment_token(company_id, branch_id, created_by, expires_hours=24, max_uses=1,
                            profile_id=None):
    """max_uses=1 (the default) is single-use: burned after exactly one
    enrollment, same as this always behaved. A larger integer allows that
    many enrollments before the token deactivates; max_uses=None means
    unlimited enrollments until expires_hours — e.g. a GPO/SCCM/Intune-
    deployed MSI meant to enroll many machines from one reusable token."""
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expires_at = (
        datetime.now(timezone.utc) + timedelta(hours=expires_hours)
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
    rows = _post("enrollment_tokens", data)
    rec = rows[0] if (rows and isinstance(rows, list)) else rows
    return token, rec


def get_enrollment_token_by_hash(token_hash, include_inactive=False):
    path = f"enrollment_tokens?token_hash=eq.{_q(token_hash)}&limit=1"
    if not include_inactive:
        path += f"&is_active=eq.true&expires_at=gt.{_q(_now_iso())}"
    rows = _get(path)
    return rows[0] if rows else None


def get_enrollment_tokens(company_id, limit=50):
    return _get(
        f"enrollment_tokens?company_id=eq.{_q(company_id)}"
        f"&order=created_at.desc&limit={limit}"
    )


def get_enrollment_token(token_id):
    rows = _get(f"enrollment_tokens?id=eq.{_q(token_id)}&limit=1")
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
    return bool(_rpc("claim_enrollment_token_use", {"p_token_id": token_id}))


def release_enrollment_token(token_id):
    """Return a claimed token use after enrollment fails before an endpoint
    is created. The database function serializes this with concurrent claims
    and safely reactivates the token when capacity remains."""
    return bool(_rpc("release_enrollment_token_use", {"p_token_id": token_id}))


def deactivate_enrollment_token(token_id):
    """Prevent use of a token whose installer/build request could not be
    created. Keep the row for audit/history instead of deleting it."""
    return _patch(
        f"enrollment_tokens?id=eq.{_q(token_id)}",
        {"is_active": False},
    )


def burn_enrollment_token(token_id, endpoint_id):
    """Record which endpoint actually used this (already-claimed — see
    claim_enrollment_token) token. Not itself racy: is_active was already
    flipped exclusively by the winning claim_enrollment_token() call."""
    _patch(f"enrollment_tokens?id=eq.{_q(token_id)}", {
        "used_by_endpoint_id": str(endpoint_id),
    })


# ─────────────────────────────────────────────────────────────────────────────
# Zero-touch enrollment profiles and pre-registered device claims
# ─────────────────────────────────────────────────────────────────────────────

def create_enrollment_profile(company_id, branch_id, name, deployment_method,
                              hostname_pattern, domain_suffix,
                              require_pre_registration, reclaim_existing,
                              created_by, warden_only_mode=True,
                              lockdown_config=None, post_enrollment=None):
    company = get_company_by_id(company_id)
    rows = _post("enrollment_profiles", {
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
            encrypt_field(company, lockdown_config, "enrollment-profile.lockdown")
            if warden_only_mode and lockdown_config else None
        ),
        "post_enrollment": post_enrollment or {},
        "created_by": created_by,
    })
    row = rows[0] if (rows and isinstance(rows, list)) else rows
    return _decrypt_enrollment_profile(row, company)


def _decrypt_enrollment_profile(profile, company=None):
    if not profile:
        return profile
    profile = dict(profile)
    if profile.get("lockdown_config") is not None:
        company = company or get_company_by_id(profile["company_id"])
        profile["lockdown_config"] = decrypt_field(
            company, profile["lockdown_config"], "enrollment-profile.lockdown"
        )
    return profile


def get_enrollment_profile(profile_id):
    rows = _get(f"enrollment_profiles?id=eq.{_q(profile_id)}&limit=1")
    return _decrypt_enrollment_profile(rows[0]) if rows else None


def get_enrollment_profiles(company_id, active_only=False):
    path = f"enrollment_profiles?company_id=eq.{_q(company_id)}"
    if active_only:
        path += "&is_active=eq.true"
    company = get_company_by_id(company_id)
    return [
        _decrypt_enrollment_profile(profile, company)
        for profile in _get(path + "&order=created_at.desc")
    ]


def deactivate_enrollment_profile(profile_id):
    return _patch(
        f"enrollment_profiles?id=eq.{_q(profile_id)}",
        {"is_active": False, "updated_at": _now_iso()},
    )


def update_enrollment_profile_preparation(profile_id, post_enrollment):
    return _patch(
        f"enrollment_profiles?id=eq.{_q(profile_id)}",
        {"post_enrollment": post_enrollment or {}, "updated_at": _now_iso()},
    )


def add_enrollment_device_claim(company_id, profile_id, hardware_id=None,
                                expected_hostname=None, provider_device_id=None,
                                assigned_user=None, serial_number=None,
                                entra_device_id=None):
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
    rows = _post("enrollment_device_claims", data)
    return rows[0] if (rows and isinstance(rows, list)) else rows


def get_enrollment_device_claim(company_id, hardware_id):
    rows = _get(
        f"enrollment_device_claims?company_id=eq.{_q(company_id)}"
        f"&hardware_id=ilike.{_q(hardware_id)}&limit=1"
    )
    return rows[0] if rows else None


def get_enrollment_device_claim_for_identity(company_id, hardware_id=None,
                                             serial_number=None, entra_device_id=None,
                                             provider_device_id=None):
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
        rows = _get(
            f"enrollment_device_claims?company_id=eq.{_q(company_id)}"
            f"&{column}={operator}.{_q(value)}&limit=1"
        )
        if rows:
            return rows[0]
    return None


def upsert_autopilot_device_claim(company_id, profile_id, device):
    existing = get_enrollment_device_claim_for_identity(
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
        rows = _patch(f"enrollment_device_claims?id=eq.{_q(existing['id'])}", fields)
        return (rows[0] if rows else existing), False
    claim = add_enrollment_device_claim(
        company_id, profile_id,
        serial_number=fields["serial_number"],
        entra_device_id=fields["entra_device_id"],
        provider_device_id=fields["provider_device_id"],
        expected_hostname=fields["expected_hostname"],
    )
    return claim, True


def sync_autopilot_device_claims(company_id, profile_id, devices):
    result = _rpc("sync_autopilot_device_claims", {
        "p_company_id": company_id,
        "p_profile_id": profile_id,
        "p_devices": devices,
    })
    return result or {"added": 0, "updated": 0}


def get_enrollment_device_claims(profile_id):
    return _get(
        f"enrollment_device_claims?profile_id=eq.{_q(profile_id)}"
        "&order=created_at.desc"
    )


def mark_enrollment_device_claim_enrolled(claim_id, endpoint_id, device_identity=None):
    identity = device_identity or {}
    fields = {
        "status": "enrolled",
        "endpoint_id": endpoint_id,
        "enrolled_at": _now_iso(),
    }
    if identity.get("hardware_id"):
        fields["hardware_id"] = identity["hardware_id"]
    if identity.get("serial_number"):
        fields["serial_number"] = identity["serial_number"]
    if identity.get("entra_device_id"):
        fields["entra_device_id"] = identity["entra_device_id"]
    _patch(f"enrollment_device_claims?id=eq.{_q(claim_id)}", fields)


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────

def get_endpoints(company_id, branch_id=None):
    path = f"endpoints?company_id=eq.{_q(company_id)}&is_active=eq.true&order=hostname.asc"
    if branch_id:
        path += f"&branch_id=eq.{_q(branch_id)}"
    company = get_company_by_id(company_id)
    rows = [_decrypt_endpoint(row, company) for row in _get(path)]
    return sorted(rows, key=lambda row: str(row.get("display_name") or row.get("hostname") or "").casefold())


def get_asset_register(company_id, branch_id=None):
    """Return active and historical devices so retirement never erases the
    asset ledger or its warranty/assignment record."""
    path = f"endpoints?company_id=eq.{_q(company_id)}&order=hostname.asc"
    if branch_id:
        path += f"&branch_id=eq.{_q(branch_id)}"
    company = get_company_by_id(company_id)
    rows = [_decrypt_endpoint(row, company) for row in _get(path)]
    return sorted(rows, key=lambda row: str(row.get("display_name") or row.get("hostname") or "").casefold())


def get_endpoint(endpoint_id):
    rows = _get(f"endpoints?id=eq.{_q(endpoint_id)}&limit=1")
    return _decrypt_endpoint(rows[0]) if rows else None


def get_endpoint_recovery_keys(endpoint_id, current_only=False):
    path = (
        f"endpoint_recovery_keys?endpoint_id=eq.{_q(endpoint_id)}"
        "&select=id,company_id,endpoint_id,volume_mount,protector_id,volume_status,"
        "protection_status,encryption_percentage,is_current,escrowed_at,last_reported_at"
    )
    if current_only:
        path += "&is_current=eq.true"
    return _get(path + "&order=escrowed_at.desc")


def escrow_endpoint_recovery_key(company, endpoint_id, volume_mount, protector_id,
                                 recovery_password, volume_status=None,
                                 protection_status=None, encryption_percentage=None):
    """Atomically store tenant-encrypted material and retire older keys."""
    encrypted = encrypt_field(company, recovery_password, "bitlocker.recovery-password")
    rows = _rpc("upsert_endpoint_recovery_key", {
        "p_company_id": company["id"], "p_endpoint_id": endpoint_id,
        "p_volume_mount": volume_mount, "p_protector_id": protector_id,
        "p_recovery_password_encrypted": encrypted,
        "p_volume_status": volume_status, "p_protection_status": protection_status,
        "p_encryption_percentage": encryption_percentage,
    })
    return rows[0] if isinstance(rows, list) and rows else rows


def reveal_endpoint_recovery_key(company, recovery_key_id):
    rows = _get(
        f"endpoint_recovery_keys?id=eq.{_q(recovery_key_id)}"
        f"&company_id=eq.{_q(company['id'])}&limit=1"
    )
    if not rows:
        return None
    row = rows[0]
    row["recovery_password"] = decrypt_field(
        company, row.pop("recovery_password_encrypted"), "bitlocker.recovery-password"
    )
    return row


def get_endpoint_by_api_key_hash(key_hash):
    rows = _get(f"endpoints?api_key_hash=eq.{_q(key_hash)}&is_active=eq.true&limit=1")
    return _decrypt_endpoint(rows[0]) if rows else None


def retire_endpoint(endpoint_id, clear_cloudflare_cert_id=True):
    """Remove an uninstalled endpoint from the active fleet while preserving
    its jobs, events and audit history.  is_active=false also invalidates the
    agent API key because agent authentication only accepts active endpoints.
    """
    fields = {
        "is_active": False,
        "status": "offline",
        "client_cert_fingerprint": None,
    }
    # Retain the external ID when Cloudflare deletion failed so an operator
    # can retry revocation; it is not used for app-level authentication.
    if clear_cloudflare_cert_id:
        fields["cloudflare_cert_id"] = None
    _patch(f"endpoints?id=eq.{_q(endpoint_id)}", fields)


def close_endpoint_work(endpoint_id, actor_id=None):
    """Close work that can no longer complete after an endpoint is retired."""
    now = _now_iso()
    company = _endpoint_company(endpoint_id)
    _patch(
        f"jobs?endpoint_id=eq.{_q(endpoint_id)}&status=in.(pending,approved,running)",
        {"status": "cancelled", "completed_at": now},
    )
    _patch(
        f"alerts?endpoint_id=eq.{_q(endpoint_id)}&is_resolved=eq.false",
        {"is_resolved": True, "resolved_by": actor_id, "resolved_at": now,
         "resolution_note": _endpoint_encrypt(
             company, "alert.resolution_note",
             "Endpoint was removed from Warden",
         )},
    )


def create_endpoint(company_id, branch_id, hostname, api_key_hash,
                    vpn_ip=None, wg_pubkey=None, hardware_id=None,
                    installation_id=None, enrollment_token_id=None,
                    enrollment_profile_id=None, device_identity=None):
    company = get_company_by_id(company_id)
    data = _encrypt_endpoint_fields(company, {
        "company_id":   company_id,
        "branch_id":    branch_id,
        "hostname":     hostname,
        "api_key_hash": api_key_hash,
        "status":       "offline",
        "enrolled_at":  _now_iso(),
    })
    if vpn_ip:
        data["vpn_ip"] = str(vpn_ip)
    if wg_pubkey:
        data["wg_pubkey"] = wg_pubkey
    if hardware_id:
        data.update(_encrypt_endpoint_fields(company, {"hardware_id": hardware_id}))
    if installation_id:
        data.update(_encrypt_endpoint_fields(company, {"installation_id": installation_id}))
    if enrollment_token_id:
        data["enrollment_token_id"] = enrollment_token_id
    if enrollment_profile_id:
        data["enrollment_profile_id"] = enrollment_profile_id
    if device_identity:
        data.update(_encrypt_endpoint_fields(company, {"device_identity": device_identity}))
    rows = _post("endpoints", data)
    row = rows[0] if (rows and isinstance(rows, list)) else rows
    return _decrypt_endpoint(row, company)


def get_endpoint_by_installation_id(company_id, installation_id):
    company = get_company_by_id(company_id)
    lookup = blind_index(company, installation_id, "endpoint.installation-id")
    rows = _get(
        f"endpoints?company_id=eq.{_q(company_id)}"
        f"&installation_id_hash=eq.{_q(lookup)}&limit=1"
    )
    return _decrypt_endpoint(rows[0], company) if rows else None


def get_endpoint_by_hardware_id(company_id, hardware_id):
    if not hardware_id:
        return None
    company = get_company_by_id(company_id)
    lookup = blind_index(company, hardware_id, "endpoint.hardware-id")
    rows = _get(
        f"endpoints?company_id=eq.{_q(company_id)}"
        f"&hardware_id_hash=eq.{_q(lookup)}&order=created_at.desc&limit=1"
    )
    return _decrypt_endpoint(rows[0], company) if rows else None


def recover_endpoint_enrollment(endpoint_id, hostname, api_key_hash):
    company = _endpoint_company(endpoint_id)
    rows = _patch(
        f"endpoints?id=eq.{_q(endpoint_id)}&is_active=eq.true",
        {**_encrypt_endpoint_fields(company, {"hostname": hostname}),
         "api_key_hash": api_key_hash},
    )
    return _decrypt_endpoint(rows[0], company) if rows else None


def reenroll_endpoint(endpoint_id, branch_id, hostname, api_key_hash,
                      hardware_id, enrollment_token_id, enrollment_profile_id=None,
                      device_identity=None, installation_id=None):
    """Re-enrol an existing installation in place.

    Manual retirement keeps the historical row and installation identity.
    Manual installer upgrades also keep that same identity. Reusing the row
    avoids a duplicate endpoint and the unique-installation-id collision while
    still requiring a fresh, tenant-scoped enrolment token.
    """
    company = _endpoint_company(endpoint_id)
    data = _encrypt_endpoint_fields(company, {
        "branch_id": branch_id,
        "hostname": hostname,
        "api_key_hash": api_key_hash,
        "hardware_id": hardware_id or None,
        "enrollment_token_id": enrollment_token_id,
        "is_active": True,
        "status": "offline",
        "enrolled_at": _now_iso(),
        "client_cert_fingerprint": None,
        "cloudflare_cert_id": None,
        "enrollment_profile_id": enrollment_profile_id,
        "device_identity": device_identity or {},
    })
    if installation_id:
        data.update(_encrypt_endpoint_fields(company, {"installation_id": installation_id}))
    rows = _patch(
        f"endpoints?id=eq.{_q(endpoint_id)}",
        data,
    )
    return _decrypt_endpoint(rows[0], company) if rows else None


def set_endpoint_client_cert(endpoint_id, fingerprint, cloudflare_cert_id):
    """Record a newly-issued mTLS client cert's fingerprint + Cloudflare
    cert ID (see services/agent_ca.py). Requires
    migrations/2026-07-30-add-client-cert-fields.sql applied first."""
    _patch(f"endpoints?id=eq.{_q(endpoint_id)}", {
        "client_cert_fingerprint": fingerprint,
        "cloudflare_cert_id": cloudflare_cert_id,
    })


def clear_endpoint_client_cert(endpoint_id):
    """Clear a revoked endpoint's stored fingerprint — combine with
    services.agent_ca.revoke_agent_cert(cloudflare_cert_id) to also delete
    it from Cloudflare; clearing only the local fingerprint fails our own
    cross-check but doesn't stop Cloudflare's edge from still accepting the
    cert on its own."""
    _patch(f"endpoints?id=eq.{_q(endpoint_id)}", {
        "client_cert_fingerprint": None,
        "cloudflare_cert_id": None,
    })


def update_endpoint_heartbeat(endpoint_id, cpu_pct, ram_used_pct, disk_free_gb, agent_version=None,
                              agent_memory_mb=None, agent_uptime_sec=None, last_seen_ip=None,
                              local_ip=None, device_type=None, platform=None,
                              capabilities=None, capability_details=None,
                              interactive_user_marker=False, interactive_user=None,
                              net_sent_mbps=None, net_recv_mbps=None, topology_telemetry=None):
    company = _endpoint_company(endpoint_id)
    data = {
        "status": "online",
        "last_seen": _now_iso(),
    }
    if cpu_pct is not None:
        data["cpu_pct"] = cpu_pct
    if ram_used_pct is not None:
        data["ram_used_pct"] = ram_used_pct
    if disk_free_gb is not None:
        data["disk_free_gb"] = disk_free_gb
    if agent_version:
        data["agent_version"] = agent_version
    if agent_memory_mb is not None:
        data["agent_memory_mb"] = agent_memory_mb
    if agent_uptime_sec is not None:
        data["agent_uptime_sec"] = agent_uptime_sec
    if net_sent_mbps is not None:
        data["net_sent_mbps"] = net_sent_mbps
    if net_recv_mbps is not None:
        data["net_recv_mbps"] = net_recv_mbps
    if isinstance(topology_telemetry, dict):
        data.update(_encrypt_endpoint_fields(
            company, {"topology_telemetry": topology_telemetry},
        ))
    if last_seen_ip:
        # Requires migrations/2026-07-30-add-last-seen-ip.sql applied to the
        # live DB first — PostgREST will reject the whole PATCH with an
        # unknown-column error otherwise, so deploy the migration before
        # this code.
        data["last_seen_ip"] = _endpoint_encrypt(company, "last_seen_ip", last_seen_ip)
    if local_ip:
        data["local_ip"] = _endpoint_encrypt(company, "local_ip", local_ip)
    if device_type in {"desktop", "laptop", "server", "iot", "unknown"}:
        data["device_type"] = device_type
    if platform in {"windows", "linux", "darwin", "unknown"}:
        data["platform"] = platform
    if isinstance(capabilities, list):
        data["capabilities"] = capabilities
    if isinstance(capability_details, dict):
        data.update(_encrypt_endpoint_fields(
            company, {"capability_details": capability_details},
        ))
    if interactive_user_marker:
        data["interactive_user"] = _endpoint_encrypt(
            company, "interactive_user", interactive_user,
        ) if interactive_user else None
        data["interactive_session_seen_at"] = _now_iso()
    data["private_data_encryption_version"] = 1
    _patch(f"endpoints?id=eq.{_q(endpoint_id)}", data)


def update_endpoint_sysinfo(endpoint_id, info):
    company = _endpoint_company(endpoint_id)
    data = {
        "os_name": info.get("os_name"),
        "os_version": info.get("os_version"),
        "os_build": info.get("os_build"),
        "os_edition": info.get("os_edition"),
        "arch": info.get("arch"),
        "cpu_model": info.get("cpu_model"),
        "ram_total_gb": info.get("ram_total_gb"),
        "disk_total_gb": info.get("disk_total_gb"),
        "platform": info.get("platform"),
    }
    filtered = {k: v for k, v in data.items() if v is not None}
    _patch(
        f"endpoints?id=eq.{_q(endpoint_id)}",
        _encrypt_endpoint_fields(company, filtered),
    )


def update_endpoint_hostname(endpoint_id, hostname):
    """Update the mutable device label without changing endpoint identity."""
    company = _endpoint_company(endpoint_id)
    _patch(
        f"endpoints?id=eq.{_q(endpoint_id)}",
        _encrypt_endpoint_fields(company, {"hostname": hostname}),
    )


def update_endpoint_nickname(endpoint_id, nickname):
    company = _endpoint_company(endpoint_id)
    _patch(f"endpoints?id=eq.{_q(endpoint_id)}",
           _encrypt_endpoint_fields(company, {"display_name": nickname or None}))


def set_endpoint_offline(endpoint_id):
    _patch(f"endpoints?id=eq.{_q(endpoint_id)}", {"status": "offline"})


def update_endpoint_notes(endpoint_id, notes, tags):
    company = _endpoint_company(endpoint_id)
    _patch(
        f"endpoints?id=eq.{_q(endpoint_id)}",
        _encrypt_endpoint_fields(company, {"notes": notes, "tags": tags}),
    )


# ── Physical topology / floor plans ─────────────────────────────────────────

def get_topology_floors(company_id, branch_id=None):
    path = f"topology_floors?company_id=eq.{_q(company_id)}&order=building.asc,level_order.asc,name.asc"
    if branch_id:
        path += f"&branch_id=eq.{_q(branch_id)}"
    return _get(path)


def get_topology_floor(floor_id):
    rows = _get(f"topology_floors?id=eq.{_q(floor_id)}&limit=1")
    return rows[0] if rows else None


def create_topology_floor(company_id, branch_id, building, name, level_order, aspect_ratio, created_by):
    rows = _post("topology_floors", {
        "company_id": company_id, "branch_id": branch_id or None,
        "building": building, "name": name, "level_order": level_order,
        "aspect_ratio": aspect_ratio, "created_by": created_by,
    })
    return rows[0] if rows else None


def update_topology_floor(floor_id, company_id, fields):
    fields = {key: value for key, value in fields.items()
              if key in {"building", "name", "level_order", "aspect_ratio", "layout_locked"}}
    fields["updated_at"] = _now_iso()
    rows = _patch(f"topology_floors?id=eq.{_q(floor_id)}&company_id=eq.{_q(company_id)}", fields)
    return rows[0] if rows else None


def delete_topology_floor(floor_id, company_id):
    _delete(f"topology_floors?id=eq.{_q(floor_id)}&company_id=eq.{_q(company_id)}")


def get_topology_rooms(company_id, floor_id):
    return _get(
        f"topology_rooms?company_id=eq.{_q(company_id)}&floor_id=eq.{_q(floor_id)}&order=name.asc"
    )


def get_topology_room(room_id):
    rows = _get(f"topology_rooms?id=eq.{_q(room_id)}&limit=1")
    return rows[0] if rows else None


def create_topology_room(company_id, floor_id, values):
    rows = _post("topology_rooms", {"company_id": company_id, "floor_id": floor_id, **values})
    return rows[0] if rows else None


def update_topology_room(room_id, company_id, values):
    fields = {key: value for key, value in values.items()
              if key in {"name", "x", "y", "width", "height", "color", "capacity"}}
    fields["updated_at"] = _now_iso()
    rows = _patch(f"topology_rooms?id=eq.{_q(room_id)}&company_id=eq.{_q(company_id)}", fields)
    return rows[0] if rows else None


def delete_topology_room(room_id, company_id):
    _delete(f"topology_rooms?id=eq.{_q(room_id)}&company_id=eq.{_q(company_id)}")


def get_topology_placements(company_id, floor_id=None):
    path = (
        "topology_endpoint_placements?select=endpoint_id,company_id,floor_id,room_id,x,y,updated_at"
        f"&company_id=eq.{_q(company_id)}"
    )
    if floor_id:
        path += f"&floor_id=eq.{_q(floor_id)}"
    return _get(path)


def upsert_topology_placement(company_id, floor_id, room_id, endpoint_id, x, y, updated_by):
    rows = _post("topology_endpoint_placements?on_conflict=endpoint_id", {
        "company_id": company_id, "floor_id": floor_id, "room_id": room_id or None,
        "endpoint_id": endpoint_id, "x": x, "y": y,
        "updated_by": updated_by, "updated_at": _now_iso(),
    }, prefer="resolution=merge-duplicates,return=representation")
    return rows[0] if rows else None


def delete_topology_placement(company_id, endpoint_id):
    _delete(
        f"topology_endpoint_placements?company_id=eq.{_q(company_id)}&endpoint_id=eq.{_q(endpoint_id)}"
    )


def get_topology_nodes(company_id, floor_id):
    return _get(
        f"topology_nodes?company_id=eq.{_q(company_id)}&floor_id=eq.{_q(floor_id)}&order=name.asc"
    )


def get_topology_node(node_id):
    rows = _get(f"topology_nodes?id=eq.{_q(node_id)}&limit=1")
    return rows[0] if rows else None


def create_topology_node(company_id, floor_id, values):
    rows = _post("topology_nodes", {"company_id": company_id, "floor_id": floor_id, **values})
    return rows[0] if rows else None


def update_topology_node(node_id, company_id, values):
    allowed = {"name", "node_type", "ip_address", "details", "room_id", "x", "y"}
    fields = {key: value for key, value in values.items() if key in allowed}
    fields["updated_at"] = _now_iso()
    rows = _patch(f"topology_nodes?id=eq.{_q(node_id)}&company_id=eq.{_q(company_id)}", fields)
    return rows[0] if rows else None


def delete_topology_node(node_id, company_id):
    _delete(f"topology_nodes?id=eq.{_q(node_id)}&company_id=eq.{_q(company_id)}")


def get_topology_links(company_id, floor_id):
    return _get(
        f"topology_links?company_id=eq.{_q(company_id)}&floor_id=eq.{_q(floor_id)}&order=created_at.asc"
    )


def create_topology_link(company_id, floor_id, values):
    rows = _post("topology_links", {"company_id": company_id, "floor_id": floor_id, **values})
    return rows[0] if rows else None


def get_topology_link(link_id):
    rows = _get(f"topology_links?id=eq.{_q(link_id)}&limit=1")
    return rows[0] if rows else None


def delete_topology_link(link_id, company_id):
    _delete(f"topology_links?id=eq.{_q(link_id)}&company_id=eq.{_q(company_id)}")


def delete_topology_links_for_object(company_id, object_type, object_id):
    _delete(
        f"topology_links?company_id=eq.{_q(company_id)}"
        f"&or=(and(source_type.eq.{_q(object_type)},source_id.eq.{_q(object_id)}),"
        f"and(target_type.eq.{_q(object_type)},target_id.eq.{_q(object_id)}))"
    )


def get_topology_snapshots(company_id, floor_id, limit=50):
    return _get(
        f"topology_snapshots?company_id=eq.{_q(company_id)}&floor_id=eq.{_q(floor_id)}"
        f"&select=id,floor_id,captured_at&order=captured_at.desc&limit={min(int(limit), 200)}"
    )


def get_topology_snapshot(snapshot_id, company_id, floor_id):
    rows = _get(
        f"topology_snapshots?id=eq.{_q(snapshot_id)}&company_id=eq.{_q(company_id)}"
        f"&floor_id=eq.{_q(floor_id)}&limit=1"
    )
    return rows[0] if rows else None


def create_topology_snapshot(company_id, floor_id, state):
    rows = _post("topology_snapshots", {
        "company_id": company_id, "floor_id": floor_id, "state": state,
    })
    return rows[0] if rows else None


def prune_topology_snapshots(company_id, floor_id, before):
    _delete(
        f"topology_snapshots?company_id=eq.{_q(company_id)}&floor_id=eq.{_q(floor_id)}"
        f"&captured_at=lt.{_q(before)}"
    )


def update_endpoint_asset(endpoint_id, values):
    allowed = {"asset_tag", "asset_state", "assigned_to", "purchase_date", "warranty_expiry", "asset_metadata"}
    payload = {key: value for key, value in values.items() if key in allowed}
    company = _endpoint_company(endpoint_id)
    payload = _encrypt_endpoint_fields(company, payload)
    rows = _patch(f"endpoints?id=eq.{_q(endpoint_id)}", payload)
    return _decrypt_endpoint(rows[0], company) if rows else None


def mark_endpoints_stale(minutes=3):
    cutoff = (
        datetime.now(timezone.utc) - timedelta(minutes=minutes)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    _patch(
        f"endpoints?status=eq.online&last_seen=lt.{_q(cutoff)}",
        {"status": "offline"}
    )


# ─────────────────────────────────────────────────────────────────────────────
# Firewall block list (application-level, administrator-controlled)
# ─────────────────────────────────────────────────────────────────────────────

def list_blocked_ips():
    return _get("firewall_blocked_ips?select=*&order=created_at.desc")


def is_ip_blocked(ip: str) -> bool:
    rows = _get(f"firewall_blocked_ips?ip_address=eq.{_q(ip)}"
                f"&or=(expires_at.is.null,expires_at.gt.{_q(_now_iso())})&limit=1")
    return bool(rows)


def block_ip(ip: str, reason: str, created_by=None, expires_at=None):
    data = {"ip_address": ip, "reason": reason}
    if created_by:
        data["created_by"] = created_by
    if expires_at:
        data["expires_at"] = expires_at
    rows = _post("firewall_blocked_ips", data)
    return rows[0] if rows else None


def unblock_ip(ip: str) -> None:
    _delete(f"firewall_blocked_ips?ip_address=eq.{_q(ip)}")


# ─────────────────────────────────────────────────────────────────────────────
# Jobs
# ─────────────────────────────────────────────────────────────────────────────

def _decrypt_job(job, company=None):
    """Job payload/log_output/error_msg are stored encrypted per-tenant
    (see services/tenant_crypto.py) — decrypt in place before handing a
    job row back to any caller. Raises tenant_crypto.VaultLocked if the
    job's company is BYOK-mode and currently locked; callers that can't
    tolerate that (e.g. dispatching to an agent) must catch it."""
    if job is None:
        return None
    company = company or get_company_by_id(job["company_id"])
    if job.get("payload") is not None:
        job["payload"] = decrypt_field(company, job["payload"], "job.payload")
    if job.get("log_output") is not None:
        job["log_output"] = decrypt_field(company, job["log_output"], "job.log-output")
    if job.get("error_msg") is not None:
        job["error_msg"] = decrypt_field(company, job["error_msg"], "job.error-message")
    if (job.get("type") == "APPLY_DEVICE_EXPERIENCE" and job.get("status") == "failed"
            and job.get("exit_code") == 408 and not job.get("error_msg")):
        job["error_msg"] = "Deployment expired after the 3-day delivery window. Redeploy it for this endpoint."
    return job


def get_jobs(company_id, endpoint_id=None, status=None, branch_id=None, limit=50, offset=0):
    path = (
        f"jobs?company_id=eq.{_q(company_id)}"
        f"&order=created_at.desc&limit={limit}&offset={offset}"
    )
    if endpoint_id:
        path += f"&endpoint_id=eq.{_q(endpoint_id)}"
    if status:
        path += f"&status=eq.{_q(status)}"
    if branch_id:
        path += f"&branch_id=eq.{_q(branch_id)}"
    rows = _get(path)
    company = get_company_by_id(company_id)
    return [_decrypt_job(j, company) for j in rows]


def get_home_sync_jobs(company_id, status=None, branch_id=None, limit=20):
    """Read tenant-scoped Home results without exposing expiring job grants."""
    path = (
        f"jobs?company_id=eq.{_q(company_id)}&type=eq.SYNC_WARDEN_HOME"
        "&select=id,endpoint_id,company_id,branch_id,status,created_at,started_at,"
        "completed_at,exit_code,log_output,error_msg"
        f"&order=created_at.desc&limit={min(100, max(1, int(limit)))}"
    )
    if status:
        path += f"&status=eq.{_q(status)}"
    if branch_id:
        path += f"&branch_id=eq.{_q(branch_id)}"
    company = get_company_by_id(company_id)
    return [_decrypt_job(row, company) for row in _get(path)]


def get_job(job_id, decrypt=True):
    rows = _get(f"jobs?id=eq.{_q(job_id)}&limit=1")
    if not rows:
        return None
    return _decrypt_job(rows[0]) if decrypt else rows[0]


def has_inflight_job(endpoint_id, job_type):
    """True if endpoint_id already has a not-yet-finished job of job_type
    (pending/approved/running) — used by the auto-update scheduler so a slow
    UPDATE_AGENT job (or one still waiting on the endpoint's next poll) isn't
    re-dispatched again on every 60s scheduler tick before it's had a chance
    to complete."""
    rows = _get(
        f"jobs?endpoint_id=eq.{_q(endpoint_id)}&type=eq.{_q(job_type)}"
        f"&status=in.(pending,approved,running)&limit=1"
    )
    return bool(rows)


def get_endpoint_home_sync_jobs(company_id, endpoint_id):
    """Read sync timing without decrypting payloads or retaining Home grants."""
    path = (
        f"jobs?company_id=eq.{_q(company_id)}&endpoint_id=eq.{_q(endpoint_id)}"
        "&type=eq.SYNC_WARDEN_HOME&select=id,status,created_at,completed_at"
    )
    active = _get(path + "&status=in.(pending,approved,running)&limit=1")
    if active:
        return active
    return _get(
        path + "&status=in.(completed,failed,cancelled)"
        "&order=completed_at.desc.nullslast,created_at.desc&limit=4"
    )


def has_recent_job(endpoint_id, job_type, minutes=15):
    """Return whether an operation was recently queued for this endpoint."""
    cutoff = (
        datetime.now(timezone.utc) - timedelta(minutes=max(1, int(minutes)))
    ).isoformat()
    rows = _get(
        f"jobs?endpoint_id=eq.{_q(endpoint_id)}&type=eq.{_q(job_type)}"
        f"&created_at=gte.{_q(cutoff)}&select=id&limit=1"
    )
    return bool(rows)


def has_job(endpoint_id, job_type):
    """True when this endpoint has ever received this one-shot operation."""
    rows = _get(
        f"jobs?endpoint_id=eq.{_q(endpoint_id)}&type=eq.{_q(job_type)}"
        "&select=id&limit=1"
    )
    return bool(rows)


def create_job(company_id, branch_id, endpoint_id, job_type, payload, created_by,
               requires_dual_approval=False, escalation_id=None, expires_at=None):
    company = get_company_by_id(company_id)
    data = {
        "company_id": company_id,
        "branch_id": branch_id,
        "endpoint_id": endpoint_id,
        "type": job_type,
        "payload": encrypt_field(company, payload, "job.payload") if payload is not None else None,
        "status": "pending",
        "created_by": created_by,
        "requires_dual_approval": requires_dual_approval,
    }
    if expires_at:
        data["expires_at"] = expires_at
    if escalation_id:
        data["escalation_id"] = escalation_id
    rows = _post("jobs", data)
    job = rows[0] if (rows and isinstance(rows, list)) else rows
    if job:
        job["payload"] = payload  # return the plaintext the caller just gave us
    return job


def create_system_job_once(company_id, branch_id, endpoint_id, job_type, payload):
    """Atomically create scheduler work unless the same operation is active."""
    company = get_company_by_id(company_id)
    rows = _rpc("create_system_job_once", {
        "p_company_id": str(company_id),
        "p_branch_id": str(branch_id) if branch_id else None,
        "p_endpoint_id": str(endpoint_id),
        "p_type": job_type,
        "p_encrypted_payload": encrypt_field(company, payload, "job.payload") if payload is not None else None,
    }) or []
    job = rows[0] if rows else None
    if job:
        job["payload"] = payload
    return job


def _company_for_job(job_id):
    rows = _get(f"jobs?id=eq.{_q(job_id)}&select=company_id&limit=1")
    if not rows:
        return None
    return get_company_by_id(rows[0]["company_id"])


def update_job_status(job_id, status, log_output=None, exit_code=None, error_msg=None):
    company = _company_for_job(job_id) if (log_output is not None or error_msg is not None) else None
    data = {"status": status}
    if log_output is not None:
        data["log_output"] = encrypt_field(company, log_output, "job.log-output")
    if exit_code is not None:
        data["exit_code"] = exit_code
    if error_msg is not None:
        data["error_msg"] = encrypt_field(company, error_msg, "job.error-message")
    if status == "running":
        data["started_at"] = _now_iso()
    elif status in ("completed", "failed", "cancelled"):
        data["completed_at"] = _now_iso()
    _patch(f"jobs?id=eq.{_q(job_id)}", data)


def finish_running_job(job_id, status, log_output=None, exit_code=None, error_msg=None):
    """Atomically finish a running job.

    Only the first result report wins.  Agent HTTP retries or stale reports
    for cancelled/completed jobs return False and must not repeat downstream
    side effects such as alerts, escalation completion, or audit events.
    """
    company = _company_for_job(job_id) if (log_output is not None or error_msg is not None) else None
    data = {
        "status": status,
        "completed_at": _now_iso(),
        "lease_expires_at": None,
    }
    if log_output is not None:
        data["log_output"] = encrypt_field(company, log_output, "job.log-output")
    if exit_code is not None:
        data["exit_code"] = exit_code
    if error_msg is not None:
        data["error_msg"] = encrypt_field(company, error_msg, "job.error-message")
    rows = _patch(
        f"jobs?id=eq.{_q(job_id)}&status=eq.running",
        data,
    )
    return bool(rows)


def claim_job_result_processing(job_id):
    return bool(_rpc("claim_job_result_processing", {"p_job_id": str(job_id)}))


def complete_job_result_processing(job_id):
    return bool(_rpc("complete_job_result_processing", {"p_job_id": str(job_id)}))


def append_job_log(job_id, new_lines):
    rows = _get(f"jobs?id=eq.{_q(job_id)}&select=company_id,log_output&limit=1")
    if not rows:
        return
    company = get_company_by_id(rows[0]["company_id"])
    existing = decrypt_field(company, rows[0].get("log_output"), "job.log-output") or ""
    _patch(f"jobs?id=eq.{_q(job_id)}", {
        "log_output": encrypt_field(company, existing + new_lines, "job.log-output"),
    })


def get_pending_jobs_for_endpoint(endpoint_id, decrypt=False, limit=5):
    """Atomically lease runnable work to one endpoint.

    Expired running leases are reclaimed; live leases are never returned a
    second time. This makes heartbeat polling independent from execution
    without allowing the same command to run concurrently.
    """
    rows = _rpc("claim_jobs_for_endpoint", {
        "p_endpoint_id": str(endpoint_id),
        "p_limit": max(1, min(int(limit), 20)),
        "p_lease_seconds": 900,
    }) or []
    if not decrypt:
        return rows
    company = None
    out = []
    for j in rows:
        company = company or get_company_by_id(j["company_id"])
        out.append(_decrypt_job(j, company))
    return out


def create_policy_deployment(company_id, branch_id, template, payload, created_by,
                             reason=None, idempotency_key=None, endpoint_ids=None,
                             target_selector=None, rollout_percentage=100):
    """Atomically create a policy rollout and all of its endpoint jobs."""
    company = get_company_by_id(company_id)
    encrypted_payload = encrypt_field(company, payload, "job.payload")
    params = {
        "p_company_id": str(company_id),
        "p_branch_id": str(branch_id),
        "p_template_id": str(template["id"]),
        "p_template_name": template["name"],
        "p_encrypted_payload": encrypted_payload,
        "p_created_by": str(created_by),
        "p_reason": reason or None,
        "p_idempotency_key": idempotency_key or None,
    }
    rpc_name = "create_policy_deployment"
    if endpoint_ids is not None:
        rpc_name = "create_targeted_policy_deployment"
        params.update({
            "p_endpoint_ids": [str(value) for value in endpoint_ids],
            "p_target_selector": target_selector or {},
            "p_rollout_percentage": int(rollout_percentage),
        })
    rows = _rpc(rpc_name, params) or []
    return rows[0] if rows else None


def cancel_policy_deployment(deployment_id, company_id):
    return int(_rpc("cancel_policy_deployment", {
        "p_deployment_id": str(deployment_id),
        "p_company_id": str(company_id),
    }) or 0)


def retry_policy_deployment(deployment_id, company_id):
    return int(_rpc("retry_policy_deployment", {
        "p_deployment_id": str(deployment_id),
        "p_company_id": str(company_id),
    }) or 0)


def maybe_pause_policy_deployment(job_id):
    return _rpc("maybe_pause_policy_deployment", {"p_job_id": str(job_id)})


def refresh_policy_deployment_status(job_id):
    return _rpc("refresh_policy_deployment_status", {"p_job_id": str(job_id)})


def get_policy_deployment(deployment_id):
    rows = _get(f"policy_deployments?id=eq.{_q(deployment_id)}&limit=1")
    return rows[0] if rows else None


def get_policy_deployments(company_id, limit=20):
    rows = _rpc("get_policy_deployment_summaries", {
        "p_company_id": str(company_id),
        "p_limit": max(1, min(int(limit), 100)),
    }) or []
    for row in rows:
        row["counts"] = {
            key: int(row.pop(key, 0) or 0)
            for key in ("pending", "running", "completed", "failed", "cancelled")
        }
    return rows


def cancel_job(job_id, admin_id):
    company = _company_for_job(job_id)
    rows = _patch(f"jobs?id=eq.{_q(job_id)}&status=in.(pending,approved)", {
        "status": "cancelled",
        "completed_at": _now_iso(),
        "error_msg": encrypt_field(company, f"Cancelled by admin {admin_id}", "job.error-message"),
    })
    return bool(rows)


# ─────────────────────────────────────────────────────────────────────────────
# Windows Users
# ─────────────────────────────────────────────────────────────────────────────

def get_windows_users(endpoint_id):
    return _get(
        "windows_users?select=id,endpoint_id,username,display_name,sid,principal_name,"
        "account_type,domain_name,is_admin,is_enabled,present,first_seen,last_synced,"
        f"profile_photo_mime&endpoint_id=eq.{_q(endpoint_id)}"
        f"&present=eq.true&order=username.asc"
    )


def get_windows_user(user_id):
    rows = _get(f"windows_users?id=eq.{_q(user_id)}&limit=1")
    return rows[0] if rows else None


def get_company_windows_users(company_id, branch_id=None):
    """Return current Windows accounts with endpoint context in one query."""
    company = get_company_by_id(company_id)
    endpoint_filter = f"endpoints.company_id=eq.{_q(company_id)}"
    if branch_id:
        endpoint_filter += f"&endpoints.branch_id=eq.{_q(branch_id)}"
    rows = _get(
        "windows_users?select=id,endpoint_id,username,display_name,sid,"
        "principal_name,account_type,domain_name,is_admin,is_enabled,"
        "first_seen,last_synced,profile_photo_mime,endpoints!inner(id,hostname,display_name,"
        f"branch_id,status,company_id,is_active)&present=eq.true&{endpoint_filter}"
        "&endpoints.is_active=eq.true"
        "&order=username.asc"
    )
    for row in rows:
        if row.get("endpoints"):
            row["endpoints"] = _decrypt_endpoint(row["endpoints"], company)
    return rows


def replace_windows_users(endpoint_id, users):
    """Atomically mark missing accounts absent and upsert the current scan."""
    return _rpc("replace_windows_users", {
        "p_endpoint_id": endpoint_id,
        "p_users": users,
    })


def upsert_windows_user(endpoint_id, username, is_admin, is_enabled, display_name=None,
                        profile_photo=None):
    rows = _get(f"windows_users?endpoint_id=eq.{_q(endpoint_id)}&username=eq.{_q(username)}&limit=1")
    data = {
        "is_admin": is_admin,
        "is_enabled": is_enabled,
        "present": True,
        "last_synced": _now_iso(),
    }
    if display_name:
        data["display_name"] = display_name
    if profile_photo:
        data["profile_photo"] = profile_photo
        data["profile_photo_mime"] = "image/png"
    if rows:
        _patch(f"windows_users?endpoint_id=eq.{_q(endpoint_id)}&username=eq.{_q(username)}", data)
    else:
        data.update({"endpoint_id": endpoint_id, "username": username})
        _post("windows_users", data)


def delete_windows_user(endpoint_id, username):
    _delete(f"windows_users?endpoint_id=eq.{_q(endpoint_id)}&username=eq.{_q(username)}")


def set_windows_user_state(endpoint_id, username, is_enabled=None, is_admin=None):
    """Optimistic update after a CREATE_USER/DISABLE_USER/ENABLE_USER/
    GRANT_ELEVATION/REVOKE_ELEVATION job completes, so the Users tab
    reflects Warden's own action immediately without waiting on a separate
    COLLECT_USERS scan. Only patches the row if it already exists — a full
    COLLECT_USERS scan is still what establishes a row's existence and
    other real fields (display_name) in the first place."""
    rows = _get(f"windows_users?endpoint_id=eq.{_q(endpoint_id)}&username=eq.{_q(username)}&limit=1")
    if not rows:
        return
    data = {}
    if is_enabled is not None:
        data["is_enabled"] = is_enabled
    if is_admin is not None:
        data["is_admin"] = is_admin
    if data:
        _patch(f"windows_users?endpoint_id=eq.{_q(endpoint_id)}&username=eq.{_q(username)}", data)


# ─────────────────────────────────────────────────────────────────────────────
# Warden identities (desired state; separate from discovered local accounts)
# ─────────────────────────────────────────────────────────────────────────────

def get_warden_identities(company_id):
    rows = _get(
        "warden_identities?select=id,company_id,username,login_email,display_name,is_admin,"
        "is_enabled,password_version,password_setup_required,offline_access_hours,session_version,conditional_access,profile_photo_mime,"
        "created_at,updated_at,password_changed_at,"
        "warden_identity_assignments(id,endpoint_id,status,password_version,"
        "last_job_id,last_error,assigned_at,updated_at,last_synced_at,"
        "endpoints(id,hostname,display_name,status,branch_id,is_active))"
        f"&company_id=eq.{_q(company_id)}&order=display_name.asc,username.asc"
    )
    company = get_company_by_id(company_id)
    for row in rows:
        for assignment in row.get("warden_identity_assignments") or []:
            if assignment.get("endpoints"):
                assignment["endpoints"] = _decrypt_endpoint(
                    assignment["endpoints"], company,
                )
    return rows


def get_warden_identity(identity_id, company_id):
    rows = _get(
        f"warden_identities?id=eq.{_q(identity_id)}&company_id=eq.{_q(company_id)}"
        "&select=*&limit=1"
    )
    return rows[0] if rows else None


def get_warden_identity_for_login(company_id, endpoint_id, username):
    login = _q(username)
    rows = _get(
        "warden_identities?select=id,company_id,username,login_email,display_name,password_hash,"
        "is_admin,is_enabled,password_version,password_setup_required,offline_access_hours,session_version,"
        "failed_attempts,locked_until,conditional_access,"
        "warden_identity_assignments!inner(id,endpoint_id,status,password_version)"
        f"&company_id=eq.{_q(company_id)}&or=(username.ilike.{login},login_email.ilike.{login})"
        f"&warden_identity_assignments.endpoint_id=eq.{_q(endpoint_id)}&limit=1"
    )
    return rows[0] if rows else None


def record_warden_login_failure(identity_id, lock_after=5, lock_minutes=15):
    return _rpc("record_warden_login_failure", {
        "p_identity_id": str(identity_id), "p_lock_after": int(lock_after),
        "p_lock_minutes": int(lock_minutes),
    })


def record_warden_login_success(identity_id):
    return _rpc("record_warden_login_success", {"p_identity_id": str(identity_id)})


def log_warden_identity_login(company_id, endpoint_id, username, outcome,
                              identity_id=None, reason=None, source_ip=None,
                              offline_grant_hours=None):
    return _post("warden_identity_login_events", {
        "company_id": company_id, "identity_id": identity_id,
        "endpoint_id": endpoint_id, "username": username,
        "outcome": outcome, "reason": reason,
        "source_ip": source_ip or None,
        "offline_grant_hours": offline_grant_hours,
    }, prefer="return=minimal")


def get_warden_identity_login_events(company_id, limit=50):
    rows = _get(
        "warden_identity_login_events?select=id,identity_id,endpoint_id,username,"
        "outcome,reason,source_ip,offline_grant_hours,created_at,"
        "endpoints(hostname,display_name)&company_id=eq."
        f"{_q(company_id)}&order=created_at.desc&limit={max(1, min(int(limit), 200))}"
    )
    company = get_company_by_id(company_id)
    for row in rows:
        if row.get("endpoints"):
            row["endpoints"] = _decrypt_endpoint(row["endpoints"], company)
    return rows


def create_warden_identity(company_id, username, display_name, password_hash,
                           is_admin, created_by):
    rows = _post("warden_identities", {
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
    rows = _rpc("create_warden_identity_and_jobs", {
        "p_company_id": str(company["id"]), "p_username": username,
        "p_display_name": display_name, "p_password_hash": password_hash,
        "p_is_admin": bool(is_admin), "p_created_by": str(created_by),
        "p_endpoint_ids": [str(value) for value in endpoint_ids],
        "p_profile_photo": profile_photo or None,
        "p_profile_photo_mime": profile_photo_mime or None,
        "p_encrypted_payload": encrypt_field(company, payload, "job.payload"),
    }) or []
    return rows[0] if rows else None


def create_warden_identity_with_setup_and_jobs(
    company, username, login_email, display_name, placeholder_password_hash, is_admin,
    created_by, endpoint_ids, payload, setup_token_hash, setup_expires_at,
    profile_photo="", profile_photo_mime="",
):
    rows = _rpc("create_warden_identity_with_setup_and_jobs", {
        "p_company_id": str(company["id"]), "p_username": username,
        "p_login_email": login_email,
        "p_display_name": display_name,
        "p_placeholder_password_hash": placeholder_password_hash,
        "p_is_admin": bool(is_admin), "p_created_by": str(created_by),
        "p_endpoint_ids": [str(value) for value in endpoint_ids],
        "p_profile_photo": profile_photo or None,
        "p_profile_photo_mime": profile_photo_mime or None,
        "p_encrypted_payload": encrypt_field(company, payload, "job.payload"),
        "p_setup_token_hash": setup_token_hash,
        "p_setup_expires_at": setup_expires_at,
    }) or []
    return rows[0] if rows else None


def get_warden_identity_for_password_setup(token_hash):
    rows = _get(
        "warden_identities?select=id,username,login_email,display_name,password_setup_required,"
        "password_setup_expires_at&password_setup_token_hash=eq."
        f"{_q(token_hash)}&limit=1"
    )
    return rows[0] if rows else None


def complete_warden_identity_password_setup(token_hash, password_hash):
    rows = _rpc("complete_warden_identity_password_setup", {
        "p_token_hash": token_hash, "p_password_hash": password_hash,
    }) or []
    return rows[0] if rows else None


def rotate_warden_identity_password(company, identity_id, password_hash,
                                    created_by, payload):
    return _rpc("rotate_warden_identity_password", {
        "p_company_id": str(company["id"]), "p_identity_id": str(identity_id),
        "p_password_hash": password_hash, "p_created_by": str(created_by),
        "p_encrypted_payload": encrypt_field(company, payload, "job.payload"),
    })


def set_warden_identity_enabled(company, identity_id, enabled, created_by, payload):
    return _rpc("set_warden_identity_enabled", {
        "p_company_id": str(company["id"]), "p_identity_id": str(identity_id),
        "p_enabled": bool(enabled), "p_created_by": str(created_by),
        "p_encrypted_payload": encrypt_field(company, payload, "job.payload"),
    })


def reassign_warden_identity(company, identity_id, endpoint_ids, created_by,
                             provision_payload, revoke_payload):
    rows = _rpc("reassign_warden_identity", {
        "p_company_id": str(company["id"]), "p_identity_id": str(identity_id),
        "p_endpoint_ids": [str(value) for value in endpoint_ids],
        "p_created_by": str(created_by),
        "p_provision_payload": encrypt_field(company, provision_payload, "job.payload"),
        "p_revoke_payload": encrypt_field(company, revoke_payload, "job.payload"),
    }) or []
    return rows[0] if rows else None


def update_warden_identity(identity_id, company_id, fields):
    return _patch(
        f"warden_identities?id=eq.{_q(identity_id)}&company_id=eq.{_q(company_id)}",
        {**fields, "updated_at": _now_iso()},
    )


def get_warden_identity_assignment(identity_id, endpoint_id):
    rows = _get(
        f"warden_identity_assignments?identity_id=eq.{_q(identity_id)}"
        f"&endpoint_id=eq.{_q(endpoint_id)}&limit=1"
    )
    return rows[0] if rows else None


def get_active_warden_usernames_for_endpoint(endpoint_id):
    rows = _get(
        "warden_identity_assignments?select=status,warden_identities(username,is_enabled)"
        f"&endpoint_id=eq.{_q(endpoint_id)}&status=eq.active"
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
    rows = _get(
        "warden_identity_assignments?select=status,warden_identities(username)"
        f"&endpoint_id=eq.{_q(endpoint_id)}&status=neq.revoked"
    )
    usernames = []
    for row in rows:
        identity = row.get("warden_identities") or {}
        if identity.get("username"):
            usernames.append(str(identity["username"]))
    return list(dict.fromkeys(usernames))


def upsert_warden_identity_assignment(identity_id, endpoint_id, status,
                                      password_version, job_id=None, error=None):
    existing = get_warden_identity_assignment(identity_id, endpoint_id)
    data = {
        "status": status,
        "password_version": int(password_version),
        "last_job_id": job_id,
        "last_error": error,
        "updated_at": _now_iso(),
    }
    if status == "active":
        data["last_synced_at"] = _now_iso()
    if existing:
        rows = _patch(f"warden_identity_assignments?id=eq.{_q(existing['id'])}", data)
        return rows[0] if rows else None
    data.update({"identity_id": identity_id, "endpoint_id": endpoint_id})
    rows = _post("warden_identity_assignments", data)
    return rows[0] if rows else None


def mark_warden_assignment_job_result(job_id, succeeded, error=None, success_status="active"):
    rows = _get(
        f"warden_identity_assignments?last_job_id=eq.{_q(job_id)}&select=id&limit=1"
    )
    if not rows:
        return None
    data = {
        "status": success_status if succeeded else "failed",
        "last_error": None if succeeded else str(error or "Agent operation failed")[:1000],
        "updated_at": _now_iso(),
    }
    if succeeded:
        data["last_synced_at"] = _now_iso()
    return _patch(f"warden_identity_assignments?id=eq.{_q(rows[0]['id'])}", data)


# ─────────────────────────────────────────────────────────────────────────────
# Software Inventory
# ─────────────────────────────────────────────────────────────────────────────

def get_software(endpoint_id, search=None, limit=100, offset=0):
    path = f"software_inventory?endpoint_id=eq.{_q(endpoint_id)}&order=name.asc&limit={limit}&offset={offset}"
    if search:
        path += f"&name=ilike.{_q('%' + search + '%')}"
    return _get(path)


def replace_software_inventory(endpoint_id, items):
    _delete(f"software_inventory?endpoint_id=eq.{_q(endpoint_id)}")
    if items:
        for item in items:
            item["endpoint_id"] = endpoint_id
        _post("software_inventory", items, prefer="return=minimal")


def replace_patch_inventory(company_id, endpoint_id, items):
    _delete(f"patch_inventory?endpoint_id=eq.{_q(endpoint_id)}")
    if items:
        now = _now_iso()
        rows = []
        for item in items:
            row = dict(item)
            row.update({"company_id": company_id, "endpoint_id": endpoint_id, "reported_at": now})
            rows.append(row)
        _post("patch_inventory", rows, prefer="return=minimal")


def get_patch_inventory(company_id):
    return _get(f"patch_inventory?company_id=eq.{_q(company_id)}&order=severity.desc,title.asc")


def get_patch_policies(company_id):
    return _get(f"patch_policies?company_id=eq.{_q(company_id)}&order=name.asc")


def get_patch_policy(policy_id):
    rows = _get(f"patch_policies?id=eq.{_q(policy_id)}&limit=1")
    return rows[0] if rows else None


def create_patch_policy(data):
    rows = _post("patch_policies", data)
    return rows[0] if rows else None


def get_patch_deployments(company_id, limit=30):
    return _get(
        f"patch_deployments?company_id=eq.{_q(company_id)}"
        f"&select=*,patch_policies(name)&order=created_at.desc&limit={min(int(limit), 100)}"
    )


def create_patch_deployment(company, policy, pilot_ids, broad_ids, payload, created_by):
    encrypted = encrypt_field(company, payload, "job.payload")
    return _rpc("create_patch_deployment", {
        "p_company_id": str(company["id"]), "p_policy_id": str(policy["id"]),
        "p_pilot_ids": [str(item) for item in pilot_ids],
        "p_broad_ids": [str(item) for item in broad_ids],
        "p_encrypted_payload": encrypted, "p_created_by": str(created_by),
    })


def get_due_patch_deployments():
    return _get("patch_deployments?status=in.(pilot,waiting)&broad_at=lte.now()&select=id")


def promote_patch_deployment(deployment_id):
    return int(_rpc("promote_patch_deployment", {"p_deployment_id": str(deployment_id)}) or 0)


def refresh_patch_deployment(job_id, succeeded):
    return _rpc("refresh_patch_deployment", {
        "p_job_id": str(job_id), "p_succeeded": bool(succeeded),
    })


def replace_network_flows(company_id, endpoint_id, flows):
    # Keep a bounded seven-day diagnostic window and cap each observation.
    cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    _delete(f"network_flows?endpoint_id=eq.{_q(endpoint_id)}&observed_at=lt.{_q(cutoff)}")
    rows = []
    for flow in list(flows)[:1000]:
        rows.append({**flow, "company_id": company_id, "endpoint_id": endpoint_id})
    if rows:
        try:
            _post("network_flows", rows, prefer="return=minimal")
        except urllib.error.HTTPError as exc:
            # PostgREST's short JSON diagnostic identifies a rejected column
            # without logging the submitted endpoint telemetry itself.
            detail = exc.read(2048).decode("utf-8", errors="replace")
            raise RuntimeError(f"network flow storage rejected: {detail}") from exc


def get_network_flows(company_id, endpoint_id=None, limit=500):
    path = f"network_flows?company_id=eq.{_q(company_id)}&order=observed_at.desc&limit={min(int(limit), 1000)}"
    if endpoint_id:
        path += f"&endpoint_id=eq.{_q(endpoint_id)}"
    return _get(path)


def get_vulnerability_advisories(limit=5000):
    return _get(f"vulnerability_advisories?order=known_exploited.desc,updated_at.desc&limit={min(int(limit), 10000)}")


def upsert_vulnerability_advisories(rows):
    if rows:
        return _post("vulnerability_advisories?on_conflict=id", rows,
                     prefer="resolution=merge-duplicates,return=minimal")


def replace_vulnerability_findings(company_id, endpoint_id, findings):
    now = _now_iso()
    seen = set()
    existing = _get(f"vulnerability_findings?endpoint_id=eq.{_q(endpoint_id)}")
    existing_by_key = {
        (str(row.get("software_id")), str(row.get("advisory_id"))): row
        for row in existing
    }
    for item in findings:
        software_id = str(item["software"]["id"])
        advisory_id = str(item["advisory"]["id"])
        key = (software_id, advisory_id)
        seen.add(key)
        row = existing_by_key.get(key)
        fields = {"confidence": item["confidence"], "evidence": item["evidence"], "last_seen": now}
        if row:
            _patch(f"vulnerability_findings?id=eq.{_q(row['id'])}", fields)
        else:
            _post("vulnerability_findings", {
                **fields, "company_id": company_id, "endpoint_id": endpoint_id,
                "software_id": software_id, "advisory_id": advisory_id,
            }, prefer="return=minimal")
    # Findings absent from the new inventory are remediated, while explicit
    # accepted-risk/false-positive decisions remain untouched.
    for row in existing:
        key = (str(row.get("software_id")), str(row.get("advisory_id")))
        if key not in seen and row.get("status") == "open":
            _patch(f"vulnerability_findings?id=eq.{_q(row['id'])}", {
                "status": "remediated", "resolved_at": now,
            })


def get_vulnerability_findings(company_id, limit=1000, status=None, endpoint_id=None):
    status_filter = f"&status=eq.{_q(status)}" if status else ""
    endpoint_filter = f"&endpoint_id=eq.{_q(endpoint_id)}" if endpoint_id else ""
    rows = _get(
        f"vulnerability_findings?company_id=eq.{_q(company_id)}"
        f"{status_filter}{endpoint_filter}"
        "&select=*,endpoints(id,hostname,display_name),software_inventory(name,version,publisher),"
        f"vulnerability_advisories(*)&order=first_seen.desc&limit={min(int(limit), 2000)}"
    )
    company = get_company_by_id(company_id)
    for row in rows:
        if row.get("endpoints"):
            row["endpoints"] = _decrypt_endpoint(row["endpoints"], company)
    return rows


def get_vulnerability_finding(finding_id):
    rows = _get(f"vulnerability_findings?id=eq.{_q(finding_id)}&limit=1")
    return rows[0] if rows else None


def update_vulnerability_finding(finding_id, status):
    fields = {"status": status}
    fields["resolved_at"] = _now_iso() if status in {"remediated", "false_positive"} else None
    rows = _patch(f"vulnerability_findings?id=eq.{_q(finding_id)}", fields)
    return rows[0] if rows else None


# ─────────────────────────────────────────────────────────────────────────────
# Warden Home storage control plane
# ─────────────────────────────────────────────────────────────────────────────

def get_home_nodes(company_id):
    return _get(f"home_storage_nodes?company_id=eq.{_q(company_id)}&order=priority.asc,name.asc")


def create_home_node(data):
    rows = _post("home_storage_nodes", data)
    return rows[0] if rows else None


def update_home_node(node_id, company_id, data):
    rows = _patch(
        f"home_storage_nodes?id=eq.{_q(node_id)}&company_id=eq.{_q(company_id)}",
        {**data, "updated_at": _now_iso()},
    )
    return rows[0] if rows else None


def get_home_node_by_key_hash(key_hash):
    rows = _get(f"home_storage_nodes?node_key_hash=eq.{_q(key_hash)}&limit=1")
    return rows[0] if rows else None


def update_home_node_heartbeat(node_id, fields):
    return _patch(f"home_storage_nodes?id=eq.{_q(node_id)}", {
        **fields, "status": "online", "last_seen": _now_iso(), "updated_at": _now_iso(),
    })


def create_home_p2p_session(company_id, endpoint_id, node_id, offer_sdp):
    # Rendezvous rows contain short-lived network candidates, never file data,
    # credentials, grants, or encryption keys.
    _delete(f"home_p2p_sessions?expires_at=lt.{_q(_now_iso())}")
    _delete(
        f"home_p2p_sessions?endpoint_id=eq.{_q(endpoint_id)}&node_id=eq.{_q(node_id)}"
        "&status=eq.offered"
    )
    rows = _post("home_p2p_sessions", {
        "company_id": company_id, "endpoint_id": endpoint_id,
        "node_id": node_id, "offer_sdp": offer_sdp,
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=2)).isoformat(),
    })
    return rows[0] if rows else None


def create_home_node_p2p_session(company_id, initiator_node_id, node_id, offer_sdp):
    _delete(f"home_p2p_sessions?expires_at=lt.{_q(_now_iso())}")
    _delete(
        f"home_p2p_sessions?initiator_node_id=eq.{_q(initiator_node_id)}"
        f"&node_id=eq.{_q(node_id)}&status=eq.offered"
    )
    rows = _post("home_p2p_sessions", {
        "company_id": company_id, "initiator_node_id": initiator_node_id,
        "node_id": node_id, "offer_sdp": offer_sdp,
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=2)).isoformat(),
    })
    return rows[0] if rows else None


def get_home_p2p_session(session_id, endpoint_id=None, node_id=None, initiator_node_id=None):
    query = f"home_p2p_sessions?id=eq.{_q(session_id)}"
    if endpoint_id:
        query += f"&endpoint_id=eq.{_q(endpoint_id)}"
    if node_id:
        query += f"&node_id=eq.{_q(node_id)}"
    if initiator_node_id:
        query += f"&initiator_node_id=eq.{_q(initiator_node_id)}"
    rows = _get(query + "&limit=1")
    return rows[0] if rows else None


def get_home_p2p_offers(node_id, limit=8):
    _delete(f"home_p2p_sessions?expires_at=lt.{_q(_now_iso())}")
    return _get(
        f"home_p2p_sessions?node_id=eq.{_q(node_id)}&status=eq.offered"
        f"&expires_at=gt.{_q(_now_iso())}"
        "&select=id,endpoint_id,initiator_node_id,offer_sdp,expires_at"
        f"&order=created_at.asc&limit={max(1, min(int(limit), 20))}"
    )


def answer_home_p2p_session(session_id, node_id, answer_sdp):
    rows = _patch(
        f"home_p2p_sessions?id=eq.{_q(session_id)}&node_id=eq.{_q(node_id)}"
        "&status=eq.offered",
        {"answer_sdp": answer_sdp, "status": "answered", "answered_at": _now_iso()},
    )
    return rows[0] if rows else None


def fail_home_p2p_session(session_id, node_id, message):
    rows = _patch(
        f"home_p2p_sessions?id=eq.{_q(session_id)}&node_id=eq.{_q(node_id)}"
        "&status=eq.offered",
        {"status": "failed", "error_message": str(message or "P2P negotiation failed")[:500]},
    )
    return rows[0] if rows else None


def get_home_spaces(company_id):
    return _get(
        f"home_spaces?company_id=eq.{_q(company_id)}"
        "&select=*,home_space_nodes(priority,writable,role,home_storage_nodes(*))&order=name.asc"
    )


def get_home_space(space_id):
    rows = _get(
        f"home_spaces?id=eq.{_q(space_id)}"
        "&select=*,home_space_nodes(priority,writable,role,home_storage_nodes(*))&limit=1"
    )
    return rows[0] if rows else None


def create_home_space(data, memberships):
    rows = _post("home_spaces", data)
    space = rows[0] if rows else None
    if space and memberships:
        _post("home_space_nodes", [
            {"space_id": space["id"], **membership}
            for membership in memberships
        ], prefer="return=minimal")
    return space


def update_home_space_topology(space_id, company_id, state):
    rows = _patch(
        f"home_spaces?id=eq.{_q(space_id)}&company_id=eq.{_q(company_id)}",
        {"active_writer_state": state, "updated_at": _now_iso()},
    )
    return rows[0] if rows else None


def get_home_assignments(company_id):
    return _get(
        f"home_assignments?company_id=eq.{_q(company_id)}"
        "&select=*,home_spaces(id,name)&order=created_at.desc"
    )


def create_home_assignment(data):
    rows = _post("home_assignments", data)
    return rows[0] if rows else None


def update_home_assignment(assignment_id, company_id, data):
    rows = _patch(
        f"home_assignments?id=eq.{_q(assignment_id)}&company_id=eq.{_q(company_id)}",
        data,
    )
    return rows[0] if rows else None


def delete_home_assignment(assignment_id, company_id):
    _delete(f"home_assignments?id=eq.{_q(assignment_id)}&company_id=eq.{_q(company_id)}")


def log_home_access(company_id, endpoint_id, identity_id, space_id, node_id, action, detail=None):
    return _post("home_access_log", {
        "company_id": company_id, "endpoint_id": endpoint_id,
        "identity_id": identity_id, "space_id": space_id, "node_id": node_id,
        "action": action, "detail": detail or {},
    }, prefer="return=minimal")


# ─────────────────────────────────────────────────────────────────────────────
# Escalation Requests
# ─────────────────────────────────────────────────────────────────────────────

def _decrypt_escalation(esc, company=None):
    if esc is None:
        return None
    company = company or get_company_by_id(esc["company_id"])
    if esc.get("payload") is not None:
        esc["payload"] = decrypt_field(company, esc["payload"], "escalation.payload")
    if esc.get("reason") is not None:
        esc["reason"] = decrypt_field(company, esc["reason"], "escalation.reason")
    if esc.get("result_log") is not None:
        esc["result_log"] = decrypt_field(company, esc["result_log"], "escalation.result-log")
    return esc


def get_escalation_requests(company_id, status=None, branch_id=None, limit=50, offset=0):
    path = (
        f"escalation_requests?company_id=eq.{_q(company_id)}"
        f"&order=requested_at.desc&limit={limit}&offset={offset}"
    )
    if status:
        path += f"&status=eq.{_q(status)}"
    if branch_id:
        path += f"&branch_id=eq.{_q(branch_id)}"
    rows = _get(path)
    company = get_company_by_id(company_id)
    return [_decrypt_escalation(e, company) for e in rows]


def get_escalation_request(req_id):
    rows = _get(f"escalation_requests?id=eq.{_q(req_id)}&limit=1")
    if not rows:
        return None
    return _decrypt_escalation(rows[0])


def create_escalation_request(company_id, branch_id, endpoint_id, windows_user,
                               operation, payload, reason, requires_dual=False,
                               requested_by=None):
    company = get_company_by_id(company_id)
    expires_at = (
        datetime.now(timezone.utc) +
        timedelta(minutes=config.ESCALATION_WINDOW_MINUTES)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    rows = _post("escalation_requests", {
        "company_id": company_id,
        "branch_id": branch_id,
        "endpoint_id": endpoint_id,
        "windows_user": windows_user,
        "operation": operation,
        "payload": encrypt_field(company, payload, "escalation.payload") if payload is not None else None,
        "reason": encrypt_field(company, reason, "escalation.reason") if reason is not None else None,
        "status": "pending",
        "expires_at": expires_at,
        "requires_dual_approval": requires_dual,
        "requested_by": requested_by,
    })
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
    import secrets as _s, hashlib as _hl
    token = _s.token_urlsafe(32)
    token_hash = _hl.sha256(token.encode()).hexdigest()
    token_expires = (
        datetime.now(timezone.utc) + timedelta(minutes=30)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    req = get_escalation_request(req_id)
    if req and req.get("requested_by") and str(req["requested_by"]) == str(admin_id):
        return None, None
    if is_secondary and req and req.get("reviewed_by") and str(req["reviewed_by"]) == str(admin_id):
        return None, None
    # The database function locks the row and repeats both independence
    # checks. Application checks above give callers a clean response; the DB
    # guard prevents a race or alternate code path bypassing the rule.
    rows = _rpc("approve_escalation_request", {
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
    company = get_company_by_id(req["company_id"]) if req else None
    return token, _decrypt_escalation(rows[0], company)


def deny_escalation(req_id, admin_id):
    _patch(f"escalation_requests?id=eq.{_q(req_id)}", {
        "status": "denied",
        "reviewed_by": admin_id,
        "reviewed_at": _now_iso(),
    })


def complete_escalation(req_id, result_log, exit_code):
    company = _get_escalation_company(req_id)
    _patch(f"escalation_requests?id=eq.{_q(req_id)}", {
        "status": "completed",
        "result_log": encrypt_field(company, result_log, "escalation.result-log") if result_log is not None else None,
        "result_exit": exit_code,
    })


def _get_escalation_company(req_id):
    rows = _get(f"escalation_requests?id=eq.{_q(req_id)}&select=company_id&limit=1")
    if not rows:
        return None
    return get_company_by_id(rows[0]["company_id"])


def expire_stale_escalations():
    _patch(
        f"escalation_requests?status=in.(pending,pending_secondary)&expires_at=lt.{_q(_now_iso())}",
        {"status": "expired"}
    )


def count_pending_escalations(company_id, branch_id=None):
    path = f"escalation_requests?company_id=eq.{_q(company_id)}&status=eq.pending&select=id"
    if branch_id:
        path += f"&branch_id=eq.{_q(branch_id)}"
    rows = _get(path)
    return len(rows)


# ─────────────────────────────────────────────────────────────────────────────
# Saved Escalations (Policies)
# ─────────────────────────────────────────────────────────────────────────────

def get_saved_escalations(company_id):
    return _get(
        f"saved_escalations?company_id=eq.{_q(company_id)}"
        f"&revoked_at=is.null&order=approved_at.desc"
    )


def get_saved_escalation(policy_id):
    rows = _get(f"saved_escalations?id=eq.{_q(policy_id)}&limit=1")
    return rows[0] if rows else None


def create_saved_escalation(company_id, scope, operation, payload_match,
                             approved_by, valid_days=None, note=None,
                             branch_id=None, endpoint_id=None, windows_user=None):
    data = {
        "company_id": company_id,
        "scope": scope,
        "operation": operation,
        "payload_match": payload_match,
        "approved_by": approved_by,
        "approved_at": _now_iso(),
        "valid_from": _now_iso(),
        "note": note,
    }
    if valid_days:
        data["valid_until"] = (
            datetime.now(timezone.utc) + timedelta(days=valid_days)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
    if branch_id:
        data["branch_id"] = branch_id
    if endpoint_id:
        data["endpoint_id"] = endpoint_id
    if windows_user:
        data["windows_user"] = windows_user
    rows = _post("saved_escalations", data)
    return rows[0] if (rows and isinstance(rows, list)) else rows


def revoke_saved_escalation(policy_id, admin_id):
    _patch(f"saved_escalations?id=eq.{_q(policy_id)}", {
        "revoked_by": admin_id,
        "revoked_at": _now_iso(),
    })


def find_matching_policy(company_id, endpoint_id, windows_user, operation, payload):
    now = _now_iso()
    rows = _get(
        f"saved_escalations?company_id=eq.{_q(company_id)}&operation=eq.{_q(operation)}"
        f"&revoked_at=is.null&or=(valid_until.is.null,valid_until.gt.{_q(now)})"
    )
    for p in rows:
        scope = p.get("scope", "")
        if "this_endpoint" in scope and p.get("endpoint_id") != endpoint_id:
            continue
        if "this_user" in scope and p.get("windows_user") and p["windows_user"] != windows_user:
            continue
        match = p.get("payload_match") or {}
        if all(str(payload.get(k)) == str(v) for k, v in match.items()):
            return p
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Alerts
# ─────────────────────────────────────────────────────────────────────────────

def get_alerts(company_id, resolved=False, branch_id=None, limit=50, offset=0, snoozed=False):
    path = (
        f"alerts?company_id=eq.{_q(company_id)}"
        f"&is_resolved=eq.{str(resolved).lower()}"
        f"&order=created_at.desc&limit={limit}&offset={offset}"
    )
    path += "&select=*,endpoints(id,hostname,display_name)"
    if branch_id:
        path += f"&branch_id=eq.{_q(branch_id)}"
    if snoozed and not resolved:
        path += f"&snoozed_until=gt.{_q(_now_iso())}"
    elif not resolved:
        path += f"&or=(snoozed_until.is.null,snoozed_until.lte.{_q(_now_iso())})"
    company = get_company_by_id(company_id)
    return [_decrypt_alert(row, company) for row in _get(path)]


def get_alert(alert_id):
    rows = _get(f"alerts?id=eq.{_q(alert_id)}&select=*,endpoints(id,hostname,display_name)&limit=1")
    return _decrypt_alert(rows[0]) if rows else None


def _decrypt_alert(row, company=None):
    if not row:
        return row
    company = company or get_company_by_id(row["company_id"])
    result = dict(row)
    for field in ("title", "message", "resolution_note"):
        result[field] = _endpoint_decrypt(
            company, f"alert.{field}", result.get(field),
        )
    # Alert titles created before endpoint records were consistently
    # decrypted may contain the encrypted hostname as their first word.
    # Recover that embedded hostname so existing alerts remain readable.
    title = result.get("title")
    if isinstance(title, str) and title.startswith("v2:") and result.get("endpoint_id"):
        encrypted_hostname, separator, remainder = title.partition(" ")
        hostname = _endpoint_decrypt(company, "hostname", encrypted_hostname)
        if hostname != encrypted_hostname:
            result["title"] = f"{hostname}{separator}{remainder}"
    encrypted = result.pop("detail_encrypted", None)
    if encrypted:
        result["detail"] = _endpoint_decrypt(company, "alert.detail", encrypted)
    if result.get("endpoints"):
        endpoint = _decrypt_endpoint(result.pop("endpoints"), company)
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
    company = get_company_by_id(company_id)
    rows = _post("alerts", {
        "company_id": company_id,
        "branch_id": branch_id,
        "endpoint_id": endpoint_id,
        "type": alert_type,
        "severity": severity,
        "title": _endpoint_encrypt(company, "alert.title", title),
        "message": _endpoint_encrypt(company, "alert.message", message),
        "detail": {},
        "detail_encrypted": _endpoint_encrypt(company, "alert.detail", detail or {}),
        "is_resolved": False,
    })
    row = rows[0] if (rows and isinstance(rows, list)) else rows
    return _decrypt_alert(row, company)


def get_open_enrollment_alert(company_id, profile_id, hostname):
    """Find a matching unresolved enrollment failure to avoid retry spam."""
    rows = _get(
        f"alerts?company_id=eq.{_q(company_id)}"
        "&type=eq.enrollment_rejected&is_resolved=eq.false"
        "&order=created_at.desc&limit=100"
    ) or []
    company = get_company_by_id(company_id)
    rows = [_decrypt_alert(row, company) for row in rows]
    wanted_profile = str(profile_id or "")
    wanted_hostname = str(hostname or "").casefold()
    for row in rows:
        detail = row.get("detail") or {}
        if (str(detail.get("profile_id") or "") == wanted_profile
                and str(detail.get("hostname") or "").casefold() == wanted_hostname):
            return row
    return None


def resolve_alert(alert_id, admin_id, note=None):
    raw = _get(f"alerts?id=eq.{_q(alert_id)}&select=company_id&limit=1")
    company = get_company_by_id(raw[0]["company_id"]) if raw else None
    _patch(f"alerts?id=eq.{_q(alert_id)}", {
        "is_resolved": True,
        "resolved_by": admin_id,
        "resolved_at": _now_iso(),
        "resolution_note": (
            _endpoint_encrypt(company, "alert.resolution_note", note)
            if company and note is not None else None
        ),
        "snoozed_until": None,
    })


def reopen_alert(alert_id):
    _patch(f"alerts?id=eq.{_q(alert_id)}", {
        "is_resolved": False,
        "resolved_by": None,
        "resolved_at": None,
        "resolution_note": None,
    })


def assign_alert(alert_id, admin_id=None):
    _patch(f"alerts?id=eq.{_q(alert_id)}", {"assigned_to": admin_id})


def snooze_alert(alert_id, until):
    _patch(f"alerts?id=eq.{_q(alert_id)}", {"snoozed_until": until})


def count_open_alerts(company_id, branch_id=None):
    path = f"alerts?company_id=eq.{_q(company_id)}&is_resolved=eq.false&select=id"
    if branch_id:
        path += f"&branch_id=eq.{_q(branch_id)}"
    path += f"&or=(snoozed_until.is.null,snoozed_until.lte.{_q(_now_iso())})"
    rows = _get(path)
    return len(rows)


# ─────────────────────────────────────────────────────────────────────────────
# App Library
# ─────────────────────────────────────────────────────────────────────────────

def get_app_library(company_id=None, include_global=True):
    if include_global and company_id:
        rows = _get(f"app_library?or=(company_id.is.null,company_id.eq.{_q(company_id)})&order=name.asc")
    elif company_id:
        rows = _get(f"app_library?company_id=eq.{_q(company_id)}&order=name.asc")
    else:
        rows = _get("app_library?company_id=is.null&order=name.asc")
    return rows


def get_app(app_id):
    rows = _get(f"app_library?id=eq.{_q(app_id)}&limit=1")
    return rows[0] if rows else None


def create_app(name, version, sha256, file_path, size_bytes, company_id=None,
               description=None, install_args="", self_service=False):
    rows = _post("app_library", {
        "name": name,
        "version": version,
        "sha256": sha256,
        "file_path": file_path,
        "size_bytes": size_bytes,
        "company_id": company_id,
        "description": description,
        "install_args": install_args,
        "self_service": bool(self_service),
    })
    return rows[0] if (rows and isinstance(rows, list)) else rows


def update_app(app_id, values):
    allowed = {"name", "version", "description", "install_args", "self_service"}
    payload = {key: value for key, value in values.items() if key in allowed}
    if not payload:
        return get_app(app_id)
    rows = _patch(f"app_library?id=eq.{_q(app_id)}", payload)
    return rows[0] if rows else None


def delete_app(app_id):
    _delete(f"app_library?id=eq.{_q(app_id)}")


# ─────────────────────────────────────────────────────────────────────────────
# Audit Log
# ─────────────────────────────────────────────────────────────────────────────

def audit(company_id, actor_id, action, detail=None, branch_id=None,
          endpoint_id=None, escalation_id=None):
    event_detail = detail or {}
    company = get_company_by_id(company_id) if company_id else None
    _post("audit_log", {
        "company_id": company_id,
        "actor_id": actor_id,
        "action": action,
        "detail": {} if company else event_detail,
        "detail_encrypted": (
            _endpoint_encrypt(company, "audit.detail", event_detail)
            if company else None
        ),
        "branch_id": branch_id,
        "endpoint_id": endpoint_id,
        "escalation_id": escalation_id,
    }, prefer="return=minimal")
    # Structured stdout is the vendor-neutral SIEM integration point. Avoid
    # duplicating potentially personal audit detail into container logs; the
    # digest lets an investigator match an exported database record exactly.
    detail_digest = hashlib.sha256(
        json.dumps(event_detail, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()
    log.info("SECURITY_AUDIT %s", json.dumps({
        "action": action,
        "company_id": str(company_id) if company_id else None,
        "actor_id": str(actor_id) if actor_id else None,
        "branch_id": str(branch_id) if branch_id else None,
        "endpoint_id": str(endpoint_id) if endpoint_id else None,
        "detail_sha256": detail_digest,
        "recorded_at": _now_iso(),
    }, separators=(",", ":")))


def verify_audit_chain():
    result = _rpc("verify_audit_chain", {})
    return result or {"rows": 0, "broken": 0, "valid": True}


def get_audit_log(company_id, limit=100, offset=0, endpoint_id=None, actor_id=None,
                  branch_id=None):
    path = (
        f"audit_log?company_id=eq.{_q(company_id)}"
        f"&order=created_at.desc&limit={limit}&offset={offset}"
    )
    if endpoint_id:
        path += f"&endpoint_id=eq.{_q(endpoint_id)}"
    if actor_id:
        path += f"&actor_id=eq.{_q(actor_id)}"
    if branch_id:
        path += f"&branch_id=eq.{_q(branch_id)}"
    company = get_company_by_id(company_id)
    rows = _get(path)
    for row in rows:
        encrypted = row.pop("detail_encrypted", None)
        if encrypted:
            row["detail"] = _endpoint_decrypt(company, "audit.detail", encrypted)
    return rows


# ─────────────────────────────────────────────────────────────────────────────
# Endpoint Metrics
# ─────────────────────────────────────────────────────────────────────────────

def insert_metric(endpoint_id, cpu_pct, ram_used_pct, disk_free_gb):
    # endpoint_metrics stores disk_free_pct; we omit disk here since the
    # current disk_free_gb is always available on the endpoints row itself.
    _post("endpoint_metrics", {
        "endpoint_id": endpoint_id,
        "cpu_pct": cpu_pct,
        "ram_used_pct": ram_used_pct,
    }, prefer="return=minimal")


def get_metrics(endpoint_id, hours=24):
    cutoff = (
        datetime.now(timezone.utc) - timedelta(hours=hours)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    return _get(
        f"endpoint_metrics?endpoint_id=eq.{_q(endpoint_id)}"
        f"&collected_at=gt.{_q(cutoff)}&order=collected_at.asc"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Endpoint Events
# ─────────────────────────────────────────────────────────────────────────────

def log_endpoint_event(endpoint_id, event_type, detail=None):
    company = _endpoint_company(endpoint_id)
    _post("endpoint_events", {
        "endpoint_id": endpoint_id,
        "event_type": event_type,
        "detail": {},
        "detail_encrypted": _endpoint_encrypt(
            company, "event.detail", detail or {},
        ),
    }, prefer="return=minimal")


def get_endpoint_events(endpoint_id, limit=50):
    rows = _get(
        f"endpoint_events?endpoint_id=eq.{_q(endpoint_id)}"
        f"&order=created_at.desc&limit={limit}"
    )
    company = _endpoint_company(endpoint_id)
    for row in rows:
        encrypted = row.pop("detail_encrypted", None)
        if encrypted:
            row["detail"] = _endpoint_decrypt(company, "event.detail", encrypted)
    return rows


def get_recent_endpoint_events(endpoint_id, event_type, since_iso, limit=50):
    """Events of a given type for this endpoint since a given ISO timestamp —
    used by alert_engine.py's anomaly checks (e.g. counting how many
    tls_cert_rotation_detected or ip_changed events happened in a recent
    window, rather than reacting to any single occurrence of either, which
    can be entirely legitimate on its own)."""
    rows = _get(
        f"endpoint_events?endpoint_id=eq.{_q(endpoint_id)}"
        f"&event_type=eq.{_q(event_type)}"
        f"&created_at=gte.{_q(since_iso)}"
        f"&order=created_at.desc&limit={limit}"
    )
    company = _endpoint_company(endpoint_id)
    for row in rows:
        encrypted = row.pop("detail_encrypted", None)
        if encrypted:
            row["detail"] = _endpoint_decrypt(company, "event.detail", encrypted)
    return rows


# ─────────────────────────────────────────────────────────────────────────────
# Build Requests
# ─────────────────────────────────────────────────────────────────────────────

def create_build_request(company_id, branch_id, enrollment_token_id, config_json, created_by,
                         target_platform="windows-amd64"):
    rows = _post("build_requests", {
        "company_id": company_id,
        "branch_id": branch_id,
        "enrollment_token_id": enrollment_token_id,
        "config_json": config_json,
        "status": "pending",
        "requested_by": created_by,
        "target_platform": target_platform,
    })
    return rows[0] if (rows and isinstance(rows, list)) else rows


def get_build_request(req_id):
    rows = _get(f"build_requests?id=eq.{_q(req_id)}&limit=1")
    return rows[0] if rows else None


def get_pending_build_requests():
    return _get("build_requests?status=eq.pending&order=created_at.asc&limit=5")


def get_build_requests(company_id, limit=20):
    return _get(
        f"build_requests?company_id=eq.{_q(company_id)}"
        f"&order=created_at.desc&limit={limit}"
    )


def update_build_request(req_id, status, artifact_url=None, error=None, sha256=None, agent_version=None):
    data = {"status": status}
    if artifact_url:
        data["download_path"] = artifact_url
    if error:
        data["build_log"] = str(error)[:4000]
    if sha256:
        data["sha256"] = sha256
    if agent_version:
        data["agent_version"] = agent_version
    if status == "completed":
        data["completed_at"] = _now_iso()
    _patch(f"build_requests?id=eq.{_q(req_id)}", data)


def complete_claimed_build(req_id, claim_token, artifact_url, sha256=None, agent_version=None):
    data = {
        "status": "completed", "download_path": artifact_url,
        "completed_at": _now_iso(), "lease_expires_at": None,
    }
    if sha256:
        data["sha256"] = sha256
    if agent_version:
        data["agent_version"] = agent_version
    rows = _patch(
        f"build_requests?id=eq.{_q(req_id)}&status=eq.building"
        f"&claim_token=eq.{_q(claim_token)}",
        data,
    )
    return bool(rows)


def mark_build_msi_ready(req_id):
    _patch(f"build_requests?id=eq.{_q(req_id)}", {"msi_ready": True})


def mark_claimed_build_msi_ready(req_id, claim_token):
    rows = _patch(
        f"build_requests?id=eq.{_q(req_id)}&status=eq.completed"
        f"&claim_token=eq.{_q(claim_token)}",
        {"msi_ready": True},
    )
    return bool(rows)


def get_latest_completed_build(target_platform="windows-amd64"):
    """The most recent successfully completed agent build, across ALL
    tenants — the compiled exe is byte-identical regardless of which
    tenant's config.json a given build bundled alongside it (only
    config.json is per-tenant; the binary itself isn't), so any completed
    build can serve as the canonical "latest agent" for UPDATE_AGENT jobs.
    """
    rows = _get(
        "build_requests?status=eq.completed&sha256=not.is.null"
        f"&target_platform=eq.{_q(target_platform)}&order=completed_at.desc&limit=1"
    )
    return rows[0] if rows else None


def endpoint_target_platform(endpoint):
    platform = str(endpoint.get("platform") or "windows").lower()
    arch = str(endpoint.get("arch") or "amd64").lower()
    if arch in {"x86_64", "x64", "amd64"}:
        arch = "amd64"
    elif arch in {"aarch64", "arm64"}:
        arch = "arm64"
    else:
        arch = "amd64"
    if platform == "windows":
        arch = "amd64"
    return f"{platform}-{arch}"


# ─────────────────────────────────────────────────────────────────────────────
# Remote Sessions
# ─────────────────────────────────────────────────────────────────────────────

def create_remote_session(endpoint_id, admin_id, company_id):
    return _rpc("create_or_get_remote_session", {
        "p_endpoint_id": str(endpoint_id),
        "p_company_id": str(company_id),
        "p_admin_id": str(admin_id) if admin_id else None,
    })


def update_remote_session_controls(session_id, access_mode, capabilities, reason, consent_required):
    rows = _patch(f"remote_sessions?id=eq.{_q(session_id)}", {
        "access_mode": access_mode,
        "capabilities": capabilities,
        "reason": reason or None,
        "consent_required": bool(consent_required),
        "consent_status": "pending" if consent_required else "not_required",
    })
    return rows[0] if isinstance(rows, list) and rows else None


def close_remote_session(session_id):
    _patch(f"remote_sessions?id=eq.{_q(session_id)}", {
        "status": "closed",
        "ended_at": _now_iso(),
        "vnc_token": None,
    })


def get_remote_sessions(endpoint_id, limit=20):
    return _get(
        f"remote_sessions?select=*,admin_users(full_name,email)"
        f"&endpoint_id=eq.{_q(endpoint_id)}"
        f"&order=started_at.desc&limit={limit}"
    )


def get_remote_session(session_id):
    rows = _get(f"remote_sessions?id=eq.{_q(session_id)}&limit=1")
    return rows[0] if rows else None


def get_active_remote_session(endpoint_id, max_age_seconds=3700):
    """Return a plausible active session for an endpoint.

    The relay has a one-hour hard limit, so an older row cannot still be live.
    The former two-minute cutoff was much too short and created conflicting
    sessions during normal support calls; having no cutoff at all made rows
    left by an old crash reusable forever.
    """
    rows = _get(
        f"remote_sessions?endpoint_id=eq.{_q(endpoint_id)}&status=eq.active"
        f"&order=started_at.desc&limit=1"
    )
    if not rows:
        return None
    session = rows[0]
    started = _parse_dt_iso(session.get("started_at"))
    if not started:
        return None
    age = (datetime.now(timezone.utc) - started).total_seconds()
    if age > max_age_seconds:
        mark_remote_session_failed(session["id"], "stale remote session expired")
        return None
    return session


def close_all_active_remote_sessions(reason="remote relay restarted"):
    """Invalidate relay rows on process start.

    WebSocket pairs live only in this process, so none can survive a server
    restart. Leaving their bearer tokens active makes the UI reuse sessions
    that have no corresponding relay or agent connection.
    """
    return _patch("remote_sessions?status=eq.active", {
        "status": "closed",
        "ended_at": _now_iso(),
        "fail_reason": reason,
        "vnc_token": None,
    })


def _parse_dt_iso(dt_str):
    if not dt_str:
        return None
    try:
        return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
    except Exception:
        return None


def update_remote_session_token(session_id, vnc_token, novnc_path):
    _patch(f"remote_sessions?id=eq.{_q(session_id)}", {
        "vnc_token":    vnc_token,
        "novnc_path":   novnc_path,
    })


def get_remote_session_by_token(token: str):
    rows = _get(f"remote_sessions?vnc_token=eq.{_q(token)}&limit=1")
    return rows[0] if rows else None


def mark_remote_session_failed(session_id, reason):
    """Called when the agent reports its side of a remote-desktop pairing
    attempt failed (see routes/agent_api.py's remote_relay_failed()) — closes
    the session with the real reason recorded, so the viewer can show it
    within a few seconds instead of only finding out via ws_proxy's 60s
    PAIR_TIMEOUT generic timeout message."""
    _patch(f"remote_sessions?id=eq.{_q(session_id)}", {
        "status": "closed",
        "fail_reason": reason,
        "ended_at": _now_iso(),
        "vnc_token": None,
    })


def create_remote_session_event(session_id, company_id, admin_id, event_type, body, metadata=None):
    rows = _post("remote_session_events", {
        "session_id": session_id,
        "company_id": company_id,
        "admin_id": admin_id,
        "event_type": event_type,
        "body": body,
        "metadata": metadata or {},
    })
    return rows[0] if isinstance(rows, list) and rows else rows


def get_remote_session_events(session_id, limit=200):
    return _get(
        f"remote_session_events?session_id=eq.{_q(session_id)}"
        f"&order=created_at.asc&limit={int(limit)}"
    )


def update_remote_session_support_state(session_id, **fields):
    allowed = {"consent_status", "recording_status", "reconnect_until"}
    data = {key: value for key, value in fields.items() if key in allowed}
    if data:
        _patch(f"remote_sessions?id=eq.{_q(session_id)}", data)


def create_remote_support_link(endpoint_id, company_id, created_by, token_hash, expires_at, max_uses=1):
    rows = _post("remote_support_links", {
        "endpoint_id": endpoint_id,
        "company_id": company_id,
        "created_by": created_by,
        "token_hash": token_hash,
        "expires_at": expires_at,
        "max_uses": max_uses,
    })
    return rows[0] if isinstance(rows, list) and rows else rows


def get_remote_support_link_by_hash(token_hash):
    rows = _get(f"remote_support_links?token_hash=eq.{_q(token_hash)}&limit=1")
    return rows[0] if rows else None


def claim_remote_support_link(token_hash):
    rows = _rpc("claim_remote_support_link", {"p_token_hash": token_hash})
    return rows[0] if isinstance(rows, list) and rows else None


def release_remote_support_link_claim(link_id):
    """Return one claimed support-link use if session/job creation fails."""
    return bool(_rpc("release_remote_support_link_claim", {"p_link_id": link_id}))


# ─────────────────────────────────────────────────────────────────────────────
# Notifications
# ─────────────────────────────────────────────────────────────────────────────

def create_notification(admin_id, company_id, title, message, notif_type="info", link=None):
    _post("notifications", {
        "admin_id": admin_id,
        "company_id": company_id,
        "title": title,
        "message": message,
        "type": notif_type,
        "link": link,
    }, prefer="return=minimal")


def get_notifications(admin_id, unread_only=False, limit=30):
    path = f"notifications?admin_id=eq.{_q(admin_id)}&order=created_at.desc&limit={limit}"
    if unread_only:
        path += "&is_read=eq.false"
    return _get(path)


def count_unread_notifications(admin_id):
    rows = _get(f"notifications?admin_id=eq.{_q(admin_id)}&is_read=eq.false&select=id")
    return len(rows)


def mark_notifications_read(admin_id):
    _patch(f"notifications?admin_id=eq.{_q(admin_id)}&is_read=eq.false", {
        "is_read": True,
        "read_at": _now_iso(),
    })


def cleanup_expired_tokens():
    """Delete expired, revoked refresh tokens older than 7 days."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        url = (
            f"{config.SUPABASE_URL}/refresh_tokens"
            f"?revoked=eq.true&created_at=lt.{_q(cutoff)}"
        )
        headers = dict(_HEADERS)
        headers["Content-Profile"] = "endpt"
        req = urllib.request.Request(url, method="DELETE", headers=headers)
        urllib.request.urlopen(req, timeout=10, context=_SSL_CTX)
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Compliance policies
# ─────────────────────────────────────────────────────────────────────────────

def create_compliance_policy(company_id, branch_id, name, description, checks, created_by):
    data = {
        "company_id": str(company_id),
        "name": name,
        "description": description or "",
        "checks": checks,
        "enabled": True,
        "created_by": str(created_by) if created_by else None,
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
    }
    if branch_id:
        data["branch_id"] = str(branch_id)
    rows = _post("compliance_policies", data)
    return rows[0] if (rows and isinstance(rows, list)) else rows


def get_compliance_policies(company_id, branch_id=None):
    q = f"compliance_policies?company_id=eq.{_q(str(company_id))}&order=created_at.asc"
    if branch_id:
        q += f"&branch_id=eq.{_q(str(branch_id))}"
    return _get(q) or []


def get_compliance_policy(policy_id):
    rows = _get(f"compliance_policies?id=eq.{_q(str(policy_id))}&limit=1")
    return rows[0] if rows else None


def update_compliance_policy(policy_id, name, description, checks, enabled):
    _patch(f"compliance_policies?id=eq.{_q(str(policy_id))}", {
        "name": name,
        "description": description or "",
        "checks": checks,
        "enabled": enabled,
        "updated_at": _now_iso(),
    })


def delete_compliance_policy(policy_id):
    _delete(f"compliance_policies?id=eq.{_q(str(policy_id))}")


# ─────────────────────────────────────────────────────────────────────────────
# Compliance results
# ─────────────────────────────────────────────────────────────────────────────

def upsert_compliance_result(endpoint_id, company_id, policy_id, overall_status, score, results):
    # Use POST with upsert (on_conflict=endpoint_id)
    data = {
        "endpoint_id": str(endpoint_id),
        "company_id": str(company_id),
        "overall_status": overall_status,
        "score": score,
        "results": results,
        "scanned_at": _now_iso(),
    }
    if policy_id:
        data["policy_id"] = str(policy_id)
    _post("compliance_results", data,
          prefer="resolution=merge-duplicates,return=representation")


def get_compliance_result(endpoint_id):
    rows = _get(f"compliance_results?endpoint_id=eq.{_q(str(endpoint_id))}&limit=1")
    return rows[0] if rows else None


def get_compliance_results_for_company(company_id, branch_id=None):
    return _get(
        f"compliance_results?company_id=eq.{_q(str(company_id))}&order=scanned_at.desc"
    ) or []


# ─────────────────────────────────────────────────────────────────────────────
# Scheduled jobs
# ─────────────────────────────────────────────────────────────────────────────

def create_scheduled_job(company_id, branch_id, endpoint_id, name, job_type, payload, interval_seconds, created_by):
    from datetime import datetime, timezone, timedelta
    next_run = (datetime.now(timezone.utc) + timedelta(seconds=interval_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
    data = {
        "company_id": str(company_id),
        "name": name,
        "job_type": job_type,
        "payload": payload or {},
        "enabled": True,
        "interval_seconds": interval_seconds,
        "next_run_at": next_run,
        "created_at": _now_iso(),
    }
    if branch_id:
        data["branch_id"] = str(branch_id)
    if endpoint_id:
        data["endpoint_id"] = str(endpoint_id)
    if created_by:
        data["created_by"] = str(created_by)
    rows = _post("scheduled_jobs", data)
    return rows[0] if (rows and isinstance(rows, list)) else rows


def get_scheduled_jobs(company_id):
    return _get(
        f"scheduled_jobs?company_id=eq.{_q(str(company_id))}&order=created_at.desc"
    ) or []


def get_scheduled_job(job_id):
    rows = _get(f"scheduled_jobs?id=eq.{_q(str(job_id))}&limit=1")
    return rows[0] if rows else None


def update_scheduled_job(job_id, enabled):
    _patch(f"scheduled_jobs?id=eq.{_q(str(job_id))}", {"enabled": enabled})


def delete_scheduled_job(job_id):
    _delete(f"scheduled_jobs?id=eq.{_q(str(job_id))}")


def get_due_scheduled_jobs():
    """Atomically claim due schedules and advance their next run.

    Advancing in the same transaction as selection prevents two scheduler
    processes from dispatching the same occurrence. A process crash can skip
    one occurrence, but cannot duplicate privileged endpoint commands.
    """
    return _rpc("claim_due_scheduled_jobs", {"p_limit": 100}) or []


def mark_scheduled_job_ran(job_id, interval_seconds):
    from datetime import datetime, timezone, timedelta
    now = _now_iso()
    interval_seconds = interval_seconds or 86400
    next_run = (datetime.now(timezone.utc) + timedelta(seconds=interval_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
    _patch(f"scheduled_jobs?id=eq.{_q(str(job_id))}", {
        "last_run_at": now,
        "next_run_at": next_run,
    })


# ─────────────────────────────────────────────────────────────────────────────
# Alert config (simple per-company thresholds — table: alert_config)
# ─────────────────────────────────────────────────────────────────────────────

def get_alert_config(company_id):
    rows = _get(f"alert_config?company_id=eq.{_q(str(company_id))}&limit=1")
    return rows[0] if rows else None


# Keep old name as alias so existing callers still work
get_alert_thresholds = get_alert_config


def get_all_alert_configs():
    return _get("alert_config?order=company_id") or []


def upsert_alert_config(company_id, cpu_pct, ram_pct, disk_free_gb, offline_minutes):
    _post("alert_config", {
        "company_id": str(company_id),
        "cpu_pct": cpu_pct,
        "ram_pct": ram_pct,
        "disk_free_gb": disk_free_gb,
        "offline_minutes": offline_minutes,
        "updated_at": _now_iso(),
    }, prefer="resolution=merge-duplicates,return=representation")


# Keep old name as alias
upsert_alert_thresholds = upsert_alert_config


# ─────────────────────────────────────────────────────────────────────────────
# Alert helpers
# ─────────────────────────────────────────────────────────────────────────────

def get_open_alert(endpoint_id, alert_type):
    rows = _get(
        f"alerts?endpoint_id=eq.{_q(str(endpoint_id))}"
        f"&type=eq.{_q(alert_type)}"
        f"&is_resolved=eq.false&limit=1"
    )
    return rows[0] if rows else None


def get_endpoints_for_alert_check(company_id):
    rows = _get(
        f"endpoints?company_id=eq.{_q(str(company_id))}"
        f"&is_active=eq.true"
        f"&select=id,company_id,branch_id,hostname,status,cpu_pct,ram_used_pct,disk_free_gb,last_seen,vpn_ip"
    ) or []
    company = get_company_by_id(company_id)
    return [_decrypt_endpoint(row, company) for row in rows]


# ─────────────────────────────────────────────────────────────────────────────
# Bulk job dispatch
# ─────────────────────────────────────────────────────────────────────────────

def get_endpoints_bulk(company_id, branch_id=None, endpoint_ids=None):
    """Get endpoints for bulk dispatch, optionally filtered."""
    if endpoint_ids:
        # PostgREST in.() syntax: id=in.(uuid1,uuid2) — commas must not be encoded
        ids_param = ",".join(str(e) for e in endpoint_ids)
        raw = _get(f"endpoints?company_id=eq.{_q(str(company_id))}&is_active=eq.true&id=in.({ids_param})") or []
        company = get_company_by_id(company_id)
        return [_decrypt_endpoint(row, company) for row in raw]
    if branch_id:
        raw = _get(f"endpoints?company_id=eq.{_q(str(company_id))}&is_active=eq.true&branch_id=eq.{_q(str(branch_id))}") or []
        company = get_company_by_id(company_id)
        return [_decrypt_endpoint(row, company) for row in raw]
    return get_endpoints(company_id) or []


# ─────────────────────────────────────────────────────────────────────────────
# Status / monitoring helpers
# ─────────────────────────────────────────────────────────────────────────────

def get_job_queue_stats(company_id):
    """Return pending/running/completed/failed job counts for the last 24h."""
    rows = _get(
        f"jobs?company_id=eq.{_q(str(company_id))}"
        f"&created_at=gt.{_q(_now_iso_offset(-86400))}"
        f"&select=status"
    ) or []
    counts = {"pending": 0, "running": 0, "completed": 0, "failed": 0}
    for r in rows:
        s = r.get("status", "")
        if s in counts:
            counts[s] += 1
    return counts


def _now_iso_offset(offset_seconds: int) -> str:
    from datetime import datetime, timezone, timedelta
    dt = datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def get_endpoint_summary(company_id):
    """Return online/offline/pending counts for a company's endpoints."""
    rows = _get(f"endpoints?company_id=eq.{_q(str(company_id))}&select=status") or []
    counts = {"online": 0, "offline": 0, "pending": 0}
    for r in rows:
        s = r.get("status", "")
        if s in counts:
            counts[s] += 1
        elif s:
            counts["offline"] += 1  # any unknown status treated as offline
    counts["total"] = sum(counts.values())
    return counts
