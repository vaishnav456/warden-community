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


from database.transport import (
    get as _get, post as _post, patch as _patch, rpc as _rpc,
    delete as _delete, count as _count, get_all as _get_all,
)
from database.dashboard import dashboard_counts




def dashboard_count(company_id, table, branch_id=None, **filters):
    """Exact metadata count, not a count of PostgREST's truncated row page."""
    if table not in {"alerts", "jobs", "escalation_requests"}:
        raise ValueError("Unsupported dashboard count")
    path = f"{table}?company_id=eq.{_q(company_id)}&select=id"
    if branch_id:
        path += f"&branch_id=eq.{_q(branch_id)}"
    allowed = {"status", "severity", "is_resolved", "created_at", "or", "expires_at"}
    for key, value in filters.items():
        if key not in allowed:
            raise ValueError("Unsupported dashboard filter")
        path += f"&{key}={_q(value)}"
    return _count(path)








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
    # Cache only within one HTTP request, never across tenants or requests.
    # Heartbeat encryption/auth repeatedly needs the same tenant key metadata.
    from flask import g, has_request_context
    cache = None
    if has_request_context():
        cache = g.setdefault("_db_company_cache", {})
        if str(company_id) in cache:
            value = cache[str(company_id)]
            return dict(value) if value else None
    rows = _get(f"companies?id=eq.{_q(company_id)}&limit=1")
    result = rows[0] if rows else None
    if cache is not None:
        cache[str(company_id)] = dict(result) if result else None
    return result


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
    from flask import g, has_request_context
    if has_request_context():
        g.get("_db_company_cache", {}).pop(str(company_id), None)
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
    "agent_integrity": "agent_integrity_encrypted",
    "device_identity": "device_identity_encrypted",
    "topology_telemetry": "topology_telemetry_encrypted",
    "capability_details": "capability_details_encrypted",
    "tags": "tags_encrypted",
    "asset_metadata": "asset_metadata_encrypted",
}

_HEARTBEAT_METRIC_FIELDS = {
    "cpu_pct", "ram_used_pct", "disk_free_gb", "agent_memory_mb",
    "agent_uptime_sec", "net_sent_mbps", "net_recv_mbps",
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
    encrypted = result.pop("heartbeat_encrypted", None)
    if encrypted:
        metrics = _endpoint_decrypt(company, "heartbeat", encrypted)
        if not isinstance(metrics, dict):
            raise ValueError("invalid encrypted heartbeat")
        for field in _HEARTBEAT_METRIC_FIELDS:
            if field in metrics:
                result[field] = metrics[field]
    return result


def _endpoint_company(endpoint_id):
    # Middleware already authenticated this exact endpoint. Reuse its tenant
    # binding; another endpoint ID must still go through the database lookup.
    from flask import g, has_request_context
    if has_request_context():
        endpoint = g.get("endpoint")
        if (isinstance(endpoint, dict) and str(endpoint.get("id")) == str(endpoint_id)
                and endpoint.get("company_id")):
            return get_company_by_id(endpoint["company_id"])
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


from database.branches import (
    get_branches,
    get_branch,
    create_branch,
    update_branch,
    delete_branch,
)


# ─────────────────────────────────────────────────────────────────────────────
# Policy templates & per-endpoint policy state
# ─────────────────────────────────────────────────────────────────────────────


from database.policies import (
    get_policy_templates,
    get_policy_template,
    create_policy_template,
    update_policy_template,
    delete_policy_template,
    get_policy_assignments,
    create_policy_assignment,
    delete_policy_assignment,
    record_policy_drift_check,
    update_endpoint_policy_state,
)


# ─────────────────────────────────────────────────────────────────────────────
# Admin Users
# ─────────────────────────────────────────────────────────────────────────────


from database.admins import (
    get_admin_by_email,
    get_admin_by_id,
    get_admins_for_company,
    get_all_admins,
    create_admin_user,
    update_admin,
    update_admin_failed_attempts,
    update_admin_last_login,
    update_admin_mfa,
    disable_admin_mfa,
    update_admin_password,
)


# ─────────────────────────────────────────────────────────────────────────────
# Refresh Tokens
# ─────────────────────────────────────────────────────────────────────────────


from database.sessions import (
    create_refresh_token,
    rotate_refresh_token,
    get_refresh_token,
    revoke_refresh_token,
    revoke_all_tokens_for_admin,
    count_active_sessions,
)


# ─────────────────────────────────────────────────────────────────────────────
# Enrollment Tokens
# ─────────────────────────────────────────────────────────────────────────────


from database.enrollment_tokens import (
    create_enrollment_token,
    get_enrollment_token_by_hash,
    get_enrollment_tokens,
    get_enrollment_token,
    claim_enrollment_token,
    release_enrollment_token,
    deactivate_enrollment_token,
    burn_enrollment_token,
)


# ─────────────────────────────────────────────────────────────────────────────
# Zero-touch enrollment profiles and pre-registered device claims
# ─────────────────────────────────────────────────────────────────────────────


from database.enrollment_profiles import (
    create_enrollment_profile,
    _decrypt_enrollment_profile,
    get_enrollment_profile,
    get_enrollment_profiles,
    deactivate_enrollment_profile,
    update_enrollment_profile_preparation,
    add_enrollment_device_claim,
    get_enrollment_device_claim,
    get_enrollment_device_claim_for_identity,
    upsert_autopilot_device_claim,
    sync_autopilot_device_claims,
    get_enrollment_device_claims,
    mark_enrollment_device_claim_enrolled,
)


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────


# ── Physical topology / floor plans ─────────────────────────────────────────


from database.endpoints import (
    get_endpoints,
    get_asset_register,
    get_endpoint,
    get_endpoint_recovery_keys,
    update_endpoint_recovery_status,
    escrow_endpoint_recovery_key,
    reveal_endpoint_recovery_key,
    get_endpoint_by_api_key_hash,
    retire_endpoint,
    close_endpoint_work,
    create_endpoint,
    get_endpoint_by_installation_id,
    get_endpoint_by_hardware_id,
    recover_endpoint_enrollment,
    reenroll_endpoint,
    set_endpoint_client_cert,
    rotate_endpoint_client_cert,
    clear_endpoint_client_cert,
    update_endpoint_heartbeat,
    update_endpoint_sysinfo,
    update_endpoint_hostname,
    update_endpoint_nickname,
    set_endpoint_offline,
    update_endpoint_notes,
    get_topology_floors,
    get_topology_floor,
    create_topology_floor,
    update_topology_floor,
    delete_topology_floor,
    get_topology_rooms,
    get_topology_room,
    create_topology_room,
    update_topology_room,
    delete_topology_room,
    get_topology_placements,
    upsert_topology_placement,
    delete_topology_placement,
    get_topology_nodes,
    get_topology_node,
    create_topology_node,
    update_topology_node,
    delete_topology_node,
    get_topology_links,
    create_topology_link,
    get_topology_link,
    delete_topology_link,
    delete_topology_links_for_object,
    get_topology_snapshots,
    get_topology_snapshot,
    create_topology_snapshot,
    prune_topology_snapshots,
    update_endpoint_asset,
    mark_endpoints_stale,
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


from database.jobs import (
    _decrypt_job,
    get_jobs,
    get_home_sync_jobs,
    get_job,
    has_inflight_job,
    get_endpoint_home_sync_jobs,
    has_recent_job,
    has_job,
    create_job,
    create_system_job_once,
    _company_for_job,
    update_job_status,
    finish_running_job,
    claim_job_result_processing,
    complete_job_result_processing,
    append_job_log,
    get_pending_jobs_for_endpoint,
    create_policy_deployment,
    cancel_policy_deployment,
    retry_policy_deployment,
    maybe_pause_policy_deployment,
    refresh_policy_deployment_status,
    get_policy_deployment,
    get_policy_deployments,
    cancel_job,
)


# ─────────────────────────────────────────────────────────────────────────────
# Windows Users
# ─────────────────────────────────────────────────────────────────────────────


from database.windows_users import (
    get_windows_users,
    get_windows_user,
    get_company_windows_users,
    replace_windows_users,
    upsert_windows_user,
    delete_windows_user,
    set_windows_user_state,
)


# ─────────────────────────────────────────────────────────────────────────────
# Warden identities (desired state; separate from discovered local accounts)
# ─────────────────────────────────────────────────────────────────────────────


from database.identities import (
    get_warden_identities,
    get_warden_identity,
    get_warden_identity_for_login,
    record_warden_login_failure,
    record_warden_login_success,
    log_warden_identity_login,
    get_warden_identity_login_events,
    create_warden_identity,
    create_warden_identity_with_jobs,
    create_warden_identity_with_setup_and_jobs,
    get_warden_identity_for_password_setup,
    complete_warden_identity_password_setup,
    rotate_warden_identity_password,
    set_warden_identity_enabled,
    reassign_warden_identity,
    update_warden_identity,
    get_warden_identity_assignment,
    get_active_warden_usernames_for_endpoint,
    get_managed_warden_usernames_for_endpoint,
    upsert_warden_identity_assignment,
    mark_warden_assignment_job_result,
)


# ─────────────────────────────────────────────────────────────────────────────
# Software Inventory
# ─────────────────────────────────────────────────────────────────────────────


from database.inventory import (
    get_software,
    replace_software_inventory,
    replace_patch_inventory,
    get_patch_inventory,
    get_patch_policies,
    get_patch_policy,
    create_patch_policy,
    get_patch_deployments,
    create_patch_deployment,
    get_due_patch_deployments,
    promote_patch_deployment,
    refresh_patch_deployment,
    replace_network_flows,
    get_network_flows,
    get_vulnerability_advisories,
    upsert_vulnerability_advisories,
    replace_vulnerability_findings,
    get_vulnerability_findings,
    get_vulnerability_finding,
    update_vulnerability_finding,
)


# ─────────────────────────────────────────────────────────────────────────────
# Warden Home storage control plane
# ─────────────────────────────────────────────────────────────────────────────


from database.home_storage import (
    get_home_nodes,
    create_home_node,
    update_home_node,
    get_home_node_by_key_hash,
    update_home_node_heartbeat,
    create_home_p2p_session,
    create_home_node_p2p_session,
    get_home_p2p_session,
    get_home_p2p_offers,
    answer_home_p2p_session,
    fail_home_p2p_session,
    get_home_spaces,
    get_home_space,
    create_home_space,
    update_home_space_topology,
    get_home_assignments,
    create_home_assignment,
    update_home_assignment,
    delete_home_assignment,
    log_home_access,
)


# ─────────────────────────────────────────────────────────────────────────────
# Escalation Requests
# ─────────────────────────────────────────────────────────────────────────────


from database.escalations import (
    _decrypt_escalation,
    get_escalation_requests,
    get_escalation_request,
    create_escalation_request,
    approve_escalation,
    deny_escalation,
    complete_escalation,
    _get_escalation_company,
    expire_stale_escalations,
    count_pending_escalations,
)


# ─────────────────────────────────────────────────────────────────────────────
# Saved Escalations (Policies)
# ─────────────────────────────────────────────────────────────────────────────


from database.escalation_policies import (
    get_saved_escalations,
    get_saved_escalation,
    create_saved_escalation,
    revoke_saved_escalation,
    find_matching_policy,
)


# ─────────────────────────────────────────────────────────────────────────────
# Alerts
# ─────────────────────────────────────────────────────────────────────────────


from database.alerts import (
    get_alerts,
    get_alert,
    _decrypt_alert,
    create_alert,
    get_open_enrollment_alert,
    resolve_alert,
    reopen_alert,
    assign_alert,
    snooze_alert,
    count_open_alerts,
)


# ─────────────────────────────────────────────────────────────────────────────
# App Library
# ─────────────────────────────────────────────────────────────────────────────


from database.apps import (
    get_app_library,
    get_app,
    get_app_file_references,
    request_app_deletion,
    package_in_use,
    create_app,
    update_app,
    delete_app,
)


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


from database.metrics import (
    insert_metric,
    get_metrics,
)


# ─────────────────────────────────────────────────────────────────────────────
# Endpoint Events
# ─────────────────────────────────────────────────────────────────────────────


from database.events import (
    log_endpoint_event,
    get_endpoint_events,
    get_recent_endpoint_events,
)


# ─────────────────────────────────────────────────────────────────────────────
# Build Requests
# ─────────────────────────────────────────────────────────────────────────────


from database.builds import (
    create_build_request,
    fail_claimed_build,
    get_build_request,
    get_pending_build_requests,
    get_build_requests,
    update_build_request,
    complete_claimed_build,
    mark_build_msi_ready,
    mark_claimed_build_msi_ready,
    get_latest_completed_build,
    endpoint_target_platform,
)


# ─────────────────────────────────────────────────────────────────────────────
# Remote Sessions
# ─────────────────────────────────────────────────────────────────────────────


from database.remote_sessions import (
    create_remote_session,
    update_remote_session_controls,
    close_remote_session,
    get_remote_sessions,
    get_remote_session,
    get_active_remote_session,
    close_all_active_remote_sessions,
    _parse_dt_iso,
    update_remote_session_token,
    get_remote_session_by_token,
    mark_remote_session_failed,
    create_remote_session_event,
    get_remote_session_events,
    update_remote_session_support_state,
    create_remote_support_link,
    get_remote_support_link_by_hash,
    claim_remote_support_link,
    release_remote_support_link_claim,
)


# ─────────────────────────────────────────────────────────────────────────────
# Notifications
# ─────────────────────────────────────────────────────────────────────────────


from database.notifications import (
    create_notification,
    get_notifications,
    count_unread_notifications,
    mark_notifications_read,
    cleanup_expired_tokens,
)


# ─────────────────────────────────────────────────────────────────────────────
# Compliance policies
# ─────────────────────────────────────────────────────────────────────────────


# ─────────────────────────────────────────────────────────────────────────────
# Compliance results
# ─────────────────────────────────────────────────────────────────────────────


from database.compliance import (
    create_compliance_policy,
    get_compliance_policies,
    get_compliance_policy,
    update_compliance_policy,
    delete_compliance_policy,
    upsert_compliance_result,
    get_compliance_result,
    get_compliance_results_for_company,
)


# ─────────────────────────────────────────────────────────────────────────────
# Scheduled jobs
# ─────────────────────────────────────────────────────────────────────────────


from database.schedules import (
    create_scheduled_job,
    get_scheduled_jobs,
    get_scheduled_job,
    update_scheduled_job,
    delete_scheduled_job,
    get_due_scheduled_jobs,
    mark_scheduled_job_ran,
)


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
    rows = _get_all(
        f"endpoints?company_id=eq.{_q(str(company_id))}"
        f"&is_active=eq.true"
        f"&select=id,company_id,branch_id,hostname,status,cpu_pct,ram_used_pct,disk_free_gb,last_seen,vpn_ip"
        + (",heartbeat_encrypted" if config.ENCRYPT_HEARTBEAT_TELEMETRY else "")
        + "&order=id.asc"
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
        raw = _get_all(
            f"endpoints?company_id=eq.{_q(str(company_id))}&is_active=eq.true&id=in.({ids_param})"
            + (f"&branch_id=eq.{_q(str(branch_id))}" if branch_id else "")
            + "&order=id.asc"
        ) or []
        company = get_company_by_id(company_id)
        return [_decrypt_endpoint(row, company) for row in raw]
    if branch_id:
        raw = _get_all(f"endpoints?company_id=eq.{_q(str(company_id))}&is_active=eq.true&branch_id=eq.{_q(str(branch_id))}&order=id.asc") or []
        company = get_company_by_id(company_id)
        return [_decrypt_endpoint(row, company) for row in raw]
    return get_endpoints(company_id) or []


# ─────────────────────────────────────────────────────────────────────────────
# Status / monitoring helpers
# ─────────────────────────────────────────────────────────────────────────────

def get_job_queue_stats(company_id, branch_id=None):
    """Return pending/running/completed/failed job counts for the last 24h."""
    rows = _get_all(
        f"jobs?company_id=eq.{_q(str(company_id))}"
        + (f"&branch_id=eq.{_q(str(branch_id))}" if branch_id else "")
        +
        f"&created_at=gt.{_q(_now_iso_offset(-86400))}"
        f"&select=status&order=id.asc"
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


def get_endpoint_summary(company_id, branch_id=None):
    """Return online/offline/pending counts for a company's endpoints."""
    rows = _get_all(
        f"endpoints?company_id=eq.{_q(str(company_id))}"
        + (f"&branch_id=eq.{_q(str(branch_id))}" if branch_id else "")
        + "&select=status&order=id.asc"
    ) or []
    counts = {"online": 0, "offline": 0, "pending": 0}
    for r in rows:
        s = r.get("status", "")
        if s in counts:
            counts[s] += 1
        elif s:
            counts["offline"] += 1  # any unknown status treated as offline
    counts["total"] = sum(counts.values())
    return counts
