"""
Warden — Settings routes
Profile, MFA, password change, notification preferences.
"""
from datetime import datetime, timezone
import hashlib
import json
import math
import re
import uuid

from flask import Blueprint, render_template, request, jsonify, g, redirect, url_for, abort, flash

import config
import db
from timezones import WINDOWS_TIME_ZONES, WINDOWS_TIME_ZONE_IDS
from middleware.auth import login_required, company_required, role_required, require_branch_scope

bp = Blueprint("settings", __name__)


def _parse_dt(dt_str):
    if not dt_str:
        return None
    try:
        return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
    except Exception:
        return None


def _fmt_dt(dt_str):
    dt = _parse_dt(dt_str)
    return dt.strftime("%d %b %Y, %H:%M UTC") if dt else "—"


def _normalise_device_id(value):
    value = str(value or "").strip().lower()
    invalid = {
        "", "none", "unknown", "default string", "to be filled by o.e.m.",
        "00000000-0000-0000-0000-000000000000",
        "ffffffff-ffff-ffff-ffff-ffffffffffff",
    }
    return "" if value in invalid else value


@bp.route("/settings")
@login_required
def index():
    return render_template("settings/index.html")


@bp.route("/settings/integrations")
@login_required
@company_required
@role_required("company_admin")
def integrations():
    from services.tenant_crypto import VaultLocked
    integration = db.get_tenant_integration(g.company["id"], "microsoft_entra")
    saved_config = {}
    vault_locked = False
    if integration:
        try:
            saved_config = db.decrypt_field(
                g.company, integration["config_encrypted"], "integration.config"
            ) or {}
        except VaultLocked:
            vault_locked = True
    return render_template(
        "settings/integrations.html",
        integration=integration,
        saved_config=saved_config,
        vault_locked=vault_locked,
        enrollment_profiles=db.get_enrollment_profiles(g.company["id"], active_only=True),
    )


def _validate_microsoft_ids(tenant_id, client_id):
    try:
        return str(uuid.UUID(tenant_id)), str(uuid.UUID(client_id))
    except (ValueError, TypeError, AttributeError):
        raise ValueError("Tenant ID and Application (client) ID must be valid UUIDs")


def _test_microsoft_integration(integration, integration_config):
    from services.microsoft_graph import test_connection
    try:
        metadata = test_connection(integration_config)
        db.update_tenant_integration_test(integration["id"], True, metadata=metadata)
        return True, metadata.get("organization_name") or "Microsoft Entra"
    except Exception as exc:
        # microsoft_graph sanitizes provider errors, including accidental
        # echoes of the client secret. Never include the stored config here.
        message = str(exc)[:500]
        db.update_tenant_integration_test(integration["id"], False, error=message)
        return False, message


@bp.route("/settings/integrations/microsoft-entra", methods=["POST"])
@login_required
@company_required
@role_required("company_admin")
def save_microsoft_integration():
    from services.tenant_crypto import VaultLocked
    tenant_id = request.form.get("tenant_id", "").strip()
    client_id = request.form.get("client_id", "").strip()
    client_secret = request.form.get("client_secret", "").strip()
    try:
        tenant_id, client_id = _validate_microsoft_ids(tenant_id, client_id)
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("settings.integrations"))

    try:
        existing, existing_config = db.get_tenant_integration_config(
            g.company, "microsoft_entra",
        )
    except VaultLocked:
        flash("Unlock the organization vault before updating credentials", "error")
        return redirect(url_for("settings.integrations"))
    if not client_secret and existing_config:
        client_secret = existing_config.get("client_secret", "")
    if not client_secret or len(client_secret) > 500:
        flash("Enter the client secret value (not the secret ID)", "error")
        return redirect(url_for("settings.integrations"))

    integration_config = {
        "tenant_id": tenant_id,
        "client_id": client_id,
        "client_secret": client_secret,
    }
    try:
        integration = db.save_tenant_integration(
            g.company, "microsoft_entra", integration_config, g.admin["id"],
        )
    except VaultLocked:
        flash("Unlock the organization vault before updating credentials", "error")
        return redirect(url_for("settings.integrations"))
    connected, result = _test_microsoft_integration(integration, integration_config)
    db.audit(g.company["id"], g.admin["id"], "microsoft_entra_credentials_updated", {
        "integration_id": integration["id"], "connection_test": "passed" if connected else "failed",
    })
    if connected:
        flash(f"Connected to {result}", "success")
    else:
        flash(f"Credentials saved securely, but connection test failed: {result}", "error")
    return redirect(url_for("settings.integrations"))


@bp.route("/settings/integrations/microsoft-entra/test", methods=["POST"])
@login_required
@company_required
@role_required("company_admin")
def test_microsoft_integration():
    from services.tenant_crypto import VaultLocked
    try:
        integration, integration_config = db.get_tenant_integration_config(
            g.company, "microsoft_entra",
        )
    except VaultLocked:
        flash("Unlock the organization vault before testing credentials", "error")
        return redirect(url_for("settings.integrations"))
    if not integration or not integration_config:
        flash("Save Microsoft credentials first", "error")
        return redirect(url_for("settings.integrations"))
    connected, result = _test_microsoft_integration(integration, integration_config)
    db.audit(g.company["id"], g.admin["id"], "microsoft_entra_connection_tested", {
        "integration_id": integration["id"], "result": "passed" if connected else "failed",
    })
    flash(f"Connected to {result}" if connected else f"Connection failed: {result}",
          "success" if connected else "error")
    return redirect(url_for("settings.integrations"))


@bp.route("/settings/integrations/microsoft-entra/sync-autopilot", methods=["POST"])
@login_required
@company_required
@role_required("company_admin")
def sync_microsoft_autopilot():
    from services.microsoft_graph import list_autopilot_devices
    from services.tenant_crypto import VaultLocked

    profile_id = request.form.get("profile_id", "").strip()
    profile = db.get_enrollment_profile(profile_id) if profile_id else None
    if (
        not profile or str(profile.get("company_id")) != str(g.company["id"])
        or not profile.get("is_active")
    ):
        flash("Select an active enrollment profile", "error")
        return redirect(url_for("settings.integrations"))
    try:
        integration, integration_config = db.get_tenant_integration_config(
            g.company, "microsoft_entra",
        )
    except VaultLocked:
        flash("Unlock the organization vault before syncing Autopilot", "error")
        return redirect(url_for("settings.integrations"))
    if not integration or not integration_config:
        flash("Connect Microsoft Entra first", "error")
        return redirect(url_for("settings.integrations"))

    try:
        devices = list_autopilot_devices(integration_config)
        result = db.sync_autopilot_device_claims(
            g.company["id"], profile_id, devices,
        )
    except Exception as exc:
        message = str(exc)[:500]
        db.update_tenant_integration_test(integration["id"], False, error=message)
        flash(f"Autopilot sync failed: {message}", "error")
        return redirect(url_for("settings.integrations"))

    metadata = dict(integration.get("metadata") or {})
    metadata.update({
        "autopilot_access": True,
        "last_sync_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "last_sync_count": len(devices),
        "last_sync_profile_id": profile_id,
    })
    db.update_tenant_integration_test(integration["id"], True, metadata=metadata)
    added, updated = int(result.get("added", 0)), int(result.get("updated", 0))
    db.audit(g.company["id"], g.admin["id"], "microsoft_autopilot_synced", {
        "integration_id": integration["id"], "profile_id": profile_id,
        "fetched": len(devices), "added": added, "updated": updated,
    }, branch_id=profile.get("branch_id"))
    flash(f"Autopilot sync complete: {added} added, {updated} updated", "success")
    return redirect(url_for("settings.integrations"))


@bp.route("/settings/integrations/microsoft-entra/disconnect", methods=["POST"])
@login_required
@company_required
@role_required("company_admin")
def disconnect_microsoft_integration():
    integration = db.get_tenant_integration(g.company["id"], "microsoft_entra")
    if integration:
        db.delete_tenant_integration(g.company["id"], "microsoft_entra")
        db.audit(g.company["id"], g.admin["id"], "microsoft_entra_disconnected", {
            "integration_id": integration["id"],
        })
    flash("Microsoft Entra credentials removed", "success")
    return redirect(url_for("settings.integrations"))


@bp.route("/settings/branches")
@login_required
@company_required
def branches():
    company_id = g.company["id"]
    branch_rows = db.get_branches(company_id)
    counts = {}
    for e in db.get_endpoints(company_id):
        bid = e.get("branch_id")
        if bid:
            counts[str(bid)] = counts.get(str(bid), 0) + 1
    for b in branch_rows:
        b["endpoint_count"] = counts.get(str(b["id"]), 0)
    return render_template(
        "settings/branches.html", branches=branch_rows,
        windows_time_zones=WINDOWS_TIME_ZONES,
    )


@bp.route("/settings/branches/create", methods=["POST"])
@login_required
@company_required
@role_required("company_admin")
def create_branch():
    name = request.form.get("name", "").strip()
    city = request.form.get("city", "").strip()
    branch_timezone = request.form.get("timezone", "UTC").strip()
    if not name:
        return jsonify({"error": "Branch name required"}), 400
    if branch_timezone not in WINDOWS_TIME_ZONE_IDS:
        return jsonify({"error": "Select a supported branch time zone"}), 400
    from services.entitlements import check_capacity
    capacity = check_capacity(g.company["id"], "branches")
    if not capacity.allowed:
        return jsonify({"error": capacity.code, "message": capacity.message}), 403
    db.create_branch(g.company["id"], name, city or None, branch_timezone)
    db.audit(g.company["id"], g.admin["id"], "branch_created", {
        "name": name, "timezone": branch_timezone,
    })
    return redirect(url_for("settings.branches"))


@bp.route("/settings/branches/<id>/timezone", methods=["POST"])
@login_required
@company_required
@role_required("company_admin")
def update_branch_timezone(id):
    branch = db.get_branch(id)
    if not branch or str(branch["company_id"]) != str(g.company["id"]):
        abort(404)
    branch_timezone = request.form.get("timezone", "").strip()
    if branch_timezone not in WINDOWS_TIME_ZONE_IDS:
        return jsonify({"error": "Select a supported branch time zone"}), 400
    db.update_branch(id, g.company["id"], {"timezone": branch_timezone})
    db.audit(g.company["id"], g.admin["id"], "branch_timezone_updated", {
        "branch_id": id, "timezone": branch_timezone,
    })
    flash("Branch time zone updated. Endpoints apply it on their next heartbeat.", "success")
    return redirect(url_for("settings.branches"))


@bp.route("/settings/branches/<id>/delete", methods=["DELETE"])
@login_required
@company_required
@role_required("company_admin")
def delete_branch(id):
    branch = db.get_branch(id)
    if not branch or str(branch["company_id"]) != str(g.company["id"]):
        abort(404)
    if db.get_endpoints(g.company["id"], branch_id=id):
        return jsonify({"error": "Remove or reassign endpoints in this branch first"}), 409
    db.delete_branch(id)
    db.audit(g.company["id"], g.admin["id"], "branch_deleted", {"name": branch["name"]})
    return "", 200


@bp.route("/settings/tokens")
@login_required
@company_required
def tokens():
    company_id = g.company["id"]
    branch_rows = db.get_branches(company_id)
    branch_map = {str(b["id"]): b for b in branch_rows}
    token_map = {str(t["id"]): t for t in db.get_enrollment_tokens(company_id, limit=50)}
    profiles = db.get_enrollment_profiles(company_id)
    profile_map = {str(p["id"]): p for p in profiles}
    for profile in profiles:
        profile["device_claims"] = db.get_enrollment_device_claims(profile["id"])
    now = datetime.now(timezone.utc)

    rows = []
    for build in db.get_build_requests(company_id, limit=50):
        et = token_map.get(str(build.get("enrollment_token_id")))
        profile = profile_map.get(str(et.get("profile_id"))) if et else None
        branch = branch_map.get(str(build.get("branch_id")))
        raw_token = (build.get("config_json") or {}).get("enrollment_token") or ""
        expires_dt = _parse_dt(et.get("expires_at")) if et else None
        rows.append({
            "id": build["id"],
            "branch_name": branch["name"] if branch else "—",
            "token_partial": (raw_token[:8] + "…") if raw_token else "————————",
            "created_at": build.get("created_at"),
            "expires_at_str": _fmt_dt(et.get("expires_at")) if et else "—",
            "used_at": et.get("used_by_endpoint_id") if et else None,
            "is_expired": bool(expires_dt and expires_dt < now),
            "build_status": build.get("status"),
            "use_count": et.get("use_count", 0) if et else 0,
            "max_uses": et.get("max_uses") if et else 1,
            "is_active": et.get("is_active") if et else False,
            "msi_ready": build.get("msi_ready", False),
            "token_id": et.get("id") if et else None,
            "profile_name": profile.get("name") if profile else "Legacy installer",
            "deployment_method": profile.get("deployment_method") if profile else "manual",
            "target_platform": build.get("target_platform") or "windows-amd64",
        })
    return render_template(
        "settings/tokens.html", branches=branch_rows, tokens=rows,
        profiles=profiles,
        policy_templates=db.get_policy_templates(company_id),
        app_library=db.get_app_library(company_id),
    )


@bp.route("/settings/enrollment-profiles/create", methods=["POST"])
@login_required
@company_required
@role_required("company_admin", "branch_admin")
def create_enrollment_profile():
    name = request.form.get("name", "").strip()
    branch_id = request.form.get("branch_id", "").strip()
    method = request.form.get("deployment_method", "intune").strip().lower()
    hostname_pattern = request.form.get("hostname_pattern", "").strip()
    domain_suffix = request.form.get("domain_suffix", "").strip().lower().lstrip(".")
    warden_only_mode = request.form.get("warden_only_mode") == "1"
    recovery_admin_username = request.form.get("recovery_admin_username", "WardenRecovery").strip()
    recovery_admin_password = request.form.get("recovery_admin_password", "")
    policy_template_id = request.form.get("policy_template_id", "").strip()
    required_app_ids = list(dict.fromkeys(request.form.getlist("required_app_ids")))[:50]
    install_updates = request.form.get("install_updates") == "1"
    allowed_methods = {"manual", "gpo", "intune", "autopilot", "sccm", "rmm"}
    if not name or len(name) > 80:
        return jsonify({"error": "Profile name is required and must be at most 80 characters"}), 400
    if method not in allowed_methods:
        return jsonify({"error": "Unsupported deployment method"}), 400
    if hostname_pattern and (len(hostname_pattern) > 80 or not re.fullmatch(r"[A-Za-z0-9*?.-]+", hostname_pattern)):
        return jsonify({"error": "Hostname pattern may contain letters, numbers, dots, dashes, * and ?"}), 400
    if domain_suffix and (len(domain_suffix) > 253 or not re.fullmatch(r"[a-z0-9.-]+", domain_suffix)):
        return jsonify({"error": "Invalid domain suffix"}), 400
    if warden_only_mode:
        from routes.directory import WINDOWS_RESERVED_NAMES, WINDOWS_USERNAME_RE, _password_error
        if (not WINDOWS_USERNAME_RE.fullmatch(recovery_admin_username)
                or recovery_admin_username.casefold() in WINDOWS_RESERVED_NAMES
                or recovery_admin_username.endswith(".")):
            return jsonify({"error": "Recovery administrator must be a valid Windows username"}), 400
        password_error = _password_error(recovery_admin_password, recovery_admin_username)
        if password_error:
            return jsonify({"error": f"Recovery administrator password: {password_error}"}), 400
    if any(str(p.get("name", "")).lower() == name.lower() for p in db.get_enrollment_profiles(g.company["id"])):
        return jsonify({"error": "An enrollment profile with this name already exists"}), 409
    branch = db.get_branch(branch_id)
    if not branch or str(branch["company_id"]) != str(g.company["id"]):
        abort(404)
    require_branch_scope(branch_id)
    if policy_template_id == "builtin:warden_enrollment_baseline":
        from policy_templates import POLICY_BENCHMARKS
        baseline_name = "Warden Enrollment Baseline"
        existing = next((
            template for template in db.get_policy_templates(g.company["id"])
            if str(template.get("name") or "").casefold() == baseline_name.casefold()
        ), None)
        if existing:
            policy_template_id = str(existing["id"])
        else:
            benchmark = POLICY_BENCHMARKS["warden_windows_secure_baseline"]
            created = db.create_policy_template(
                g.company["id"], baseline_name,
                "Recommended secure starting policy for newly enrolled Windows devices.",
                benchmark["settings"], g.admin["id"],
            )
            policy_template_id = str(created["id"])
    if policy_template_id:
        policy_template = db.get_policy_template(policy_template_id)
        if not policy_template or str(policy_template.get("company_id")) != str(g.company["id"]):
            return jsonify({"error": "Invalid post-enrollment policy template"}), 400
    for app_id in required_app_ids:
        app = db.get_app(app_id)
        if not app or (app.get("company_id") and str(app.get("company_id")) != str(g.company["id"])):
            return jsonify({"error": "Invalid required application"}), 400
    profile = db.create_enrollment_profile(
        g.company["id"], branch_id, name, method, hostname_pattern,
        domain_suffix, request.form.get("require_pre_registration") == "1",
        request.form.get("reclaim_existing") == "1", g.admin["id"],
        warden_only_mode=warden_only_mode,
        lockdown_config={
            "recovery_admin_username": recovery_admin_username,
            "recovery_admin_password": recovery_admin_password,
        } if warden_only_mode else None,
        post_enrollment={
            "policy_template_id": policy_template_id or None,
            "required_app_ids": required_app_ids,
            "install_updates": install_updates,
        },
    )
    db.audit(g.company["id"], g.admin["id"], "enrollment_profile_created", {
        "profile_id": profile["id"], "name": name, "deployment_method": method,
        "branch_id": branch_id, "warden_only_mode": warden_only_mode,
        "recovery_admin_username": recovery_admin_username if warden_only_mode else None,
        "policy_template_id": policy_template_id or None,
        "required_app_count": len(required_app_ids),
        "install_updates": install_updates,
    }, branch_id=branch_id)
    flash("Enrollment profile created", "success")
    return redirect(url_for("settings.tokens"))


@bp.route("/settings/enrollment-profiles/<profile_id>/deactivate", methods=["POST"])
@login_required
@company_required
@role_required("company_admin", "branch_admin")
def deactivate_enrollment_profile(profile_id):
    profile = db.get_enrollment_profile(profile_id)
    if not profile or str(profile["company_id"]) != str(g.company["id"]):
        abort(404)
    require_branch_scope(profile.get("branch_id"))
    db.deactivate_enrollment_profile(profile_id)
    db.audit(g.company["id"], g.admin["id"], "enrollment_profile_deactivated", {
        "profile_id": profile_id, "name": profile.get("name"),
    }, branch_id=profile.get("branch_id"))
    flash("Enrollment profile deactivated; existing agents remain enrolled", "success")
    return redirect(url_for("settings.tokens"))


@bp.route("/settings/enrollment-profiles/<profile_id>/devices", methods=["POST"])
@login_required
@company_required
@role_required("company_admin", "branch_admin")
def add_enrollment_devices(profile_id):
    profile = db.get_enrollment_profile(profile_id)
    if not profile or str(profile["company_id"]) != str(g.company["id"]):
        abort(404)
    require_branch_scope(profile.get("branch_id"))
    hardware_ids = []
    for line in request.form.get("hardware_ids", "").splitlines():
        value = _normalise_device_id(line)
        if value and value not in hardware_ids:
            hardware_ids.append(value)
    if not hardware_ids or len(hardware_ids) > 500:
        return jsonify({"error": "Enter between 1 and 500 hardware IDs"}), 400
    added = 0
    for hardware_id in hardware_ids:
        if len(hardware_id) > 200 or db.get_enrollment_device_claim(g.company["id"], hardware_id):
            continue
        db.add_enrollment_device_claim(g.company["id"], profile_id, hardware_id)
        added += 1
    db.audit(g.company["id"], g.admin["id"], "enrollment_devices_registered", {
        "profile_id": profile_id, "added": added,
    }, branch_id=profile.get("branch_id"))
    flash(f"{added} device{'s' if added != 1 else ''} pre-registered", "success")
    return redirect(url_for("settings.tokens"))


@bp.route("/settings/tokens/<token_id>/revoke", methods=["POST"])
@login_required
@company_required
@role_required("company_admin", "branch_admin")
def revoke_enrollment_token(token_id):
    token = db.get_enrollment_token(token_id)
    if not token or str(token["company_id"]) != str(g.company["id"]):
        abort(404)
    require_branch_scope(token.get("branch_id"))
    db.deactivate_enrollment_token(token_id)
    db.audit(g.company["id"], g.admin["id"], "enrollment_token_revoked", {
        "token_id": token_id, "profile_id": token.get("profile_id"),
    }, branch_id=token.get("branch_id"))
    flash("Installer credential revoked; enrolled devices are unaffected", "success")
    return redirect(url_for("settings.tokens"))


@bp.route("/settings/tokens/create", methods=["POST"])
@login_required
@company_required
@role_required("company_admin", "branch_admin")
def create_token():
    branch_id = request.form.get("branch_id", "").strip()
    profile_id = request.form.get("profile_id", "").strip()
    target_platform = request.form.get("target_platform", "windows-amd64").strip().lower()
    if target_platform not in {
        "windows-amd64", "linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64",
    }:
        return jsonify({"error": "invalid target platform"}), 400
    try:
        expiry_hours = int(request.form.get("expiry_hours", 24) or 24)
    except (TypeError, ValueError):
        return jsonify({"error": "expiry_hours must be an integer"}), 400
    if expiry_hours < 1 or expiry_hours > 24 * 30:
        return jsonify({"error": "expiry_hours must be between 1 and 720"}), 400
    profile = None
    if profile_id:
        profile = db.get_enrollment_profile(profile_id)
        if not profile or str(profile["company_id"]) != str(g.company["id"]) or not profile.get("is_active"):
            abort(404)
        branch_id = str(profile.get("branch_id") or "")
    if not branch_id:
        return jsonify({"error": "branch_id or enrollment profile required"}), 400

    # Single-use (default) unless the admin explicitly asks for a reusable
    # token — needed for domain-wide deployment (GPO/SCCM/Intune), where
    # the SAME installer/MSI enrolls many machines rather than one.
    reusable = request.form.get("reusable") == "1"
    max_uses = 1
    if reusable:
        max_uses_raw = request.form.get("max_uses", "").strip()
        if max_uses_raw:
            try:
                max_uses = int(max_uses_raw)
                if max_uses < 1:
                    raise ValueError
            except ValueError:
                return jsonify({"error": "max_uses must be a positive integer"}), 400
        else:
            max_uses = None  # unlimited enrollments until expiry_hours

    branch = db.get_branch(branch_id)
    if not branch or str(branch["company_id"]) != str(g.company["id"]):
        abort(404)
    require_branch_scope(branch_id)

    from services.cert_fingerprint import fetch_live_cert_fingerprint
    try:
        fingerprint = fetch_live_cert_fingerprint(config.SERVER_URL)
    except Exception as e:
        flash(f"Could not generate installer — server TLS fingerprint unavailable: {e}", "error")
        return redirect(url_for("settings.tokens"))

    company = g.company
    token, token_rec = db.create_enrollment_token(
        company_id=company["id"], branch_id=branch_id,
        created_by=g.admin["id"], expires_hours=expiry_hours,
        max_uses=max_uses,
        profile_id=profile_id or None,
    )
    if not token_rec:
        flash("Failed to create enrollment token", "error")
        return redirect(url_for("settings.tokens"))

    from services.signing import get_server_pubkey_b64
    config_json = {
        "server_url": config.SERVER_URL,
        "server_ed25519_pubkey": get_server_pubkey_b64(),
        "cert_fingerprint": fingerprint,
        "tls_trust_mode": "webpki",
        "company_id": str(company["id"]),
        "company_slug": company["slug"],
        "branch_id": str(branch_id),
        "enrollment_token": token,
        "enrollment_profile_id": profile_id or None,
    }
    try:
        build_req = db.create_build_request(
            company_id=company["id"], branch_id=branch_id,
            enrollment_token_id=token_rec["id"], config_json=config_json,
            created_by=g.admin["id"],
            target_platform=target_platform,
        )
    except Exception:
        db.deactivate_enrollment_token(token_rec["id"])
        raise
    if not build_req:
        db.deactivate_enrollment_token(token_rec["id"])
        flash("Failed to queue installer build", "error")
        return redirect(url_for("settings.tokens"))
    db.audit(g.company["id"], g.admin["id"], "installer_generated", {
        "branch_id": branch_id, "target_platform": target_platform,
    })
    return redirect(url_for("settings.tokens"))


@bp.route("/settings/builds")
@login_required
@company_required
def builds():
    company_id = g.company["id"]
    branch_map = {str(b["id"]): b for b in db.get_branches(company_id)}
    raw_builds = db.get_build_requests(company_id, limit=30)
    now = datetime.now(timezone.utc)

    recent = []
    pending_count = 0
    recent_activity = False
    stuck_pending = False
    for b in raw_builds:
        branch = branch_map.get(str(b.get("branch_id")))
        duration = None
        created_dt = _parse_dt(b.get("created_at"))
        completed_dt = _parse_dt(b.get("completed_at"))
        if created_dt and completed_dt:
            duration = f"{int((completed_dt - created_dt).total_seconds())}s"
        status = b.get("status")
        if status in ("pending", "building"):
            pending_count += 1
            if status == "pending" and created_dt and (now - created_dt).total_seconds() > 900:
                stuck_pending = True
        activity_dt = completed_dt or created_dt
        if status in ("building", "completed", "failed") and activity_dt and (now - activity_dt).total_seconds() < 900:
            recent_activity = True
        recent.append({
            "branch_name": branch["name"] if branch else "—",
            "target_platform": b.get("target_platform") or "windows-amd64",
            "status": status,
            "started_ago": b.get("created_at"),
            "duration": duration,
            "log": b.get("build_log"),
        })

    if recent_activity:
        build_service_status = "online"
    elif stuck_pending:
        build_service_status = "offline"
    else:
        build_service_status = "unknown"

    latest = db.get_latest_completed_build()
    return render_template(
        "settings/builds.html",
        recent_builds=recent,
        build_service_status=build_service_status,
        build_agent_version=latest.get("agent_version") if latest else None,
        pending_builds=pending_count,
    )


@bp.route("/settings/policy-templates")
@login_required
@company_required
def policy_templates():
    from policy_settings import POLICY_SETTINGS
    from policy_templates import POLICY_BENCHMARKS
    templates = [
        template for template in db.get_policy_templates(g.company["id"])
        if "windows_firewall_rules" not in (template.get("settings") or {})
    ]
    template_ids = {str(template["id"]) for template in templates}
    deployments = [
        deployment for deployment in db.get_policy_deployments(g.company["id"], limit=30)
        if str(deployment.get("template_id")) in template_ids
    ][:12]
    branches = db.get_branches(g.company["id"])
    branch_names = {str(branch["id"]): branch["name"] for branch in branches}
    endpoint_counts = {}
    for endpoint in db.get_endpoints(g.company["id"]):
        endpoint_branch_id = str(endpoint.get("branch_id") or "")
        endpoint_counts[endpoint_branch_id] = endpoint_counts.get(endpoint_branch_id, 0) + 1
    for branch in branches:
        branch["endpoint_count"] = endpoint_counts.get(str(branch["id"]), 0)
    if g.admin.get("role") == "branch_admin":
        branch_id = g.admin.get("branch_id")
        if not branch_id:
            abort(403)
        branches = [b for b in branches if str(b.get("id")) == str(branch_id)]
        deployments = [
            deployment for deployment in deployments
            if str(deployment.get("branch_id")) == str(branch_id)
        ]
    for deployment in deployments:
        deployment["branch_name"] = branch_names.get(str(deployment.get("branch_id")), "Unknown branch")
    can_manage_templates = g.admin.get("role") in (
        "company_admin", "branch_admin"
    )
    return render_template(
        "settings/policy_templates.html",
        templates=templates,
        catalog={
            key: meta for key, meta in POLICY_SETTINGS.items()
            if key != "windows_firewall_rules"
        },
        branches=branches,
        can_deploy=can_manage_templates,
        can_manage_templates=can_manage_templates,
        deployments=deployments,
        benchmarks=POLICY_BENCHMARKS,
    )


@bp.route("/settings/firewall-policies")
@login_required
@company_required
def firewall_policies():
    """Visual, GPO-style editor for Warden-owned Windows Firewall rules.

    Firewall policies remain ordinary policy templates underneath, so they
    inherit the same signed agent jobs, branch rollout rings, audit trail,
    drift state and clone/deploy model as every other local policy.
    """
    all_templates = db.get_policy_templates(g.company["id"])
    templates = []
    template_ids = set()
    for template in all_templates:
        raw = (template.get("settings") or {}).get("windows_firewall_rules")
        if raw is None:
            continue
        try:
            template["firewall_rules"] = json.loads(raw)
        except (TypeError, ValueError):
            template["firewall_rules"] = []
        templates.append(template)
        template_ids.add(str(template["id"]))

    role = g.admin.get("role")
    scoped_branch_id = g.admin.get("branch_id") if role == "branch_admin" else None
    if role == "branch_admin" and not scoped_branch_id:
        abort(403)

    branches = db.get_branches(g.company["id"])
    endpoints = db.get_endpoints(g.company["id"], branch_id=scoped_branch_id)
    endpoint_counts = {}
    for endpoint in endpoints:
        branch_id = str(endpoint.get("branch_id") or "")
        endpoint_counts[branch_id] = endpoint_counts.get(branch_id, 0) + 1
    for branch in branches:
        branch["endpoint_count"] = endpoint_counts.get(str(branch["id"]), 0)

    deployments = [
        deployment for deployment in db.get_policy_deployments(g.company["id"], limit=30)
        if str(deployment.get("template_id")) in template_ids
    ][:12]
    branch_names = {str(branch["id"]): branch["name"] for branch in branches}
    if role == "branch_admin":
        branches = [branch for branch in branches if str(branch["id"]) == str(scoped_branch_id)]
        deployments = [
            deployment for deployment in deployments
            if str(deployment.get("branch_id")) == str(scoped_branch_id)
        ]
    for deployment in deployments:
        deployment["branch_name"] = branch_names.get(str(deployment.get("branch_id")), "Unknown branch")

    # Program-specific Windows Firewall rules need an executable, not merely
    # the Add/Remove Programs display name.  New agents report the registered
    # DisplayIcon executable with inventory; aggregate identical paths so the
    # editor stays usable across a large fleet while still showing provenance.
    installed_by_path = {}
    for endpoint in endpoints:
        for software in db.get_software(endpoint["id"], limit=5000):
            path = str(software.get("executable_path") or "").strip()
            if not path:
                continue
            key = path.casefold()
            entry = installed_by_path.setdefault(key, {
                "path": path,
                "name": str(software.get("name") or path),
                "publisher": str(software.get("publisher") or ""),
                "version": str(software.get("version") or ""),
                "endpoints": [],
            })
            hostname = str(endpoint.get("display_name") or endpoint.get("hostname") or "Unknown endpoint")
            if hostname not in entry["endpoints"]:
                entry["endpoints"].append(hostname)
    installed_applications = sorted(
        installed_by_path.values(), key=lambda item: (item["name"].casefold(), item["path"].casefold())
    )
    deployment_endpoints = [
        {
            "id": str(endpoint["id"]),
            "hostname": endpoint.get("display_name") or endpoint.get("hostname") or "Unknown endpoint",
            "branch_id": str(endpoint.get("branch_id") or ""),
            "platform": str(endpoint.get("platform") or "windows").lower(),
            "status": endpoint.get("status") or "unknown",
            "tags": [str(value) for value in (endpoint.get("tags") or [])],
        }
        for endpoint in endpoints
    ]

    return render_template(
        "settings/firewall_policies.html",
        templates=templates,
        branches=branches,
        deployments=deployments,
        installed_applications=installed_applications,
        deployment_endpoints=deployment_endpoints,
        can_manage=role == "company_admin",
        can_deploy=role in {"company_admin", "branch_admin"},
    )


@bp.route("/settings/firewall-policies/save", methods=["POST"])
@login_required
@company_required
@role_required("company_admin")
def save_firewall_policy():
    from policy_settings import validate_setting_value

    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict):
        return jsonify({"error": "request body must be an object"}), 400
    name = str(body.get("name") or "").strip()
    description = str(body.get("description") or "").strip()
    template_id = str(body.get("template_id") or "").strip()
    rules = body.get("rules")
    if not name or len(name) > 120:
        return jsonify({"error": "Policy name is required and must be at most 120 characters"}), 400
    if len(description) > 500:
        return jsonify({"error": "Description must be at most 500 characters"}), 400
    if not isinstance(rules, list) or not rules:
        return jsonify({"error": "Add at least one firewall rule"}), 400
    if len(rules) > 100:
        return jsonify({"error": "A firewall policy can contain at most 100 rules"}), 400

    serialised = json.dumps(rules, separators=(",", ":"))
    try:
        validate_setting_value("windows_firewall_rules", serialised)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    settings = {
        "firewall_all_profiles_enabled": True,
        "windows_firewall_rules": serialised,
    }
    if template_id:
        existing = db.get_policy_template(template_id)
        if not existing or str(existing.get("company_id")) != str(g.company["id"]):
            abort(404)
        saved = db.update_policy_template(template_id, name, description, settings)
        event = "firewall_policy_updated"
    else:
        saved = db.create_policy_template(
            g.company["id"], name, description, settings, g.admin["id"],
        )
        event = "firewall_policy_created"
    if not saved:
        return jsonify({"error": "Could not save firewall policy"}), 500
    db.audit(g.company["id"], g.admin["id"], event, {
        "template_id": str(saved["id"]),
        "name": name,
        "rule_count": len(rules),
        "enabled_rule_count": sum(1 for rule in rules if rule.get("enabled", True)),
    })
    return jsonify({"ok": True, "id": str(saved["id"])})


@bp.route("/settings/policy-templates/create", methods=["POST"])
@login_required
@company_required
@role_required("company_admin")
def create_policy_template():
    from policy_settings import validate_settings_dict

    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    settings = request.get_json(silent=True) if request.is_json else None
    if settings is None:
        # Sent as a JSON string in a hidden form field by the template
        # builder UI (checkboxes + per-setting value inputs assembled
        # client-side), not as individual form fields — the set of settings
        # included varies per template.
        import json
        try:
            settings = json.loads(request.form.get("settings_json", "{}"))
        except ValueError:
            return jsonify({"error": "invalid settings payload"}), 400

    if not name:
        return jsonify({"error": "Template name required"}), 400
    try:
        validate_settings_dict(settings)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    template = db.create_policy_template(
        g.company["id"], name, description, settings, g.admin["id"],
    )
    db.audit(g.company["id"], g.admin["id"], "policy_template_created", {
        "name": name, "settings": list(settings.keys()),
    })
    if not template:
        return jsonify({"error": "Failed to create template"}), 500
    return redirect(url_for("settings.policy_templates"))


@bp.route("/settings/policy-templates/<id>/delete", methods=["DELETE"])
@login_required
@company_required
@role_required("company_admin")
def delete_policy_template(id):
    template = db.get_policy_template(id)
    if not template or str(template["company_id"]) != str(g.company["id"]):
        abort(404)
    db.delete_policy_template(id)
    db.audit(g.company["id"], g.admin["id"], "policy_template_deleted", {"name": template["name"]})
    return "", 200


@bp.route("/settings/policy-templates/<id>/deploy", methods=["POST"])
@login_required
@company_required
@role_required("company_admin", "branch_admin")
def deploy_policy_template(id):
    """Queue one validated policy-template job for every active endpoint in a branch."""
    from policy_settings import validate_settings_dict
    from services.entitlements import check_job

    template = db.get_policy_template(id)
    if not template or str(template["company_id"]) != str(g.company["id"]):
        abort(404)
    try:
        validate_settings_dict(template.get("settings"))
    except ValueError as exc:
        return jsonify({"error": f"invalid_saved_template: {exc}"}), 400

    body = request.get_json(silent=True) or {}
    branch_id = str(body.get("branch_id") or "").strip()
    reason = str(body.get("reason") or "").strip()
    idempotency_key = str(body.get("idempotency_key") or "").strip()
    if not branch_id:
        return jsonify({"error": "branch_id_required"}), 400
    if not idempotency_key or len(idempotency_key) > 128:
        return jsonify({"error": "valid idempotency_key required"}), 400

    branch = db.get_branch(branch_id)
    if not branch or str(branch.get("company_id")) != str(g.company["id"]):
        return jsonify({"error": "unknown_branch"}), 404
    require_branch_scope(branch_id)

    entitlement = check_job(g.company["id"], "PUSH_LOCAL_POLICY")
    if not entitlement.allowed:
        return jsonify({"error": entitlement.code, "message": entitlement.message}), 403

    endpoints = db.get_endpoints(g.company["id"], branch_id=branch_id)
    if not endpoints:
        return jsonify({"error": "This branch has no active endpoints."}), 409

    platform = str(body.get("platform") or "windows").strip().lower()
    if platform == "all":
        platform = "windows"  # compatibility with the first targeting UI
    if platform != "windows":
        return jsonify({"error": "invalid_platform_filter"}), 400
    tag = str(body.get("tag") or "").strip()[:64]
    include_ids = body.get("include_endpoint_ids") or []
    exclude_ids = body.get("exclude_endpoint_ids") or []
    if not isinstance(include_ids, list) or not isinstance(exclude_ids, list):
        return jsonify({"error": "endpoint_filters_must_be_arrays"}), 400
    if len(include_ids) > 5000 or len(exclude_ids) > 5000:
        return jsonify({"error": "too_many_endpoint_filters"}), 400
    include_ids = {str(value) for value in include_ids}
    exclude_ids = {str(value) for value in exclude_ids}
    try:
        rollout_percentage = int(body.get("rollout_percentage", 100))
    except (TypeError, ValueError):
        return jsonify({"error": "rollout_percentage_must_be_an_integer"}), 400
    if not 1 <= rollout_percentage <= 100:
        return jsonify({"error": "rollout_percentage_must_be_between_1_and_100"}), 400

    eligible = []
    for endpoint in endpoints:
        endpoint_id = str(endpoint["id"])
        endpoint_platform = str(endpoint.get("platform") or "windows").lower()
        endpoint_tags = {str(value).casefold() for value in (endpoint.get("tags") or [])}
        if endpoint_platform != platform:
            continue
        if tag and tag.casefold() not in endpoint_tags:
            continue
        if include_ids and endpoint_id not in include_ids:
            continue
        if endpoint_id in exclude_ids:
            continue
        eligible.append(endpoint)
    if not eligible:
        return jsonify({"error": "No active endpoints match these filters."}), 409

    # Stable hashing keeps repeated pilot previews on the same devices instead
    # of selecting a different random canary set on every click.
    eligible.sort(key=lambda endpoint: hashlib.sha256(
        f"{template['id']}:{endpoint['id']}".encode("utf-8")
    ).hexdigest())
    target_count = max(1, math.ceil(len(eligible) * rollout_percentage / 100))
    targets = eligible[:target_count]
    selector = {
        "branch_id": branch_id, "platform": platform, "tag": tag or None,
        "include_endpoint_ids": sorted(include_ids),
        "exclude_endpoint_ids": sorted(exclude_ids),
        "eligible_count": len(eligible),
    }

    payload = {"settings": template["settings"], "policy_version": 1}
    deployment = db.create_policy_deployment(
        g.company["id"], branch_id, template, payload, g.admin["id"], reason,
        idempotency_key, endpoint_ids=[endpoint["id"] for endpoint in targets],
        target_selector=selector, rollout_percentage=rollout_percentage,
    )
    if not deployment:
        return jsonify({"error": "No policy jobs could be queued."}), 500
    targeted = int(deployment.get("targeted") or 0)
    queued = int(deployment.get("queued") or 0)
    failed = targeted - queued

    db.audit(g.company["id"], g.admin["id"], "policy_template_group_deployed", {
        "template_id": str(template["id"]),
        "template_name": template["name"],
        "branch_id": branch_id,
        "branch_name": branch.get("name"),
        "deployment_id": str(deployment["deployment_id"]),
        "targeted": targeted,
        "queued": queued,
        "failed": failed,
        "reason": reason,
        "target_selector": selector,
        "rollout_percentage": rollout_percentage,
    })
    return jsonify({
        "ok": True,
        "deployment_id": str(deployment["deployment_id"]),
        "template": template["name"],
        "branch": branch.get("name"),
        "targeted": targeted,
        "queued": queued,
        "failed": failed,
        "eligible": len(eligible),
        "rollout_percentage": rollout_percentage,
    })


@bp.route("/settings/policy-deployments/<id>/cancel", methods=["POST"])
@login_required
@company_required
@role_required("company_admin", "branch_admin")
def cancel_policy_deployment(id):
    deployment = db.get_policy_deployment(id)
    if not deployment or str(deployment["company_id"]) != str(g.company["id"]):
        abort(404)
    require_branch_scope(deployment.get("branch_id"))
    cancelled = db.cancel_policy_deployment(id, g.company["id"])
    db.audit(g.company["id"], g.admin["id"], "policy_deployment_cancelled", {
        "deployment_id": id, "cancelled_jobs": cancelled,
    })
    return jsonify({"ok": True, "cancelled": cancelled})


@bp.route("/settings/policy-deployments/<id>/retry", methods=["POST"])
@login_required
@company_required
@role_required("company_admin", "branch_admin")
def retry_policy_deployment(id):
    deployment = db.get_policy_deployment(id)
    if not deployment or str(deployment["company_id"]) != str(g.company["id"]):
        abort(404)
    require_branch_scope(deployment.get("branch_id"))
    retried = db.retry_policy_deployment(id, g.company["id"])
    db.audit(g.company["id"], g.admin["id"], "policy_deployment_retried", {
        "deployment_id": id, "retried_jobs": retried,
    })
    return jsonify({"ok": True, "retried": retried})


_AGENT_RECOVERY_SCRIPT = r"""<#
.SYNOPSIS
  Warden Agent -- emergency removal script for a service stuck under its
  own tamper-protection lock.

.DESCRIPTION
  Fully removes a WardenAgent Windows service and its data directory when
  it's stuck in a locked state and cannot be started, stopped, or removed
  by a local Administrator -- e.g. installed by a buggy version of
  install.bat that locked the service down before ever starting it once,
  or any other situation where the service's tamper-protection ACL is
  blocking legitimate recovery ("Access Denied" from net start/sc stop/
  sc delete even when run elevated).

  This is NOT the sanctioned way to remove a HEALTHY Warden agent -- that
  requires a server-approved, signed UNINSTALL_AGENT job dispatched from
  the Warden admin console, which goes through this agent's own approval
  and audit flow. This script exists purely to tear down a broken local
  install that the sanctioned path can't reach, because the agent itself
  isn't running well enough to receive that job. After running this, the
  machine has no Warden agent at all -- reinstall with a freshly generated
  installer from Settings -> Enrollment Tokens.

  Must be run as Administrator. Internally uses a temporary SYSTEM-context
  scheduled task, since the locked ACL only grants control rights to
  SYSTEM, not even to Administrators.
#>

# Everything is wrapped in this try/finally so the console window stays
# open long enough to actually read the output no matter how the script
# was launched or which path it takes (success, early exit, error exit).
# Double-clicking a .ps1 opens a console that closes the INSTANT the
# script finishes -- especially on an error, since $ErrorActionPreference
# = 'Stop' terminates immediately -- so without this, a failure's whole
# explanation can vanish before it's ever readable. `exit` inside a try
# still runs its enclosing finally before the process actually exits.
#
# Deliberately NOT using "#Requires -RunAsAdministrator" -- that check
# happens before the script body even starts, outside this try/finally
# entirely, so an elevation failure would still vanish instantly with no
# chance to read it. Checking manually instead keeps it under the same
# pause-before-close guarantee as everything else.
$ErrorActionPreference = 'Stop'
try {

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "This script must be run as Administrator." -ForegroundColor Red
    Write-Host "Right-click PowerShell -> 'Run as Administrator', then run this script again." -ForegroundColor Red
    exit 1
}

$serviceName = 'WardenAgent'
$dataDir     = 'C:\ProgramData\WardenAgent'
$taskName    = 'WardenAgentRecoveryRemove'

Write-Host "Warden Agent recovery -- removing service '$serviceName' and its data..." -ForegroundColor Cyan

$svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if (-not $svc -and -not (Test-Path $dataDir)) {
    Write-Host "Nothing found to remove -- no service, no data directory." -ForegroundColor Yellow
    exit 0
}

# All run as SYSTEM, which already holds full control over both the
# service and the data directory regardless of the locked ACL (see
# agent-go/tamper.go's hardenService()/hardenDataDir()) -- no separate
# "unlock" step is needed, SYSTEM can just tear it all down directly.
#
# "sc stop" only REQUESTS a stop and returns immediately -- it does not
# wait for the process to actually exit. The agent's own shutdown path
# (agent-go/service.go's Execute()) waits up to 10s for a graceful stop
# before giving up, and its rotating log writer keeps agent.log open for
# the whole process lifetime -- so deleting the data directory before the
# process has actually exited fails on whatever files it still has open,
# often silently. Poll for a real STOPPED state (up to 15s) and force-kill
# by image name as a fallback (also catches any orphaned remote-desktop
# helper child process, which shares the same exe) before removing anything.
#
# "takeown" (not just icacls /reset) is used on the data directory because
# /reset depends on inheriting sane permissions back from the parent
# (C:\ProgramData) -- taking ownership outright doesn't depend on that,
# and is the same mechanism a real Administrator would use by hand. Every
# step's own output/errorlevel is logged to a file so a failure is visible
# instead of silent.
$logPath = 'C:\Windows\Temp\warden-remove-log.txt'
$cmd = @"
echo === Warden Agent removal log === > $logPath
echo Running as: >> $logPath
whoami >> $logPath 2>&1
echo [1/6] Requesting service stop... >> $logPath
sc stop $serviceName >> $logPath 2>&1
setlocal EnableDelayedExpansion
set waited=0
:waitloop
sc query $serviceName 2>>$logPath | find "STOPPED" >nul 2>&1
if not errorlevel 1 goto stopped
set /a waited+=1
if !waited! GEQ 15 goto stopped
timeout /t 1 /nobreak >nul
goto waitloop
:stopped
echo [2/6] Service stop wait finished after !waited!s. >> $logPath
echo [3/6] Force-killing any remaining warden-agent.exe processes... >> $logPath
taskkill /F /IM warden-agent.exe /T >> $logPath 2>&1
echo [4/6] Deleting service registration... >> $logPath
sc delete $serviceName >> $logPath 2>&1
echo [5/6] Taking ownership and granting full control on $dataDir ... >> $logPath
takeown /f "$dataDir" /r /d y >> $logPath 2>&1
icacls "$dataDir" /grant:r *S-1-5-18:(OI)(CI)(F) /t /c >> $logPath 2>&1
icacls "$dataDir" /grant:r *S-1-5-32-544:(OI)(CI)(F) /t /c >> $logPath 2>&1
echo [6/6] Removing $dataDir ... >> $logPath
rmdir /s /q "$dataDir" >> $logPath 2>&1
if exist "$dataDir" (
  echo RESULT: directory still exists after rmdir. >> $logPath
) else (
  echo RESULT: directory fully removed. >> $logPath
)
"@

# C:\Windows\Temp, not the calling user's %TEMP% -- SYSTEM is guaranteed
# access here regardless of how that user profile's own folder ACLs are set.
$scriptPath = 'C:\Windows\Temp\warden-remove-inner.bat'
Set-Content -Path $scriptPath -Value $cmd -Encoding ASCII

try {
    $createOut = schtasks /create /tn $taskName /tr "cmd /c `"$scriptPath`"" /sc once /st 23:59 /ru SYSTEM /f 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "Could not create the SYSTEM-context recovery task (exit $LASTEXITCODE):" -ForegroundColor Red
        Write-Host "$createOut" -ForegroundColor Red
        Write-Host "Nothing was run as SYSTEM -- the removal below did not happen." -ForegroundColor Red
        exit 1
    }
    $runOut = schtasks /run /tn $taskName 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "Could not RUN the recovery task (exit $LASTEXITCODE):" -ForegroundColor Red
        Write-Host "$runOut" -ForegroundColor Red
        schtasks /delete /tn $taskName /f 2>&1 | Out-Null
        exit 1
    }

    Write-Host "Waiting for removal to finish (up to ~20s -- the agent's own graceful shutdown needs time)..." -ForegroundColor Cyan
    Start-Sleep -Seconds 20

    schtasks /delete /tn $taskName /f | Out-Null
}
finally {
    Remove-Item -Path $scriptPath -ErrorAction SilentlyContinue
}

if (Test-Path $logPath) {
    Write-Host ""
    Write-Host "--- Removal log ---" -ForegroundColor Cyan
    Get-Content $logPath | ForEach-Object { Write-Host $_ }
    Write-Host "-------------------" -ForegroundColor Cyan
    Remove-Item -Path $logPath -ErrorAction SilentlyContinue
}

$stillThere = (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) -or (Test-Path $dataDir)
if ($stillThere) {
    Write-Host ""
    Write-Host "Removal incomplete -- see the log above for which step failed. Check manually:" -ForegroundColor Yellow
    Write-Host "  Get-Service $serviceName"
    Write-Host "  Test-Path '$dataDir'"
} else {
    Write-Host ""
    Write-Host "Service and data directory fully removed." -ForegroundColor Green
    Write-Host "Generate a fresh installer from Settings -> Enrollment Tokens to reinstall." -ForegroundColor Green
}

} catch {
    Write-Host ""
    Write-Host "Unexpected error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkRed
} finally {
    Write-Host ""
    Write-Host "Press Enter to close this window..." -ForegroundColor Gray
    Read-Host | Out-Null
}
"""


@bp.route("/settings/agent-recovery-script")
@login_required
@company_required
@role_required("company_admin")
def agent_recovery_script():
    """Downloads a PowerShell script that fully removes a WardenAgent
    Windows service (and its data directory) stuck under its own
    tamper-protection ACL (see agent-go/tamper.go) -- an emergency recovery
    tool, not the sanctioned removal path (that's a server-approved
    UNINSTALL_AGENT job). Audited since it bypasses a security control by
    design."""
    db.audit(g.company["id"], g.admin["id"], "agent_recovery_script_downloaded")
    from flask import Response
    return Response(
        _AGENT_RECOVERY_SCRIPT,
        mimetype="text/plain",
        headers={"Content-Disposition": "attachment; filename=warden-agent-recovery.ps1"},
    )


@bp.route("/settings/notifications", methods=["POST"])
@login_required
def update_notifications():
    prefs = {
        "in_app": request.form.get("in_app") == "1",
        "escalation": request.form.get("escalation") == "1",
        "alerts": request.form.get("alerts") == "1",
        "email": request.form.get("email") == "1",
    }
    db.update_admin(g.admin["id"], {"notification_prefs": prefs})
    return jsonify({"ok": True})


@bp.route("/settings/thresholds")
@login_required
@company_required
def thresholds():
    t = db.get_alert_thresholds(g.company["id"]) or {
        "cpu_pct": 90, "ram_pct": 90, "disk_free_gb": 5, "offline_minutes": 5
    }
    return render_template("settings/thresholds.html", thresholds=t)


@bp.route("/settings/thresholds", methods=["POST"])
@login_required
@company_required
@role_required("company_admin")
def save_thresholds():
    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict):
        return jsonify({"error": "invalid_payload"}), 400
    try:
        cpu_pct = int(body.get("cpu_pct", 90))
        ram_pct = int(body.get("ram_pct", 90))
        disk_free_gb = int(body.get("disk_free_gb", 5))
        offline_minutes = int(body.get("offline_minutes", 5))
    except (TypeError, ValueError):
        return jsonify({"error": "thresholds_must_be_integers"}), 400
    if not (1 <= cpu_pct <= 100 and 1 <= ram_pct <= 100
            and 0 <= disk_free_gb <= 100000 and 1 <= offline_minutes <= 10080):
        return jsonify({"error": "threshold_out_of_range"}), 400
    db.upsert_alert_thresholds(
        company_id=g.company["id"],
        cpu_pct=cpu_pct,
        ram_pct=ram_pct,
        disk_free_gb=disk_free_gb,
        offline_minutes=offline_minutes,
    )
    db.audit(g.company["id"], g.admin["id"], "alert_thresholds_updated", body)
    return jsonify({"ok": True})


@bp.route("/settings/security")
@login_required
@company_required
@role_required("company_admin")
def security():
    """Organization encryption, approval, update, and TLS controls."""
    endpoints = [
        endpoint for endpoint in db.get_endpoints(g.company["id"])
        if "ROTATE_TLS_PINS" in set(endpoint.get("capabilities") or [])
    ]
    return render_template(
        "settings/security.html", company=g.company,
        tls_rotation_endpoints=endpoints,
    )


@bp.route("/settings/security/encryption", methods=["POST"])
@login_required
@company_required
@role_required("company_admin")
def set_encryption_mode():
    """Switch this organization from managed to BYOK encryption. Re-wraps the
    *existing* DEK under the new passphrase (see
    tenant_crypto.rewrap_to_byok) so every row already encrypted under
    managed mode stays decryptable — nothing is re-encrypted, because
    the underlying DEK never changes. Changing an already-set BYOK
    passphrase, or moving BYOK back to managed, isn't supported here —
    same principle applies (rewrap the same DEK again), just not wired
    up as a route yet."""
    from services.tenant_crypto import rewrap_to_byok

    if g.company.get("encryption_mode") == "byok":
        return jsonify({"error": "This organization is already BYOK. Re-keying isn't supported yet."}), 400

    mode = request.form.get("mode", "managed")
    if mode != "byok":
        return jsonify({"error": "Only switching managed -> byok is supported here"}), 400

    passphrase = request.form.get("passphrase", "")
    try:
        fields = rewrap_to_byok(g.company["id"], g.company.get("encryption_mode", "managed"),
                                 g.company.get("wrapped_dek"), passphrase)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    db.set_company_encryption(g.company["id"], fields["encryption_mode"],
                               fields["wrapped_dek"], fields["byok_salt"])
    db.audit(g.company["id"], g.admin["id"], "tenant_encryption_mode_changed", {"mode": "byok"})
    return jsonify({"ok": True})


@bp.route("/settings/security/encryption/rewrap", methods=["POST"])
@login_required
@company_required
@role_required("company_admin")
def rewrap_encryption_key():
    if g.company.get("encryption_mode") != "byok":
        return jsonify({"error": "Organization is not using BYOK"}), 400
    current = request.form.get("current_passphrase", "")
    target = request.form.get("target_mode", "byok")
    new_passphrase = request.form.get("new_passphrase", "")
    from services.tenant_crypto import unlock_byok, rewrap_to_byok, rewrap_to_managed, lock_company
    if target not in {"managed", "byok"}:
        return jsonify({"error": "Invalid target mode"}), 400
    try:
        unlock_byok(
            g.company["id"], current, g.company.get("wrapped_dek"),
            g.company.get("byok_salt"),
        )
        if target == "managed":
            fields = rewrap_to_managed(g.company["id"], "byok", g.company.get("wrapped_dek"))
        elif target == "byok":
            fields = rewrap_to_byok(g.company["id"], "byok", g.company.get("wrapped_dek"), new_passphrase)
    except ValueError as exc:
        lock_company(g.company["id"])
        return jsonify({"error": str(exc)}), 400
    db.set_company_encryption(
        g.company["id"], fields["encryption_mode"], fields["wrapped_dek"], fields["byok_salt"],
    )
    if target == "byok":
        lock_company(g.company["id"])
    db.audit(g.company["id"], g.admin["id"], "tenant_encryption_key_rewrapped", {
        "target_mode": target,
    })
    return jsonify({"ok": True})


@bp.route("/settings/security/dual-approval", methods=["POST"])
@login_required
@company_required
@role_required("company_admin")
def set_dual_approval():
    """Organization-level opt-out of the two-different-admins requirement on
    dual-approval-gated ops (UNINSTALL_AGENT, SHUTDOWN, REBOOT, DELETE_USER,
    etc. — see routes/endpoints.py's DUAL_APPROVAL_OPS). Weakens a real
    security control, so it's an explicit, audited organization choice —
    not a default — for organizations (e.g. solo-admin) that can never produce a
    second distinct approver."""
    required = request.values.get("required") == "1"
    db.set_company_dual_approval(g.company["id"], required)
    db.audit(g.company["id"], g.admin["id"], "tenant_dual_approval_setting_changed", {"required": required})
    return jsonify({"ok": True})


@bp.route("/settings/security/auto-update", methods=["POST"])
@login_required
@company_required
@role_required("company_admin")
def set_auto_update():
    """Organization-level opt-in: when enabled, the background scheduler
    (services/scheduler.py) auto-dispatches UPDATE_AGENT to any online
    endpoint whose reported agent_version lags the latest completed build,
    instead of waiting for an admin to click Update Agent per-endpoint."""
    enabled = request.values.get("enabled") == "1"
    db.set_company_auto_update(g.company["id"], enabled)
    db.audit(g.company["id"], g.admin["id"], "tenant_auto_update_setting_changed", {"enabled": enabled})
    return jsonify({"ok": True})


@bp.route("/settings/security/vault/unlock", methods=["POST"])
@login_required
@company_required
@role_required("company_admin")
def unlock_vault():
    from services.tenant_crypto import unlock_byok
    if g.company.get("encryption_mode") != "byok":
        return jsonify({"error": "This organization isn't in BYOK mode"}), 400
    passphrase = request.form.get("passphrase", "")
    try:
        unlock_byok(g.company["id"], passphrase, g.company.get("wrapped_dek"), g.company.get("byok_salt"))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 401
    db.audit(g.company["id"], g.admin["id"], "tenant_vault_unlocked")
    return jsonify({"ok": True})


@bp.route("/settings/security/vault/lock", methods=["POST"])
@login_required
@company_required
@role_required("company_admin")
def lock_vault():
    from services.tenant_crypto import lock_company
    lock_company(g.company["id"])
    db.audit(g.company["id"], g.admin["id"], "tenant_vault_locked")
    return jsonify({"ok": True})


@bp.route("/settings/disable-mfa", methods=["POST"])
@login_required
def disable_mfa():
    from routes.auth import _check_password
    password = request.form.get("password", "")
    if not _check_password(password, g.admin["password_hash"]):
        return jsonify({"error": "Incorrect password"}), 401
    db.disable_admin_mfa(g.admin["id"])
    db.audit(g.admin.get("company_id"), g.admin["id"], "mfa_disabled")
    return redirect(url_for("settings.index"))
