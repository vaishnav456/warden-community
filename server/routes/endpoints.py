"""
Warden — Endpoints routes
List, detail (tabbed), create enrollment token, job dispatch.
"""
import base64
import binascii
import hashlib
import ipaddress
import json
import logging
import pathlib
import re
import secrets
from datetime import date, datetime, timedelta, timezone
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, g, abort, Response, make_response

import config
import db
from services.dashboard_view import selected_branch, prepare_endpoints, report_online, scoped_url
from middleware.auth import login_required, company_required, role_required, require_branch_scope
from services.agent_updates import AgentBuildUnavailable, update_payload

bp = Blueprint("endpoints", __name__)
log = logging.getLogger("warden.endpoints")

# Approval is deliberately reserved for operations whose impact is
# destructive, arbitrary, or unusually difficult to reverse. Routine
# administration is already role/branch scoped and fully audited.
ESCALATION_REQUIRED_OPS = {
    "DELETE_USER", "RUN_CMD", "REBOOT", "SHUTDOWN",
    "UNINSTALL_AGENT", "ROTATE_TLS_PINS",
    "GRANT_ELEVATION",
    "CAPTURE_PACKETS",
    "ENABLE_BITLOCKER", "ROTATE_BITLOCKER_RECOVERY",
}
DUAL_APPROVAL_OPS = {
    "DELETE_USER", "SHUTDOWN", "REBOOT", "UNINSTALL_AGENT",
    "ROTATE_TLS_PINS", "GRANT_ELEVATION",
    "ENABLE_BITLOCKER", "ROTATE_BITLOCKER_RECOVERY",
}

# A technician is a help-desk operator, not an organization administrator. Keep
# direct endpoint execution limited to evidence collection and diagnostics.
# Higher-impact actions may still be requested when they are explicitly in
# ESCALATION_REQUIRED_OPS, but an administrator must approve the request.
TECHNICIAN_DIRECT_OPS = {
    "COLLECT_SYSINFO", "COLLECT_SOFTWARE", "COLLECT_USERS",
    "COMPLIANCE_SCAN", "GET_EVENT_LOGS", "CHECK_POLICY_DRIFT",
    "LIST_DIRECTORY", "FILE_PULL", "COLLECT_NETWORK_FLOWS",
}


PLATFORM_DEFAULT_CAPABILITIES = {
    # Empty capability arrays belong to pre-capability Windows agents.
    "windows": {
        "INSTALL_APP", "UNINSTALL_APP", "CREATE_USER", "PROVISION_WARDEN_IDENTITY", "DELETE_USER",
        "WARDEN_ONLY_LOCKDOWN",
        "RESET_PASSWORD", "DISABLE_USER", "ENABLE_USER", "GRANT_ELEVATION",
        "REVOKE_ELEVATION", "RUN_CMD", "REBOOT", "SHUTDOWN",
        "COLLECT_SYSINFO", "COLLECT_SOFTWARE", "UPDATE_AGENT", "REINSTALL_AGENT",
        "SET_PERIPHERAL_POLICY", "SETUP_REMOTE_ACCESS", "REMOVE_REMOTE_ACCESS",
        "COMPLIANCE_SCAN", "FILE_PUSH", "FILE_PULL", "LIST_DIRECTORY",
        "GET_EVENT_LOGS", "WINDOWS_UPDATE", "UNINSTALL_AGENT",
        "PUSH_LOCAL_POLICY", "CHECK_POLICY_DRIFT", "COLLECT_USERS",
        "ROTATE_TLS_PINS",
        "CONFIGURE_DEVICE_IDENTITY",
        "CAPTURE_PACKETS",
        "COLLECT_NETWORK_FLOWS",
        "SYNC_WARDEN_HOME",
        "APPLY_DEVICE_EXPERIENCE",
        "ENABLE_BITLOCKER", "ROTATE_BITLOCKER_RECOVERY",
    },
}


def _endpoint_capabilities(endpoint):
    reported = endpoint.get("capabilities")
    if isinstance(reported, list) and reported:
        return {str(value) for value in reported}
    return PLATFORM_DEFAULT_CAPABILITIES.get(endpoint.get("platform") or "windows", set())


def _fail_remote_session(session_id, reason):
    """Best-effort rollback that must not hide the original provisioning
    failure when PostgREST is itself unhealthy."""
    try:
        db.mark_remote_session_failed(session_id, reason)
    except Exception:
        log.exception("Could not mark remote session %s failed", session_id)


@bp.route("/endpoints")
@login_required
@company_required
def list_endpoints():
    from services.endpoint_fleet import load, listing
    branch_id = selected_branch()
    branches = db.get_branches(g.company["id"])
    if g.admin.get("role") == "branch_admin":
        branches = [b for b in branches if str(b.get("id")) == str(branch_id)]
    context = listing(load(g.company, branch_id), request.args)
    filters = dict(q=context["query"], state=context["selected_state"],
                   health=context["selected_health"], platform=context["selected_platform"],
                   sort=context["selected_sort"], page_size=context["page_size"])
    def fleet_url(**changes):
        return scoped_url("/endpoints", branch_id, **{**filters, **changes})
    context.update(branches=branches, branch_names={str(b["id"]): b["name"] for b in branches},
                   selected_branch=branch_id, fleet_url=fleet_url,
                   scoped_url=lambda path, **values: scoped_url(path, branch_id, **values))
    if request.headers.get("X-Fleet-Refresh") == "1":
        response = jsonify(
            rows=render_template("partials/endpoint_cards.html", **context),
            pagination=render_template("partials/endpoint_pagination.html", **context),
            summary=context["fleet_summary"], total=context["total_matches"],
            shown=len(context["endpoints"]), page=context["page"], pages=context["page_count"])
    else:
        response = make_response(render_template("endpoints/list.html", **context))
    response.headers["Cache-Control"] = "private, no-store"
    return response

@bp.route("/endpoints/<endpoint_id>/users/<user_id>/photo")
@login_required
@company_required
def endpoint_user_photo(endpoint_id, user_id):
    endpoint = db.get_endpoint(endpoint_id)
    if not endpoint or str(endpoint["company_id"]) != str(g.company["id"]):
        abort(404)
    require_branch_scope(endpoint.get("branch_id"))
    user = db.get_windows_user(user_id)
    if not user or str(user.get("endpoint_id")) != str(endpoint_id):
        abort(404)
    data_url = str(user.get("profile_photo") or "")
    if user.get("profile_photo_mime") != "image/png" or not data_url.startswith("data:image/png;base64,"):
        abort(404)
    try:
        raw = base64.b64decode(data_url.split(",", 1)[1], validate=True)
    except (ValueError, binascii.Error, IndexError):
        abort(404)
    response = Response(raw, mimetype="image/png")
    response.headers["Cache-Control"] = "private, max-age=300"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@bp.route("/endpoints/<endpoint_id>")
@login_required
@company_required
def detail(endpoint_id):
    endpoint = db.get_endpoint(endpoint_id)
    if not endpoint or str(endpoint["company_id"]) != str(g.company["id"]):
        abort(404)
    require_branch_scope(endpoint.get("branch_id"))
    server_base = config.SERVER_URL.rstrip("/")
    if not server_base.startswith("https://"):
        return jsonify({"error": "remote_relay_requires_https_server_url"}), 503

    tab = request.args.get("tab", "overview")
    endpoint_capabilities = _endpoint_capabilities(endpoint)
    tab_capability = {
        "sessions": "SETUP_REMOTE_ACCESS",
        "software": "COLLECT_SOFTWARE",
        "users": "COLLECT_USERS",
        "compliance": "COMPLIANCE_SCAN",
        "policy": "PUSH_LOCAL_POLICY",
        "firewall": "PUSH_LOCAL_POLICY",
        "experience": "APPLY_DEVICE_EXPERIENCE",
        "encryption": "ENABLE_BITLOCKER",
    }
    required = tab_capability.get(tab)
    if required and required not in endpoint_capabilities:
        return redirect(url_for("endpoints.detail", endpoint_id=endpoint_id, tab="overview"))
    branch = db.get_branch(endpoint["branch_id"]) if endpoint.get("branch_id") else None
    apps = db.get_app_library(g.company["id"])

    # Tab-specific data
    users = []
    software = []
    events = []
    jobs = []
    pending_escalations = []
    sessions = []
    alerts = []
    metrics = []
    compliance_result = None
    recovery_keys = []

    if tab == "overview":
        events = db.get_endpoint_events(endpoint_id, limit=20)
        metrics = db.get_metrics(endpoint_id, hours=24, max_points=240)
        alerts = db.get_alerts(g.company["id"], resolved=False, limit=5)
        alerts = [a for a in alerts if str(a.get("endpoint_id")) == endpoint_id]
    elif tab == "users":
        users = db.get_windows_users(endpoint_id)
        managed_usernames = {
            value.casefold()
            for value in db.get_managed_warden_usernames_for_endpoint(endpoint_id)
        }
        for user in users:
            user["warden_managed"] = str(user.get("username") or "").casefold() in managed_usernames
    elif tab == "software":
        search = request.args.get("q", "")
        software = db.get_software(endpoint_id, search=search or None)
        findings_by_software = {}
        for finding in db.get_vulnerability_findings(
                g.company["id"], endpoint_id=endpoint_id, limit=2000):
            findings_by_software.setdefault(str(finding.get("software_id")), []).append(finding)
        for installed in software:
            installed["vulnerabilities"] = findings_by_software.get(str(installed.get("id")), [])
    elif tab == "events":
        events = db.get_endpoint_events(endpoint_id, limit=100)
    elif tab == "jobs":
        jobs = db.get_jobs(g.company["id"], endpoint_id=endpoint_id, limit=30)
        pending_escalations = [
            item for item in db.get_escalation_requests(g.company["id"], limit=100)
            if str(item.get("endpoint_id")) == str(endpoint_id)
            and item.get("status") in {"pending", "pending_secondary"}
        ]
    elif tab == "sessions":
        sessions = db.get_remote_sessions(endpoint_id)
        for session in sessions:
            session["collaboration_events"] = [
                event for event in db.get_remote_session_events(session["id"])
                if event.get("event_type") in {"note", "chat_admin", "chat_endpoint"}
            ]
    elif tab == "alerts":
        all_alerts = db.get_alerts(g.company["id"], limit=50)
        alerts = [a for a in all_alerts if str(a.get("endpoint_id")) == endpoint_id]
    elif tab == "compliance":
        compliance_result = db.get_compliance_result(endpoint_id)
    elif tab == "metrics":
        metrics = db.get_metrics(endpoint_id, hours=24, max_points=240)
    elif tab == "encryption":
        from services.bitlocker_status import display_status
        recovery_keys = display_status(endpoint)

    from policy_templates import POLICY_TEMPLATES
    from policy_settings import POLICY_SETTINGS

    saved_policy_templates = db.get_policy_templates(g.company["id"]) if tab in {"policy", "firewall"} else []
    firewall_policy_templates = []
    endpoint_firewall_rules = []
    endpoint_firewall_applications = []
    packet_captures = []
    if tab == "firewall":
        firewall_policy_templates = [
            template for template in saved_policy_templates
            if "windows_firewall_rules" in (template.get("settings") or {})
        ]
        firewall_state = (endpoint.get("policy_state") or {}).get("windows_firewall_rules") or {}
        raw_rules = firewall_state.get("current_value")
        if raw_rules is None:
            raw_rules = firewall_state.get("value")
        if isinstance(raw_rules, str):
            try:
                parsed_rules = json.loads(raw_rules)
                if isinstance(parsed_rules, list):
                    endpoint_firewall_rules = parsed_rules
            except (TypeError, ValueError):
                pass
        # Application-targeted firewall rules require the real executable
        # path reported by this endpoint, not an installer name from the app
        # package library.  Expose the endpoint's inventory as a safe picker
        # while retaining manual path entry for portable/custom software.
        seen_application_paths = set()
        for installed in db.get_software(endpoint_id, limit=5000):
            executable_path = str(installed.get("executable_path") or "").strip()
            path_key = executable_path.casefold()
            if not executable_path or path_key in seen_application_paths:
                continue
            seen_application_paths.add(path_key)
            endpoint_firewall_applications.append({
                "path": executable_path,
                "name": str(installed.get("name") or executable_path),
                "publisher": str(installed.get("publisher") or ""),
                "version": str(installed.get("version") or ""),
            })
        endpoint_firewall_applications.sort(
            key=lambda item: (item["name"].casefold(), item["path"].casefold())
        )
        packet_captures = [
            job for job in db.get_jobs(g.company["id"], endpoint_id=endpoint_id, limit=50)
            if job.get("type") == "CAPTURE_PACKETS"
        ][:10]

    from services.endpoint_drives import local_drives
    return render_template(
        "endpoints/detail.html",
        local_drives=local_drives(endpoint),
        endpoint=endpoint,
        branch=branch,
        tab=tab,
        apps=apps,
        policy_templates=POLICY_TEMPLATES,
        policy_settings={
            key: meta for key, meta in POLICY_SETTINGS.items()
            if key != "windows_firewall_rules"
        },
        saved_policy_templates=saved_policy_templates,
        firewall_policy_templates=firewall_policy_templates,
        endpoint_firewall_rules=endpoint_firewall_rules,
        endpoint_firewall_applications=endpoint_firewall_applications,
        packet_captures=packet_captures,
        server_url=server_base,
        users=users,
        software=software,
        events=events,
        jobs=jobs,
        pending_escalations=pending_escalations,
        sessions=sessions,
        alerts=alerts,
        metrics=metrics,
        compliance_result=compliance_result,
        recovery_keys=recovery_keys,
        endpoint_capabilities=endpoint_capabilities,
        endpoint_platform=endpoint.get("platform") or "windows",
        capability_details=endpoint.get("capability_details") or {},
    )


@bp.route("/partials/endpoints/<endpoint_id>/jobs")
@login_required
@company_required
def endpoint_jobs_partial(endpoint_id):
    endpoint = db.get_endpoint(endpoint_id)
    if not endpoint or str(endpoint.get("company_id")) != str(g.company["id"]):
        abort(404)
    require_branch_scope(endpoint.get("branch_id"))
    jobs = db.get_jobs(g.company["id"], endpoint_id=endpoint_id, limit=30)
    pending_escalations = [
        item for item in db.get_escalation_requests(g.company["id"], limit=100)
        if str(item.get("endpoint_id")) == str(endpoint_id)
        and item.get("status") in {"pending", "pending_secondary"}
    ]
    return render_template("partials/endpoint_job_history.html", endpoint=endpoint, jobs=jobs,
                           pending_escalations=pending_escalations)


@bp.route("/partials/endpoint-row/<endpoint_id>")
@login_required
@company_required
def endpoint_row(endpoint_id):
    """HTMX partial — single endpoint row for live status refresh."""
    endpoint = db.get_endpoint(endpoint_id)
    if not endpoint or str(endpoint["company_id"]) != str(g.company["id"]):
        abort(404)
    require_branch_scope(endpoint.get("branch_id"))
    branch = db.get_branch(endpoint["branch_id"]) if endpoint.get("branch_id") else None
    branch_names = {str(endpoint.get("branch_id")): branch["name"]} if branch else {}
    from services.endpoint_fleet import prepare, recent_jobs
    scan = db.get_compliance_result(endpoint_id)
    endpoint = prepare([endpoint], [scan] if scan else [],
                       db.get_patch_inventory(g.company["id"]),
                       recent_jobs(g.company["id"], endpoint_id=endpoint_id))[0]
    return render_template("partials/endpoint_row.html", endpoint=endpoint, branch_names=branch_names)


@bp.route("/partials/endpoint-status/<endpoint_id>")
@login_required
@company_required
def endpoint_status(endpoint_id):
    """HTMX partial — just the status badge."""
    endpoint = db.get_endpoint(endpoint_id)
    if not endpoint or str(endpoint["company_id"]) != str(g.company["id"]):
        abort(404)
    require_branch_scope(endpoint.get("branch_id"))
    return render_template("partials/endpoint_status.html", endpoint=endpoint)


@bp.get("/partials/bitlocker-status/<endpoint_id>")
@login_required
@company_required
def bitlocker_status_partial(endpoint_id):
    endpoint = db.get_endpoint(endpoint_id)
    if not endpoint or str(endpoint["company_id"]) != str(g.company["id"]):
        abort(404)
    require_branch_scope(endpoint.get("branch_id"))
    from services.bitlocker_status import display_status
    response = make_response(render_template(
        "partials/bitlocker_status.html", recovery_keys=display_status(endpoint)))
    response.headers["Cache-Control"] = "no-store"
    return response


@bp.route("/endpoints/<endpoint_id>/recovery-keys/<recovery_key_id>/reveal", methods=["POST"])
@login_required
@company_required
@role_required("company_admin")
def reveal_recovery_key(endpoint_id, recovery_key_id):
    endpoint = db.get_endpoint(endpoint_id)
    if not endpoint or str(endpoint.get("company_id")) != str(g.company["id"]):
        abort(404)
    require_branch_scope(endpoint.get("branch_id"))
    try:
        record = db.reveal_endpoint_recovery_key(g.company, recovery_key_id)
    except Exception as exc:
        from services.tenant_crypto import VaultLocked
        if isinstance(exc, VaultLocked):
            return jsonify({"error": "Organization vault is locked"}), 423
        raise
    if not record or str(record.get("endpoint_id")) != str(endpoint_id):
        abort(404)
    db.audit(g.company["id"], g.admin["id"], "bitlocker_recovery_key_revealed", {
        "endpoint_id": endpoint_id, "recovery_key_id": recovery_key_id,
        "volume_mount": record.get("volume_mount"), "protector_id": record.get("protector_id"),
    }, branch_id=endpoint.get("branch_id"), endpoint_id=endpoint_id)
    response = jsonify({
        "recovery_password": record["recovery_password"],
        "volume_mount": record.get("volume_mount"),
        "protector_id": record.get("protector_id"),
    })
    response.headers["Cache-Control"] = "no-store"
    return response


@bp.post("/endpoints/<endpoint_id>/nickname")
@login_required
@company_required
@role_required("superadmin", "company_admin", "branch_admin")
def update_nickname(endpoint_id):
    endpoint = db.get_endpoint(endpoint_id)
    if not endpoint or str(endpoint["company_id"]) != str(g.company["id"]):
        abort(404)
    require_branch_scope(endpoint.get("branch_id"))
    nickname = (request.get_json(silent=True) or {}).get("nickname", "")
    if not isinstance(nickname, str) or len(nickname.strip()) > 100 or any(ord(c) < 32 for c in nickname):
        return jsonify({"error": "Nickname must be at most 100 characters without control characters."}), 400
    nickname = nickname.strip()
    db.update_endpoint_nickname(endpoint_id, nickname)
    db.audit(g.company["id"], g.admin["id"], "endpoint_nickname_updated",
             {"endpoint_id": endpoint_id}, endpoint_id=endpoint_id)
    return jsonify({"ok": True, "display_name": nickname or endpoint["hostname"]})


@bp.route("/endpoints/<endpoint_id>/notes", methods=["POST"])
@login_required
@company_required
def update_notes(endpoint_id):
    endpoint = db.get_endpoint(endpoint_id)
    if not endpoint or str(endpoint["company_id"]) != str(g.company["id"]):
        abort(404)
    require_branch_scope(endpoint.get("branch_id"))
    notes = request.form.get("notes", "")
    tags_raw = request.form.get("tags", "")
    tags = [t.strip() for t in tags_raw.split(",") if t.strip()]
    db.update_endpoint_notes(endpoint_id, notes, tags)
    db.audit(g.company["id"], g.admin["id"], "endpoint_notes_updated",
             {"endpoint_id": endpoint_id}, endpoint_id=endpoint_id)
    return jsonify({"ok": True})


@bp.route("/endpoints/<endpoint_id>/asset", methods=["POST"])
@login_required
@company_required
@role_required("company_admin", "branch_admin", "technician")
def update_asset(endpoint_id):
    endpoint = db.get_endpoint(endpoint_id)
    if not endpoint or str(endpoint.get("company_id")) != str(g.company["id"]):
        abort(404)
    require_branch_scope(endpoint.get("branch_id"))
    state = request.form.get("asset_state", "in_service").strip()
    if state not in {"stock", "in_service", "repair", "retired", "disposed", "lost"}:
        return jsonify({"error": "Invalid asset state"}), 400
    values = {
        "asset_tag": request.form.get("asset_tag", "").strip()[:80] or None,
        "asset_state": state,
        "assigned_to": request.form.get("assigned_to", "").strip()[:160] or None,
        "purchase_date": request.form.get("purchase_date", "").strip() or None,
        "warranty_expiry": request.form.get("warranty_expiry", "").strip() or None,
        "asset_metadata": {"location": request.form.get("asset_location", "").strip()[:160]},
    }
    for key in ("purchase_date", "warranty_expiry"):
        if values[key] and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", values[key]):
            return jsonify({"error": f"Invalid {key}"}), 400
        if values[key]:
            try:
                date.fromisoformat(values[key])
            except ValueError:
                return jsonify({"error": f"Invalid {key}"}), 400
    try:
        db.update_endpoint_asset(endpoint_id, values)
    except Exception as exc:
        if "asset_tag" in str(exc).lower():
            return jsonify({"error": "Asset tag is already in use"}), 409
        raise
    db.audit(g.company["id"], g.admin["id"], "endpoint_asset_updated", {
        "endpoint_id": endpoint_id, "asset_tag": values["asset_tag"], "asset_state": state,
    }, branch_id=endpoint.get("branch_id"), endpoint_id=endpoint_id)
    return jsonify({"ok": True})


@bp.route("/endpoints/<endpoint_id>/incident-response", methods=["POST"])
@login_required
@company_required
@role_required("company_admin", "branch_admin", "technician")
def incident_response(endpoint_id):
    endpoint = db.get_endpoint(endpoint_id)
    if not endpoint or str(endpoint.get("company_id")) != str(g.company["id"]):
        abort(404)
    require_branch_scope(endpoint.get("branch_id"))
    body = request.get_json(silent=True) or {}
    action = str(body.get("action") or "").strip().lower()
    reason = str(body.get("reason") or "").strip()
    if not reason or len(reason) > 300:
        return jsonify({"error": "A reason of at most 300 characters is required"}), 400
    capabilities = _endpoint_capabilities(endpoint)
    jobs = []
    if action == "collect":
        for operation in ("COLLECT_SYSINFO", "COLLECT_SOFTWARE", "GET_EVENT_LOGS", "COMPLIANCE_SCAN"):
            if operation in capabilities:
                payload = {"log_name": "System", "max_events": 500} if operation == "GET_EVENT_LOGS" else {}
                jobs.append((operation, payload))
    elif action in {"contain", "release"}:
        # Alternate entry points must preserve dispatch_job's role boundary.
        if g.admin.get("role") == "technician":
            return jsonify({"error": "administrator_approval_required"}), 403
        if str(endpoint.get("platform") or "windows").lower() != "windows" or "PUSH_LOCAL_POLICY" not in capabilities:
            return jsonify({"error": "Windows policy capability is required"}), 409
        rules = [] if action == "release" else [
            {"name": "Contain inbound traffic", "direction": "in", "action": "block", "protocol": "any"},
            {"name": "Block outbound SMB", "direction": "out", "action": "block", "protocol": "tcp", "remote_ports": ["135", "139", "445"]},
            {"name": "Block outbound RDP", "direction": "out", "action": "block", "protocol": "tcp", "remote_ports": ["3389"]},
        ]
        jobs.append(("PUSH_LOCAL_POLICY", {"settings": {"windows_firewall_rules": json.dumps(rules, separators=(",", ":"))}, "policy_version": 1}))
    else:
        return jsonify({"error": "action must be collect, contain, or release"}), 400
    created = []
    from services.entitlements import check_job
    for operation, payload in jobs:
        decision = check_job(g.company["id"], operation)
        if not decision.allowed:
            continue
        job = db.create_job(g.company["id"], endpoint.get("branch_id"), endpoint_id, operation, payload, g.admin["id"])
        if job:
            created.append(str(job["id"]))
    if not created:
        return jsonify({"error": "No compatible incident-response jobs could be queued"}), 409
    db.log_endpoint_event(endpoint_id, f"incident_{action}_requested", {
        "reason": reason, "job_ids": created, "requested_by": str(g.admin["id"]),
    })
    db.audit(g.company["id"], g.admin["id"], f"incident_{action}_requested", {
        "endpoint_id": endpoint_id, "reason": reason, "job_ids": created,
    }, branch_id=endpoint.get("branch_id"), endpoint_id=endpoint_id)
    return jsonify({"ok": True, "jobs": created}), 202


@bp.route("/endpoints/<endpoint_id>/remove-from-warden", methods=["POST"])
@login_required
@company_required
@role_required("company_admin", "branch_admin")
def remove_from_warden(endpoint_id):
    """Retire an endpoint immediately without uninstalling its local agent.

    Inactive endpoints are excluded from capacity usage and their API keys no
    longer authenticate. History is retained, and a fresh enrolment token can
    explicitly reactivate the same installation later.
    """
    endpoint = db.get_endpoint(endpoint_id)
    if not endpoint or str(endpoint["company_id"]) != str(g.company["id"]):
        abort(404)
    require_branch_scope(endpoint.get("branch_id"))
    if not endpoint.get("is_active", True):
        return jsonify({"ok": True, "already_removed": True})

    cf_cert_id = endpoint.get("cloudflare_cert_id")
    cert_revocation_failed = False
    if cf_cert_id:
        try:
            from services.agent_ca import revoke_agent_cert
            revoke_agent_cert(cf_cert_id)
        except Exception as exc:
            cert_revocation_failed = True
            log.exception(
                "Could not revoke client certificate while removing endpoint %s",
                endpoint_id,
            )
            db.create_alert(
                company_id=g.company["id"],
                branch_id=endpoint.get("branch_id"),
                endpoint_id=endpoint_id,
                alert_type="client_cert_revocation_failed",
                severity="critical",
                title=f"Client certificate revocation failed: {endpoint.get('hostname')}",
                message=f"Certificate {cf_cert_id}: {str(exc)[:450]}",
            )

    db.retire_endpoint(
        endpoint_id,
        clear_cloudflare_cert_id=not cert_revocation_failed,
    )
    db.close_endpoint_work(endpoint_id, g.admin["id"])
    db.audit(g.company["id"], g.admin["id"], "endpoint_removed_from_warden", {
        "endpoint_id": endpoint_id,
        "hostname": endpoint.get("hostname"),
        "agent_uninstalled": False,
        "license_released": True,
        "certificate_revocation_failed": cert_revocation_failed,
    }, branch_id=endpoint.get("branch_id"), endpoint_id=endpoint_id)
    return jsonify({
        "ok": True,
        "message": "Endpoint removed from Warden and its license seat was released. The local agent remains installed but disconnected.",
    })


@bp.route("/endpoints/<endpoint_id>/dispatch-job", methods=["POST"])
@login_required
@company_required
@role_required("company_admin", "branch_admin", "technician")
def dispatch_job(endpoint_id):
    """
    Create a job and (for ops requiring escalation) create escalation request first.
    Body: {
        "type": "INSTALL_APP",
        "payload": {...},
        "windows_user": "john",
        "reason": "..."
    }
    """
    endpoint = db.get_endpoint(endpoint_id)
    if not endpoint or str(endpoint["company_id"]) != str(g.company["id"]):
        abort(404)
    require_branch_scope(endpoint.get("branch_id"))

    body = request.get_json(silent=True) or {}
    job_type = body.get("type", "").strip()
    payload = body.get("payload") or {}
    windows_user = body.get("windows_user", "").strip()
    reason = body.get("reason", "").strip()

    from routes.enroll import ALLOWED_OPERATIONS
    if job_type not in ALLOWED_OPERATIONS:
        return jsonify({"error": "unknown_operation"}), 400
    if (g.admin.get("role") == "technician"
            and job_type not in TECHNICIAN_DIRECT_OPS
            and job_type not in ESCALATION_REQUIRED_OPS):
        return jsonify({
            "error": "administrator_approval_required",
            "message": "An organization administrator must perform this endpoint action.",
        }), 403
    capabilities = _endpoint_capabilities(endpoint)
    if capabilities and job_type not in capabilities:
        return jsonify({
            "error": "operation_not_supported",
            "message": f"{job_type} is not supported by this {endpoint.get('platform') or 'endpoint'} agent",
        }), 409

    if job_type == "CONFIGURE_DEVICE_IDENTITY":
        if not isinstance(payload, dict):
            return jsonify({"error": "invalid_identity_payload"}), 400
        hostname = payload.get("hostname")
        restart = payload.get("restart", False)
        if (not isinstance(hostname, str)
                or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,13}[A-Za-z0-9])?", hostname)
                or hostname.isdigit() or not isinstance(restart, bool)):
            return jsonify({"error": "Use a hostname of 1–15 letters, numbers or hyphens (not all numbers)."}), 400
        version = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", str(endpoint.get("agent_version") or ""))
        if not version or tuple(map(int, version.groups())) < (2, 6, 43):
            return jsonify({"error": "Update to Windows Agent 2.6.43 or later before renaming; older agents always restart."}), 409
        payload = {"hostname": hostname.upper(), "restart": restart}

    if job_type in {"ENABLE_BITLOCKER", "ROTATE_BITLOCKER_RECOVERY"}:
        if str(endpoint.get("platform") or "windows").lower() != "windows":
            return jsonify({"error": "bitlocker_requires_windows"}), 409
        payload = {}

    from services.entitlements import check_job
    entitlement = check_job(g.company["id"], job_type)
    if not entitlement.allowed:
        return jsonify({"error": entitlement.code, "message": entitlement.message}), 403

    # These six ops only ever passed their target account through the
    # separate windows_user field (see endpoints/detail.html's Users tab
    # buttons: openJobModal(type, u.username)) — but every corresponding
    # agent-go handler (disableUser/deleteUser/enableUser/resetPassword/
    # grantElevation/revokeElevation) reads the username from the job
    # PAYLOAD (p["username"]), which stayed empty. Without this merge these
    # operations fail on the agent with "missing username" every time.
    USER_SCOPED_OPS = {
        "DELETE_USER", "RESET_PASSWORD", "DISABLE_USER", "ENABLE_USER",
        "GRANT_ELEVATION", "REVOKE_ELEVATION",
    }
    if job_type in USER_SCOPED_OPS:
        if not windows_user:
            return jsonify({"error": "windows_user_required"}), 400
        managed_usernames = {
            value.casefold()
            for value in db.get_managed_warden_usernames_for_endpoint(endpoint_id)
        }
        if windows_user.casefold() in managed_usernames:
            return jsonify({
                "error": "managed_identity_use_directory",
                "message": "This is a Warden-managed identity. Change its password, access, assignments, or status from Directory.",
            }), 409
        payload = {**payload, "username": windows_user}

    if job_type == "GRANT_ELEVATION":
        try:
            duration = int(payload.get("duration_minutes", 15))
        except (TypeError, ValueError):
            return jsonify({"error": "duration_minutes_must_be_an_integer"}), 400
        if not 1 <= duration <= 240:
            return jsonify({"error": "duration_minutes_must_be_between_1_and_240"}), 400
        if not reason:
            return jsonify({"error": "reason_required_for_elevation"}), 400
        payload = {**payload, "duration_minutes": duration}

    if job_type == "CHECK_POLICY_DRIFT" and "keys" in payload:
        # Scoped check (e.g. "did this one saved template drift") instead of
        # the default full ~1300-setting scan — still validate every key is
        # real before it ever reaches the agent.
        from policy_settings import POLICY_SETTINGS
        keys = payload.get("keys")
        if not isinstance(keys, list) or not keys:
            return jsonify({"error": "keys must be a non-empty list"}), 400
        unknown = [k for k in keys if k not in POLICY_SETTINGS]
        if unknown:
            return jsonify({"error": f"unknown policy setting(s): {unknown}"}), 400

    if job_type == "CAPTURE_PACKETS":
        if (endpoint.get("platform") or "windows").lower() != "windows":
            return jsonify({"error": "packet_capture_requires_windows"}), 409
        if not reason:
            return jsonify({"error": "reason_required_for_packet_capture"}), 400
        try:
            duration = int(payload.get("duration_seconds", 30))
            max_size = int(payload.get("max_size_mb", 4))
            port = int(payload.get("port", 0) or 0)
        except (TypeError, ValueError):
            return jsonify({"error": "invalid_packet_capture_limits"}), 400
        protocol = str(payload.get("protocol") or "any").lower()
        remote_ip = str(payload.get("remote_ip") or "").strip()
        if not 5 <= duration <= 120 or not 1 <= max_size <= 8:
            return jsonify({"error": "capture_must_be_5_to_120_seconds_and_1_to_8_mb"}), 400
        if protocol not in {"any", "tcp", "udp", "icmp"} or not 0 <= port <= 65535:
            return jsonify({"error": "invalid_packet_capture_filter"}), 400
        if remote_ip:
            try:
                ipaddress.ip_network(remote_ip, strict=False)
            except ValueError:
                return jsonify({"error": "invalid_remote_ip_or_cidr"}), 400
        payload = {
            "duration_seconds": duration, "max_size_mb": max_size,
            "protocol": protocol, "remote_ip": remote_ip, "port": port,
        }

    if job_type == "PUSH_LOCAL_POLICY":
        from policy_templates import POLICY_TEMPLATES
        from policy_settings import POLICY_SETTINGS, validate_settings_dict

        if "template_id" in payload:
            # A company-authored template (server/db policy_templates table)
            # — resolve to its underlying settings dict server-side now, at
            # dispatch time, rather than trusting the client's copy or
            # storing an opaque reference an admin could edit/delete out
            # from under an already-pending escalation.
            saved = db.get_policy_template(payload["template_id"])
            if not saved or str(saved["company_id"]) != str(g.company["id"]):
                return jsonify({"error": "unknown_policy_template"}), 400
            try:
                validate_settings_dict(saved["settings"])
            except ValueError as exc:
                return jsonify({"error": f"invalid_saved_template: {exc}"}), 400
            payload = {"settings": saved["settings"]}
        elif "settings" in payload:
            # One-off, per-endpoint setting change(s) not saved as a template.
            try:
                validate_settings_dict(payload["settings"])
            except ValueError as exc:
                return jsonify({"error": str(exc)}), 400
        else:
            # Legacy fixed, pre-built LGPO template (server/policy_templates.py).
            template = payload.get("template", "")
            if template not in POLICY_TEMPLATES:
                return jsonify({"error": "unknown_policy_template"}), 400

        settings = payload.get("settings") if isinstance(payload, dict) else None
        if isinstance(settings, dict) and not (endpoint.get("device_identity") or {}).get("domain_joined"):
            ad_only = [
                key for key in settings
                if (POLICY_SETTINGS.get(key) or {}).get("requires_ad")
            ]
            if ad_only:
                return jsonify({
                    "error": "active_directory_required",
                    "message": "This LAPS setting requires an Active Directory-joined endpoint and AD password backup. It has no effect in Warden-only mode.",
                }), 409

    if job_type in {"UPDATE_AGENT", "REINSTALL_AGENT"}:
        # Never trust a client-supplied sha256/download_url for something
        # that gets executed as a privileged Windows service — always
        # derive it server-side from the most recent completed build.
        try:
            payload = update_payload(endpoint)
        except AgentBuildUnavailable:
            return jsonify({"error": "no_agent_build_available"}), 409

    if job_type == "ROTATE_TLS_PINS":
        fingerprints = payload.get("fingerprints")
        if not isinstance(fingerprints, list) or not 1 <= len(fingerprints) <= 3:
            return jsonify({"error": "fingerprints must contain 1 to 3 SHA-256 values"}), 400
        normalized = []
        for value in fingerprints:
            clean = str(value).replace(":", "").strip().lower()
            if not re.fullmatch(r"[0-9a-f]{64}", clean):
                return jsonify({"error": "invalid TLS fingerprint"}), 400
            if clean not in normalized:
                normalized.append(clean)
        payload = {"fingerprints": normalized}

    # All privileged ops require escalation
    identity_restart = job_type == "CONFIGURE_DEVICE_IDENTITY" and payload.get("restart") is True
    if job_type in ESCALATION_REQUIRED_OPS or identity_restart:
        # An organization can explicitly opt out of the two-different-admins
        # requirement (see companies.require_dual_approval / settings.py's
        # set_dual_approval()) — e.g. a solo-admin organization that can never
        # produce a second distinct approver. Still gated by escalation
        # approval either way; this only changes single vs dual.
        requires_dual = (job_type in DUAL_APPROVAL_OPS or identity_restart) and g.company.get("require_dual_approval", True)
        # Check for auto-approve policy
        policy = db.find_matching_policy(
            g.company["id"], endpoint_id, windows_user, job_type, payload
        )
        esc_req = db.create_escalation_request(
            company_id=g.company["id"],
            branch_id=endpoint["branch_id"],
            endpoint_id=endpoint_id,
            windows_user=windows_user,
            operation=job_type,
            payload=payload,
            reason=reason,
            requires_dual=requires_dual,
            requested_by=g.admin["id"],
        )
        if not esc_req:
            return jsonify({"error": "failed_to_create_escalation"}), 500

        # Auto-approval is an administrative delegation mechanism.  A
        # technician may request an escalated action, but must never turn a
        # matching policy into their own approval.
        if policy and g.admin.get("role") != "technician":
            # Auto-approve — matched a saved policy, so this counts as the
            # FIRST approval step. For a dual-approval op, approve_escalation
            # (per its own requires_dual_approval check) only advances the
            # escalation to "pending_secondary", not "approved" — a second,
            # genuinely separate admin still has to approve via
            # routes/escalations.py before a runnable job gets created. Only
            # create the job here if the returned status is actually
            # "approved" — creating it unconditionally would let a single
            # saved-policy match dispatch a dual-approval-gated operation
            # (e.g. UNINSTALL_AGENT, PUSH_LOCAL_POLICY, SHUTDOWN) after only
            # one approval step, defeating the entire point of requiring two.
            policy_approver = policy.get("approved_by")
            token, updated_esc = (
                db.approve_escalation(esc_req["id"], policy_approver, "pending")
                if policy_approver else (None, None)
            )
            if not updated_esc:
                # A saved policy owned by the requester is not an independent
                # approval. Leave the request pending for another admin.
                return jsonify({
                    "ok": True,
                    "job_id": None,
                    "escalation_id": str(esc_req["id"]),
                    "status": "pending_approval",
                })
            status = updated_esc["status"]
            if status == "approved":
                job = db.create_job(
                    company_id=g.company["id"],
                    branch_id=endpoint["branch_id"],
                    endpoint_id=endpoint_id,
                    job_type=job_type,
                    payload=payload,
                    created_by=g.admin["id"],
                    requires_dual_approval=requires_dual,
                    escalation_id=esc_req["id"],
                )
                if not job:
                    return jsonify({"error": "failed_to_create_job"}), 500
                job_id = str(job["id"])
            else:
                job_id = None
        else:
            # Not auto-approved — do NOT create a job yet. A runnable job is only
            # created once the escalation is actually approved (single or dual,
            # see routes/escalations.py:approve). Creating it here would let the
            # agent pick it up on the next heartbeat before anyone approved it,
            # bypassing approval entirely.
            status = "pending_approval"
            job_id = None

        db.audit(g.company["id"], g.admin["id"], "job_dispatched", {
            "job_type": job_type, "endpoint_id": endpoint_id,
            "escalation_id": esc_req["id"],
        }, endpoint_id=endpoint_id, escalation_id=esc_req["id"])

        return jsonify({
            "ok": True,
            "job_id": job_id,
            "escalation_id": str(esc_req["id"]),
            "status": status,
        })

    # Non-privileged ops (e.g. COLLECT_SYSINFO) — dispatch directly
    job = db.create_job(
        company_id=g.company["id"],
        branch_id=endpoint["branch_id"],
        endpoint_id=endpoint_id,
        job_type=job_type,
        payload=payload,
        created_by=g.admin["id"],
    )
    if not job:
        return jsonify({"error": "failed_to_create_job"}), 500
    db.audit(g.company["id"], g.admin["id"], "job_dispatched",
             {"job_type": job_type, "endpoint_id": endpoint_id}, endpoint_id=endpoint_id)
    return jsonify({"ok": True, "job_id": str(job["id"])})


_EXPERIENCE_IMAGE_MAX_BYTES = 10 * 1024 * 1024
_EXPERIENCE_IMAGE_TYPES = {b"\x89PNG\r\n\x1a\n": ".png", b"\xff\xd8\xff": ".jpg"}
_EXPERIENCE_RETENTION = timedelta(days=3)


def _store_experience_image(upload, company_id):
    if not upload or not upload.filename:
        return None
    data = upload.read(_EXPERIENCE_IMAGE_MAX_BYTES + 1)
    if not data or len(data) > _EXPERIENCE_IMAGE_MAX_BYTES:
        raise ValueError("Images must be between 1 byte and 10 MB")
    extension = next((ext for signature, ext in _EXPERIENCE_IMAGE_TYPES.items()
                      if data.startswith(signature)), None)
    if not extension:
        raise ValueError("Only genuine PNG and JPEG images are accepted")
    asset_id = hashlib.sha256(data).hexdigest()
    tenant_dir = config.UPLOAD_DIR / "branding" / str(company_id)
    tenant_dir.mkdir(parents=True, exist_ok=True)
    path = tenant_dir / f"{asset_id}{extension}"
    if not path.exists():
        path.write_bytes(data)
    else:
        # A repeated deployment renews the same deduplicated asset's 72-hour
        # availability without creating another copy.
        path.touch()
    return asset_id


def _experience_payload(form, files, company_id):
    wallpaper_id = _store_experience_image(files.get("wallpaper"), company_id)
    lock_screen_id = _store_experience_image(files.get("lock_screen"), company_id)
    title = str(form.get("announcement_title") or "").strip()[:120]
    message = str(form.get("announcement_message") or "").strip()[:2000]
    severity = str(form.get("announcement_severity") or "info").strip()
    fit = str(form.get("image_fit") or "fill").strip()
    if severity not in {"info", "warning", "critical"} or fit not in {"fill", "fit", "stretch", "center", "tile", "span"}:
        raise ValueError("Invalid image placement or announcement severity")
    if bool(title) != bool(message):
        raise ValueError("Announcement title and message are both required")
    if not wallpaper_id and not lock_screen_id and not message:
        raise ValueError("Choose a wallpaper, lock screen image, or announcement")
    return {
        "wallpaper_asset_id": wallpaper_id,
        "lock_screen_asset_id": lock_screen_id,
        "image_fit": fit,
        "announcement_title": title or None,
        "announcement_message": message or None,
        "announcement_severity": severity,
        "announcement_require_ack": form.get("announcement_require_ack") == "1",
        "announcement_timeout_seconds": 300,
        "deployment_retention_hours": 72,
    }


def _experience_expires_at():
    return (datetime.now(timezone.utc) + _EXPERIENCE_RETENTION).isoformat()


@bp.route("/endpoints/<endpoint_id>/experience", methods=["POST"])
@login_required
@company_required
@role_required("company_admin", "branch_admin")
def apply_endpoint_experience(endpoint_id):
    endpoint = db.get_endpoint(endpoint_id)
    if not endpoint or str(endpoint["company_id"]) != str(g.company["id"]):
        abort(404)
    require_branch_scope(endpoint.get("branch_id"))
    if (endpoint.get("platform") or "windows").lower() != "windows":
        return jsonify({"error": "device_experience_requires_windows"}), 409
    if "APPLY_DEVICE_EXPERIENCE" not in _endpoint_capabilities(endpoint):
        return jsonify({"error": "update_agent_to_manage_device_experience"}), 409
    try:
        payload = _experience_payload(request.form, request.files, g.company["id"])
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except OSError:
        log.exception("Could not store endpoint experience image")
        return jsonify({"error": "Image storage is temporarily unavailable. Please retry."}), 503
    job = db.create_job(
        g.company["id"], endpoint.get("branch_id"), endpoint_id,
        "APPLY_DEVICE_EXPERIENCE", payload, g.admin["id"], expires_at=_experience_expires_at(),
    )
    if not job:
        return jsonify({"error": "failed_to_create_job"}), 500
    db.audit(g.company["id"], g.admin["id"], "endpoint_experience_queued", {
        "endpoint_id": endpoint_id, "wallpaper": bool(payload["wallpaper_asset_id"]),
        "lock_screen": bool(payload["lock_screen_asset_id"]), "announcement": bool(payload["announcement_message"]),
        "announcement_require_ack": payload["announcement_require_ack"],
    }, endpoint_id=endpoint_id)
    return jsonify({"ok": True, "job_id": str(job["id"]),
                    "message": "Device experience queued for up to 3 days. Follow its result in Jobs."})


@bp.route("/endpoints/experience/bulk", methods=["POST"])
@login_required
@company_required
@role_required("company_admin", "branch_admin")
def apply_bulk_endpoint_experience():
    branch_id = str(request.form.get("branch_id") or "").strip() or None
    if g.admin.get("role") == "branch_admin":
        branch_id = g.admin.get("branch_id")
        if not branch_id:
            abort(403)
    endpoint_ids = request.form.getlist("endpoint_ids")
    if request.form.get("target_mode") == "selected" and not endpoint_ids:
        return jsonify({"error": "Select at least one endpoint"}), 400
    if len(endpoint_ids) > 1000 or any(not re.fullmatch(r"[0-9a-fA-F-]{36}", value) for value in endpoint_ids):
        return jsonify({"error": "Invalid endpoint selection"}), 400
    targets = db.get_endpoints_bulk(g.company["id"], branch_id=branch_id, endpoint_ids=endpoint_ids or None)
    targets = [ep for ep in targets if str(ep.get("company_id")) == str(g.company["id"])
               and (not branch_id or str(ep.get("branch_id")) == str(branch_id))]
    if endpoint_ids and set(endpoint_ids) != {str(ep["id"]) for ep in targets}:
        return jsonify({"error": "Audience changed; review again"}), 409
    try:
        payload = _experience_payload(request.form, request.files, g.company["id"])
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except OSError:
        log.exception("Could not store bulk endpoint experience image")
        return jsonify({"error": "Image storage is temporarily unavailable. Please retry."}), 503

    endpoints = targets
    expires_at = _experience_expires_at()
    dispatched = 0
    skipped = 0
    for endpoint in endpoints:
        if ((endpoint.get("platform") or "windows").lower() != "windows"
                or "APPLY_DEVICE_EXPERIENCE" not in _endpoint_capabilities(endpoint)):
            skipped += 1
            continue
        job = db.create_job(
            g.company["id"], endpoint.get("branch_id"), endpoint["id"],
            "APPLY_DEVICE_EXPERIENCE", payload, g.admin["id"], expires_at=expires_at,
        )
        if job:
            dispatched += 1
        else:
            skipped += 1
    db.audit(g.company["id"], g.admin["id"], "bulk_endpoint_experience_queued", {
        "branch_id": branch_id, "dispatched": dispatched, "skipped": skipped,
        "retention_hours": 72, "wallpaper": bool(payload["wallpaper_asset_id"]),
        "lock_screen": bool(payload["lock_screen_asset_id"]),
        "announcement": bool(payload["announcement_message"]),
    })
    return jsonify({"ok": True, "dispatched": dispatched, "skipped": skipped,
                    "expires_in_hours": 72})


@bp.route("/endpoints/bulk-dispatch", methods=["POST"])
@login_required
@company_required
@role_required("company_admin", "branch_admin")
def bulk_dispatch():
    """
    Dispatch a job to multiple endpoints at once.
    Body: {
        "type": "COLLECT_SOFTWARE",
        "payload": {},
        "branch_id": "uuid (optional)",
        "endpoint_ids": ["uuid", ...] (optional, overrides branch_id)
    }
    """
    body = request.get_json(silent=True) or {}
    job_type = body.get("type", "").strip()
    payload = body.get("payload") or {}
    branch_id = body.get("branch_id")
    endpoint_ids = body.get("endpoint_ids") or []

    from routes.enroll import ALLOWED_OPERATIONS
    if job_type not in ALLOWED_OPERATIONS:
        return jsonify({"error": "unknown_operation"}), 400

    # Only allow non-privileged bulk ops (no user mgmt, no destructive ops)
    BULK_ALLOWED = {
        "COLLECT_SYSINFO", "COLLECT_SOFTWARE", "COMPLIANCE_SCAN",
        "SET_PERIPHERAL_POLICY", "GET_EVENT_LOGS", "WINDOWS_UPDATE",
        "CHECK_POLICY_DRIFT", "COLLECT_USERS",
        "COLLECT_NETWORK_FLOWS",
    }
    if job_type not in BULK_ALLOWED and not (body.get("preview") is True and job_type == "APPLY_DEVICE_EXPERIENCE"):
        return jsonify({"error": "operation_not_allowed_in_bulk"}), 400

    from services.entitlements import check_job
    decision = check_job(g.company["id"], job_type)
    if not decision.allowed:
        return jsonify({"error": decision.code, "message": decision.message}), 403

    if g.admin.get("role") == "branch_admin":
        admin_branch_id = g.admin.get("branch_id")
        if not admin_branch_id:
            abort(403)
        # A branch_admin can only ever target their own branch — override
        # whatever branch_id/endpoint_ids the request asked for rather than
        # just validating it, so this can't be widened by omitting branch_id
        # (which would otherwise fall through to "every endpoint in the
        # company").
        branch_id = str(admin_branch_id)
        # Preserve an explicit device selection; enforce branch below as well.

    if not isinstance(endpoint_ids, list) or len(endpoint_ids) > 1000:
        return jsonify({"error": "Select at most 1000 endpoints"}), 400
    if body.get("target_mode") == "selected" and not endpoint_ids:
        return jsonify({"error": "Select at least one endpoint"}), 400
    if any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F-]{36}", value) for value in endpoint_ids):
        return jsonify({"error": "Invalid endpoint selection"}), 400
    endpoints = db.get_endpoints_bulk(g.company["id"], branch_id=branch_id, endpoint_ids=endpoint_ids or None)
    endpoints = [ep for ep in endpoints if str(ep.get("company_id")) == str(g.company["id"])
                 and (not branch_id or str(ep.get("branch_id")) == str(branch_id))]
    if endpoint_ids and set(endpoint_ids) != {str(ep["id"]) for ep in endpoints}:
        return jsonify({"error": "Selection changed or includes unavailable endpoints; review again"}), 409
    if body.get("preview") is True:
        def supported(ep):
            return (job_type in _endpoint_capabilities(ep)
                    and (job_type != "WINDOWS_UPDATE" or (ep.get("platform") or "windows") == "windows"))
        return jsonify({"ok": True, "targets": [
            {"id": ep["id"], "name": ep.get("display_name") or ep.get("hostname") or "Endpoint",
             "online": report_online(ep), "supported": supported(ep)}
            for ep in endpoints]})
    dispatched = 0
    skipped = 0
    for ep in endpoints:
        if str(ep.get("company_id", "")) != str(g.company["id"]):
            skipped += 1
            continue
        if g.admin.get("role") == "branch_admin" and str(ep.get("branch_id", "")) != str(g.admin.get("branch_id")):
            skipped += 1
            continue
        if job_type == "WINDOWS_UPDATE" and str(ep.get("platform") or "windows").lower() != "windows":
            skipped += 1
            continue
        capabilities = _endpoint_capabilities(ep)
        if job_type not in capabilities:
            skipped += 1
            continue
        job = db.create_job(
            company_id=g.company["id"],
            branch_id=ep.get("branch_id"),
            endpoint_id=ep["id"],
            job_type=job_type,
            payload=payload,
            created_by=g.admin["id"],
        )
        if job:
            dispatched += 1
        else:
            skipped += 1

    db.audit(g.company["id"], g.admin["id"], "bulk_job_dispatched", {
        "job_type": job_type,
        "dispatched": dispatched,
        "branch_id": branch_id,
    })
    return jsonify({"ok": True, "dispatched": dispatched, "skipped": skipped})


@bp.route("/endpoints/<endpoint_id>/packet-captures/<job_id>/download")
@login_required
@company_required
def download_packet_capture(endpoint_id, job_id):
    endpoint = db.get_endpoint(endpoint_id)
    job = db.get_job(job_id)
    if (not endpoint or str(endpoint.get("company_id")) != str(g.company["id"])
            or not job or str(job.get("endpoint_id")) != endpoint_id
            or str(job.get("company_id")) != str(g.company["id"])
            or job.get("type") != "CAPTURE_PACKETS"):
        abort(404)
    require_branch_scope(endpoint.get("branch_id"))
    if job.get("status") != "completed":
        return jsonify({"error": "capture_not_ready"}), 409
    try:
        result = json.loads(job.get("log_output") or "{}")
        content = base64.b64decode(result.get("content_b64") or "", validate=True)
    except (ValueError, TypeError, json.JSONDecodeError, binascii.Error):
        return jsonify({"error": "invalid_capture_result"}), 500
    if len(content) < 4 or content[:4] != b"\x0a\x0d\x0d\x0a":
        return jsonify({"error": "invalid_capture_result"}), 500
    filename = pathlib.PureWindowsPath(
        result.get("download_name") or "warden-capture.pcapng"
    ).name.replace('"', '') or "warden-capture.pcapng"
    db.audit(g.company["id"], g.admin["id"], "packet_capture_downloaded", {
        "endpoint_id": endpoint_id, "job_id": job_id, "size_bytes": len(content),
    }, branch_id=endpoint.get("branch_id"), endpoint_id=endpoint_id)
    return Response(content, mimetype="application/vnd.tcpdump.pcap", headers={
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Cache-Control": "private, no-store",
        "X-Content-Type-Options": "nosniff",
    })


@bp.route("/endpoints/<endpoint_id>/cancel-job/<job_id>", methods=["POST"])
@login_required
@company_required
def cancel_job(endpoint_id, job_id):
    job = db.get_job(job_id)
    if not job or str(job["company_id"]) != str(g.company["id"]):
        abort(404)
    require_branch_scope(job.get("branch_id"))
    if not db.cancel_job(job_id, g.admin["id"]):
        return jsonify({"error": "Job started before cancellation could be applied"}), 409
    db.audit(g.company["id"], g.admin["id"], "job_cancelled",
             {"job_id": job_id}, endpoint_id=endpoint_id)
    return jsonify({"ok": True})


@bp.route("/endpoints/generate-installer", methods=["POST"])
@login_required
@company_required
@role_required("company_admin", "branch_admin")
def generate_installer():
    """
    Generate a per-branch enrollment installer.
    Creates an enrollment token + build request.
    """
    branch_id = request.form.get("branch_id", "").strip()
    target_platform = request.form.get("target_platform", "windows-amd64").strip().lower()
    if target_platform not in {
        "windows-amd64", "linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64",
    }:
        return jsonify({"error": "invalid target platform"}), 400
    if not branch_id:
        return jsonify({"error": "branch_id required"}), 400

    branch = db.get_branch(branch_id)
    if not branch or str(branch["company_id"]) != str(g.company["id"]):
        abort(404)
    require_branch_scope(branch_id)

    from services.cert_fingerprint import fetch_live_cert_fingerprint
    try:
        fingerprint = fetch_live_cert_fingerprint(config.SERVER_URL)
    except Exception as e:
        return jsonify({
            "error": "server_tls_fingerprint_unavailable",
            "message": f"Could not fetch the live server certificate: {e}",
        }), 503

    company = g.company
    branch_slug = re.sub(r"[^a-z0-9]+", "-", (branch.get("name") or "").lower()).strip("-")
    token, token_rec = db.create_enrollment_token(
        company_id=company["id"],
        branch_id=branch_id,
        created_by=g.admin["id"],
    )
    if not token_rec:
        return jsonify({"error": "failed_to_create_token"}), 500

    from services.signing import get_server_pubkey_b64
    config_json = {
        "server_url": config.SERVER_URL,
        "server_ed25519_pubkey": get_server_pubkey_b64(),
        "heartbeat_encryption_required": config.HEARTBEAT_MESSAGE_ENCRYPTION,
        "agent_core_modules": config.AGENT_CORE_MODULES_ENABLED,
        "agent_integrity_verification": config.ENCRYPT_HEARTBEAT_TELEMETRY,
        "cert_fingerprint": fingerprint,
        "tls_trust_mode": "webpki",
        "company_id": str(company["id"]),
        "company_slug": company["slug"],
        "branch_id": str(branch_id),
        "branch_slug": branch_slug or "unknown",
        "enrollment_token": token,
    }

    try:
        build_req = db.create_build_request(
            company_id=company["id"],
            branch_id=branch_id,
            enrollment_token_id=token_rec["id"],
            config_json=config_json,
            created_by=g.admin["id"],
            target_platform=target_platform,
        )
    except Exception:
        db.deactivate_enrollment_token(token_rec["id"])
        raise

    if not build_req:
        db.deactivate_enrollment_token(token_rec["id"])
        return jsonify({"error": "failed_to_create_build_request"}), 500

    db.audit(g.company["id"], g.admin["id"], "installer_generated", {
        "branch_id": branch_id,
        "branch_name": branch.get("name"),
        "build_request_id": str(build_req["id"]) if build_req else None,
        "target_platform": target_platform,
    })

    return jsonify({
        "ok": True,
        "build_request_id": str(build_req["id"]) if build_req else None,
        "message": "Installer build queued. Check Settings → Enrollment Tokens for status and to download it.",
    })


# ── Remote access (screen-share relay over outbound WSS, see agent/remote.py) ──

_REMOTE_PRIVILEGED_ROLES = {"company_admin", "branch_admin"}


def _remote_session_capabilities(access_mode, role, endpoint=None, requested=None):
    control = access_mode in {"full_control", "unattended"}
    privileged = role in _REMOTE_PRIVILEGED_ROLES
    details = (endpoint or {}).get("capability_details") or {}
    # Older agents did not report granular remote capabilities, so preserve
    # their existing behaviour. New cross-platform agents explicitly report
    # unavailable input/clipboard support and the server removes those powers
    # from the session instead of presenting controls that silently do nothing.
    remote_input = details.get("remote_input") is not False
    remote_clipboard = details.get("remote_clipboard") is not False
    remote_process_manager = details.get("remote_process_manager") is not False
    granted = {
        "view": True,
        "control": control and remote_input,
        "clipboard": control and remote_clipboard,
        "file_transfer": control and privileged,
        "process_manager": control and privileged and remote_process_manager,
        "reboot": control and privileged,
    }
    if isinstance(requested, dict):
        for name in ("clipboard", "file_transfer", "process_manager", "reboot"):
            granted[name] = granted[name] and requested.get(name) is True
    return granted


def _remote_capability_labels(capabilities):
    labels = ["View screen"]
    if capabilities.get("control"):
        labels.append("Keyboard and mouse")
    if capabilities.get("clipboard"):
        labels.append("Clipboard")
    if capabilities.get("file_transfer"):
        labels.append("File transfer")
    if capabilities.get("process_manager"):
        labels.append("Process manager")
    if capabilities.get("reboot"):
        labels.append("Restart endpoint")
    return labels


def _require_remote_session_capability(session, capability="view"):
    """Enforce session ownership and least-privilege remote capabilities."""
    role = str(g.admin.get("role") or "")
    if role not in _REMOTE_PRIVILEGED_ROLES:
        if str(session.get("admin_id") or "") != str(g.admin.get("id") or ""):
            abort(403)
    capabilities = session.get("capabilities") or {}
    if not capabilities.get(capability, capability == "view"):
        abort(403)
    return capabilities

@bp.route("/endpoints/<endpoint_id>/start-session", methods=["POST"])
@login_required
@company_required
@role_required("company_admin", "branch_admin", "technician")
def start_remote_session(endpoint_id):
    """
    Dispatch SETUP_REMOTE_ACCESS to the agent, create a remote_session record,
    generate a websockify token, and return the noVNC URL.

    The agent opens an authenticated outbound WSS relay. We create the session
    optimistically here and patch it when the job completes.
    """
    endpoint = db.get_endpoint(endpoint_id)
    if not endpoint or str(endpoint["company_id"]) != str(g.company["id"]):
        abort(404)
    require_branch_scope(endpoint.get("branch_id"))
    if endpoint.get("status") != "online":
        return jsonify({"error": "endpoint_offline"}), 409
    if "SETUP_REMOTE_ACCESS" not in _endpoint_capabilities(endpoint):
        reason = (endpoint.get("capability_details") or {}).get("remote_control")
        return jsonify({
            "error": "remote_access_unavailable",
            "message": reason or "Remote access is not available on this endpoint",
        }), 409
    from services.entitlements import check_feature
    entitlement = check_feature(g.company["id"], "remote_control")
    if not entitlement.allowed:
        return jsonify({"error": entitlement.code, "message": entitlement.message}), 403

    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict):
        return jsonify({"error": "invalid_payload"}), 400
    access_mode = str(body.get("access_mode") or "full_control").strip().lower()
    if access_mode not in {"view_only", "full_control", "unattended"}:
        return jsonify({"error": "invalid_access_mode"}), 400
    role = str(g.admin.get("role") or "")
    if access_mode == "unattended" and role not in _REMOTE_PRIVILEGED_ROLES:
        return jsonify({"error": "unattended_access_requires_admin"}), 403
    details = endpoint.get("capability_details") or {}
    if access_mode in {"full_control", "unattended"} and details.get("remote_input") is False:
        return jsonify({
            "error": "remote_input_unavailable",
            "message": details.get("remote_control") or "This endpoint supports view-only remote sessions.",
        }), 409
    if access_mode != "unattended" and details.get("remote_consent") is False:
        return jsonify({
            "error": "remote_consent_unavailable",
            "message": "This endpoint cannot display an attended-access consent prompt. Use view-only after updating its agent, or use unattended access if your policy allows it.",
        }), 409
    reason = str(body.get("reason") or "Interactive support").strip()[:500]
    if not reason:
        return jsonify({"error": "reason_required"}), 400
    consent_title = str(body.get("consent_title") or "Warden remote support").strip()[:120]
    consent_message = str(body.get("consent_message") or "Your support technician can see this screen and, if requested, control this computer.").strip()[:500]
    if not consent_title or not consent_message:
        return jsonify({"error": "consent_warning_required"}), 400
    requested_capabilities = body.get("requested_capabilities")
    if requested_capabilities is not None and not isinstance(requested_capabilities, dict):
        return jsonify({"error": "invalid_requested_capabilities"}), 400
    capabilities = _remote_session_capabilities(
        access_mode, role, endpoint, requested_capabilities,
    )
    capability_labels = _remote_capability_labels(capabilities)
    consent_required = access_mode != "unattended"

    server_base = config.SERVER_URL.rstrip("/")
    if not server_base.startswith("https://"):
        return jsonify({"error": "remote_relay_requires_https_server_url"}), 503

    # The agent can only ever run one relay session at a time (agent-go's
    # relayLive is a singleton) — dispatching a second SETUP_REMOTE_ACCESS
    # while a first is still active/connecting always fails immediately
    # with "already running" on the agent side, leaving whoever triggered
    # the SECOND attempt (a double-click, a second tab, a page reload)
    # stuck with no useful signal. Reuse a still-fresh existing session
    # instead of creating a conflicting new one.
    existing = db.get_active_remote_session(endpoint_id)
    if existing and existing.get("vnc_token") and existing.get("novnc_path"):
        if str(existing.get("admin_id") or "") != str(g.admin.get("id") or ""):
            return jsonify({"error": "remote_session_already_active"}), 409
        if existing.get("access_mode") != access_mode:
            return jsonify({
                "error": "remote_session_access_mode_conflict",
                "message": "An active session already uses a different access level. End it before starting another session.",
            }), 409
        return jsonify({
            "ok":         True,
            "session_id": str(existing["id"]),
            "job_id":     None,
            "viewer_url": existing["novnc_path"],
            "reused":     True,
        })

    # Create remote session record
    from services.ws_proxy import relay_capacity_reached
    if relay_capacity_reached(g.company["id"]):
        response = jsonify({
            "error": "remote_relay_busy",
            "message": "The server is busy protecting active sessions. Please retry shortly.",
        })
        response.status_code = 503
        response.headers["Retry-After"] = "15"
        return response
    session = db.create_remote_session(
        endpoint_id=endpoint_id,
        company_id=g.company["id"],
        admin_id=g.admin["id"],
    )
    if not session:
        return jsonify({"error": "failed_to_create_session"}), 500
    if not session.pop("_created", True):
        if session.get("vnc_token") and session.get("novnc_path"):
            if str(session.get("admin_id") or "") != str(g.admin.get("id") or ""):
                return jsonify({"error": "remote_session_already_active"}), 409
            if session.get("access_mode") != access_mode:
                return jsonify({
                    "error": "remote_session_access_mode_conflict",
                    "message": "An active session already uses a different access level. End it before starting another session.",
                }), 409
            return jsonify({
                "ok": True,
                "session_id": str(session["id"]),
                "job_id": None,
                "viewer_url": session["novnc_path"],
                "reused": True,
            })
        return jsonify({"error": "remote_session_initializing"}), 409

    session_id = str(session["id"])

    db.update_remote_session_controls(
        session_id, access_mode, capabilities, reason, consent_required,
    )

    # vnc_token authenticates the browser → relay WebSocket connection
    vnc_token = secrets.token_urlsafe(32)

    # relay_url is sent to the agent — it dials out to the relay with its API key
    relay_url = f"{server_base.replace('https://', 'wss://', 1)}/agent-relay/{session_id}"

    novnc_path = f"/endpoints/{endpoint_id}/remote-view/{session_id}"
    try:
        db.update_remote_session_token(session["id"], vnc_token, novnc_path)
    except Exception:
        _fail_remote_session(session_id, "failed to provision remote-session token")
        raise

    # Dispatch SETUP_REMOTE_ACCESS job — agent dials the relay, no VPN needed
    try:
        job = db.create_job(
            company_id=g.company["id"],
            branch_id=endpoint["branch_id"],
            endpoint_id=endpoint_id,
            job_type="SETUP_REMOTE_ACCESS",
            payload={
                "session_id": session_id,
                "relay_url":  relay_url,
                "access_mode": access_mode,
                "consent_required": consent_required,
                "helper_name": g.admin.get("full_name") or g.admin.get("email") or "Warden technician",
                "reason": reason,
                "consent_title": consent_title,
                "consent_message": consent_message,
                "requested_access": capability_labels,
            },
            created_by=g.admin["id"],
        )
    except Exception:
        _fail_remote_session(session_id, "failed to queue remote-access job")
        raise
    if not job:
        _fail_remote_session(session_id, "failed to queue remote-access job")
        return jsonify({"error": "failed_to_create_remote_job"}), 500

    db.audit(g.company["id"], g.admin["id"], "remote_session_started", {
        "endpoint_id": endpoint_id,
        "session_id": str(session["id"]),
        "access_mode": access_mode,
        "capabilities": capabilities,
        "consent_required": consent_required,
        "reason": reason,
        "consent_title": consent_title,
        "requested_access": capability_labels,
    }, endpoint_id=endpoint_id)

    return jsonify({
        "ok":         True,
        "session_id": session_id,
        "job_id":     str(job["id"]) if job else None,
        "viewer_url": novnc_path,
    })


@bp.route("/endpoints/<endpoint_id>/remote-view/<session_id>")
@login_required
@company_required
def remote_view(endpoint_id, session_id):
    """Render the noVNC viewer page for an active remote session."""
    endpoint = db.get_endpoint(endpoint_id)
    if not endpoint or str(endpoint["company_id"]) != str(g.company["id"]):
        abort(404)
    require_branch_scope(endpoint.get("branch_id"))
    session = db.get_remote_session(session_id)
    if not session or str(session["endpoint_id"]) != endpoint_id:
        abort(404)
    capabilities = _require_remote_session_capability(session, "view")
    if not session.get("vnc_token"):
        abort(410)  # session token revoked
    response = make_response(render_template(
        "endpoints/remote_view.html",
        endpoint=endpoint,
        session=session,
        remote_capabilities=capabilities,
    ))
    response.set_cookie(
        "warden_remote", session["vnc_token"], max_age=3600,
        path=f"/remote-ws/{endpoint_id}", secure=True, httponly=True,
        samesite="Strict",
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@bp.route("/endpoints/<endpoint_id>/remote-view/<session_id>/status")
@login_required
@company_required
def remote_view_status(endpoint_id, session_id):
    """Polled by remote_view.html so a failed agent-side pairing (see
    agent_api.remote_relay_failed) shows its real reason within a few
    seconds, instead of the viewer only finding out once ws_proxy's own 60s
    PAIR_TIMEOUT closes the browser's WebSocket with a generic message."""
    endpoint = db.get_endpoint(endpoint_id)
    if not endpoint or str(endpoint["company_id"]) != str(g.company["id"]):
        abort(404)
    require_branch_scope(endpoint.get("branch_id"))
    session = db.get_remote_session(session_id)
    if not session or str(session["endpoint_id"]) != endpoint_id:
        abort(404)
    _require_remote_session_capability(session, "view")
    from services.device_health import remote_diagnostic
    return jsonify({
        "diagnostic": remote_diagnostic(endpoint, session),
        "status": session.get("status"),
        "fail_reason": session.get("fail_reason"),
        "consent_required": bool(session.get("consent_required")),
        "consent_status": session.get("consent_status"),
    })


@bp.route("/endpoints/<endpoint_id>/remote-view/<session_id>/reconnect", methods=["POST"])
@login_required
@company_required
def remote_reconnect_after_reboot(endpoint_id, session_id):
    endpoint = db.get_endpoint(endpoint_id)
    if not endpoint or str(endpoint["company_id"]) != str(g.company["id"]):
        abort(404)
    require_branch_scope(endpoint.get("branch_id"))
    if endpoint.get("status") != "online":
        return jsonify({"error": "endpoint_offline"}), 409
    from services.entitlements import check_feature
    entitlement = check_feature(g.company["id"], "remote_control")
    if not entitlement.allowed:
        return jsonify({"error": entitlement.code, "message": entitlement.message}), 403
    previous = db.get_remote_session(session_id)
    if not previous or str(previous.get("endpoint_id")) != endpoint_id:
        abort(404)
    capabilities = _require_remote_session_capability(previous, "reboot")
    db.close_remote_session(session_id)
    session = db.create_remote_session(endpoint_id, g.admin["id"], g.company["id"])
    if not session:
        return jsonify({"error": "failed_to_create_session"}), 500
    if not session.pop("_created", True):
        return jsonify({"error": "remote_session_initializing"}), 409
    new_id = str(session["id"])
    db.update_remote_session_controls(
        new_id, previous.get("access_mode") or "full_control", capabilities,
        previous.get("reason") or "Reconnect after reboot",
        bool(previous.get("consent_required")),
    )
    token = secrets.token_urlsafe(32)
    server_base = config.SERVER_URL.rstrip("/")
    relay_url = f"{server_base.replace('https://', 'wss://', 1)}/agent-relay/{new_id}"
    viewer_url = f"/endpoints/{endpoint_id}/remote-view/{new_id}"
    try:
        db.update_remote_session_token(new_id, token, viewer_url)
    except Exception:
        _fail_remote_session(new_id, "failed to provision remote-session token")
        raise
    try:
        job = db.create_job(
            g.company["id"], endpoint.get("branch_id"), endpoint_id,
            "SETUP_REMOTE_ACCESS", {
                "session_id": new_id, "relay_url": relay_url,
                "access_mode": previous.get("access_mode") or "full_control",
                "consent_required": bool(previous.get("consent_required")),
                "helper_name": g.admin.get("full_name") or g.admin.get("email") or "Warden technician",
                "reason": previous.get("reason") or "Reconnect after reboot",
            },
            created_by=g.admin["id"],
        )
    except Exception:
        _fail_remote_session(new_id, "failed to queue remote-access job")
        raise
    if not job:
        _fail_remote_session(new_id, "failed to queue remote-access job")
        return jsonify({"error": "failed_to_create_remote_job"}), 500
    db.create_remote_session_event(
        new_id, g.company["id"], g.admin["id"], "system",
        "Remote session restored after endpoint reboot",
        {"previous_session_id": session_id},
    )
    return jsonify({"ok": True, "viewer_url": viewer_url})


@bp.route("/endpoints/<endpoint_id>/remote-view/<session_id>/events", methods=["GET", "POST"])
@login_required
@company_required
def remote_session_events(endpoint_id, session_id):
    endpoint = db.get_endpoint(endpoint_id)
    if not endpoint or str(endpoint["company_id"]) != str(g.company["id"]):
        abort(404)
    require_branch_scope(endpoint.get("branch_id"))
    session = db.get_remote_session(session_id)
    if not session or str(session.get("endpoint_id")) != endpoint_id:
        abort(404)
    _require_remote_session_capability(session, "view")
    if request.method == "GET":
        return jsonify({"events": db.get_remote_session_events(session_id)})

    if session.get("status") != "active":
        return jsonify({"error": "session_not_active"}), 409

    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict):
        return jsonify({"error": "invalid_payload"}), 400
    event_type = str(body.get("type") or "").strip()
    text = str(body.get("body") or "").strip()
    # "system" is reserved for trusted server/agent events. Allowing a
    # browser user to submit it makes technician text indistinguishable from
    # authoritative audit events.
    if event_type not in {"note", "chat_admin"}:
        return jsonify({"error": "invalid_event_type"}), 400
    if not text or len(text) > 4000:
        return jsonify({"error": "body_must_be_1_to_4000_characters"}), 400
    event = db.create_remote_session_event(
        session_id, g.company["id"], g.admin["id"], event_type, text,
        metadata={"admin_name": g.admin.get("full_name") or g.admin.get("email")},
    )
    db.audit(g.company["id"], g.admin["id"], f"remote_session_{event_type}", {
        "endpoint_id": endpoint_id, "session_id": session_id,
    }, endpoint_id=endpoint_id)
    return jsonify({"ok": True, "event": event})


@bp.route("/endpoints/<endpoint_id>/support-link", methods=["POST"])
@login_required
@company_required
@role_required("company_admin", "branch_admin")
def create_support_link(endpoint_id):
    endpoint = db.get_endpoint(endpoint_id)
    if not endpoint or str(endpoint["company_id"]) != str(g.company["id"]):
        abort(404)
    require_branch_scope(endpoint.get("branch_id"))
    from services.entitlements import check_feature
    entitlement = check_feature(g.company["id"], "remote_control")
    if not entitlement.allowed:
        return jsonify({"error": entitlement.code, "message": entitlement.message}), 403
    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict):
        return jsonify({"error": "invalid_payload"}), 400
    try:
        minutes = max(5, min(int(body.get("minutes") or 60), 1440))
        max_uses = max(1, min(int(body.get("max_uses") or 1), 20))
    except (TypeError, ValueError):
        return jsonify({"error": "minutes_and_max_uses_must_be_integers"}), 400
    token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    link = db.create_remote_support_link(
        endpoint_id, g.company["id"], g.admin["id"],
        hashlib.sha256(token.encode()).hexdigest(), expires.isoformat(), max_uses,
    )
    if not link:
        return jsonify({"error": "failed_to_create_support_link"}), 500
    db.audit(g.company["id"], g.admin["id"], "remote_support_link_created", {
        "endpoint_id": endpoint_id, "link_id": str(link["id"]),
        "expires_at": expires.isoformat(), "max_uses": max_uses,
    }, endpoint_id=endpoint_id)
    return jsonify({
        "ok": True,
        "url": f"{config.SERVER_URL.rstrip('/')}/support/{token}",
        "expires_at": expires.isoformat(),
    })


@bp.route("/support/<token>")
def consume_support_link(token):
    """Redeem a short-lived capability link exactly once (or up to its
    explicitly configured use cap) and immediately create its remote session.
    The raw token is never stored; the atomic database function checks expiry,
    revocation and use_count in the same UPDATE."""
    if not token or len(token) > 200:
        abort(404)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    from middleware.security import check_rate_limit
    # The IP-wide bucket stops an attacker from bypassing throttling by
    # trying a fresh random token on every request; the token bucket also
    # limits repeated redemption of a known shared link.
    if (not check_rate_limit("support-link", 60, fail_closed=True)
            or not check_rate_limit(f"support-link:{token_hash}", 20, fail_closed=True)):
        response = Response("Too many support-link attempts. Try again later.", status=429)
        response.headers["Retry-After"] = "60"
        response.headers["Cache-Control"] = "no-store"
        return response
    # Do not consume a use from a one-time link merely because its endpoint
    # happens to be offline. The atomic claim still performs the authoritative
    # expiry/revocation/use-cap check after this non-consuming availability
    # preflight.
    candidate = db.get_remote_support_link_by_hash(token_hash)
    if not candidate:
        return "This support link is expired, revoked, or has already been used.", 410
    endpoint = db.get_endpoint(candidate["endpoint_id"])
    if not endpoint or endpoint.get("status") != "online":
        return "Endpoint is not currently online.", 409
    # Check before the atomic claim so a disabled feature does not burn
    # one use from a still-valid support link.
    from services.entitlements import check_feature
    entitlement = check_feature(candidate["company_id"], "remote_control")
    if not entitlement.allowed:
        return "Remote support is not available for this organization.", 403
    link = db.claim_remote_support_link(token_hash)
    if not link:
        return "This support link is expired, revoked, or has already been used.", 410

    try:
        session = db.create_remote_session(
            endpoint["id"], link.get("created_by"), link["company_id"],
        )
    except Exception:
        db.release_remote_support_link_claim(link["id"])
        raise
    if not session:
        db.release_remote_support_link_claim(link["id"])
        return "Unable to create the remote support session.", 503
    if not session.pop("_created", True):
        db.release_remote_support_link_claim(link["id"])
        return "A remote support session is already active for this endpoint.", 409
    session_id = str(session["id"])
    support_capabilities = {
        "view": True, "control": True, "clipboard": True,
        "file_transfer": False, "process_manager": False, "reboot": False,
    }
    db.update_remote_session_controls(
        session_id, "full_control", support_capabilities,
        "Temporary support link", True,
    )
    vnc_token = secrets.token_urlsafe(32)
    server_base = config.SERVER_URL.rstrip("/")
    relay_url = f"{server_base.replace('https://', 'wss://', 1)}/agent-relay/{session_id}"
    viewer_path = f"/support-session/{session_id}"
    try:
        db.update_remote_session_token(session_id, vnc_token, viewer_path)
    except Exception:
        _fail_remote_session(session_id, "failed to provision remote-session token")
        db.release_remote_support_link_claim(link["id"])
        raise
    try:
        job = db.create_job(
            link["company_id"], endpoint.get("branch_id"), endpoint["id"],
            "SETUP_REMOTE_ACCESS", {
                "session_id": session_id, "relay_url": relay_url,
                "access_mode": "full_control", "consent_required": True,
                "helper_name": "A temporary Warden support guest",
                "reason": "Temporary support link",
            },
            created_by=link.get("created_by"),
        )
    except Exception:
        _fail_remote_session(session_id, "failed to queue remote-access job")
        db.release_remote_support_link_claim(link["id"])
        raise
    if not job:
        _fail_remote_session(session_id, "failed to queue remote-access job")
        db.release_remote_support_link_claim(link["id"])
        return "Unable to queue the remote support session.", 503
    db.create_remote_session_event(
        session_id, link["company_id"], link.get("created_by"), "system",
        "Temporary support link redeemed",
        {"support_link_id": str(link["id"])},
    )
    response = make_response(render_template(
        "endpoints/remote_view.html", endpoint=endpoint, session=session,
        support_mode=True,
        remote_capabilities=support_capabilities,
    ))
    response.set_cookie(
        "warden_remote", vnc_token, max_age=3600,
        path=f"/remote-ws/{endpoint['id']}", secure=True, httponly=True,
        samesite="Strict",
    )
    response.headers["Cache-Control"] = "no-store"
    return response


_REMOTE_DROP_MAX_BYTES = 8 * 1024 * 1024  # 8 MB — see comment on remote_file_push()
_REMOTE_USER_PATH_RE = re.compile(
    r"(?i)C:\\Users\\[^\\/:*?\"<>|]+\\(?:Desktop|Documents|Downloads)"
    r"(?:\\[^:*?\"<>|]+)*"
)
_REMOTE_POSIX_PATH_RE = re.compile(
    r"/(?:home|Users)/[^/\x00]+/(?:Desktop|Documents|Downloads)(?:/[^/\x00]+)*"
    r"|/(?:tmp|private/tmp|Users/Shared)(?:/[^/\x00]+)*"
)


def _valid_remote_user_path(endpoint, path):
    if (endpoint.get("platform") or "windows") in {"linux", "darwin"}:
        return bool(_REMOTE_POSIX_PATH_RE.fullmatch(path))
    return bool(_REMOTE_USER_PATH_RE.fullmatch(path))


@bp.route("/endpoints/<endpoint_id>/remote-view/<session_id>/file-push", methods=["POST"])
@login_required
@company_required
def remote_file_push(endpoint_id, session_id):
    """
    Upload or drag-and-drop file transfer for an active remote session.

    Not a live/real-time channel like RDP's clipboard file transfer — it
    reuses the existing FILE_PUSH job type (agent/commands.py's
    _file_push, agent-go/commands.go's filePush), which carries the whole
    file as base64 inside the job's payload column (organization
    encrypted — see services/tenant_crypto.py). That means: (a) a hard
    size cap, since base64 inflates size ~33% and this lands in a DB row,
    not a stream, and (b) the file arrives whenever the agent's next
    heartbeat happens to be (up to ~POLL_INTERVAL_SEC, ~30s), not
    instantly — there's no fast path from here into the live WebSocket
    relay's frame/input channel.

    The viewer copies the foreground Explorer address bar and submits that
    directory. Only a local C:\\Users path is accepted; Public Desktop is the
    fallback when Explorer is not foreground or the path cannot be detected.
    """
    endpoint = db.get_endpoint(endpoint_id)
    if not endpoint or str(endpoint["company_id"]) != str(g.company["id"]):
        abort(404)
    require_branch_scope(endpoint.get("branch_id"))

    session = db.get_remote_session(session_id)
    if not session or str(session["endpoint_id"]) != endpoint_id:
        abort(404)
    _require_remote_session_capability(session, "file_transfer")
    if session.get("status") != "active":
        return jsonify({"error": "session_not_active"}), 409

    if "file" not in request.files:
        return jsonify({"error": "no_file_provided"}), 400
    f = request.files["file"]
    filename = pathlib.Path(f.filename or "dropped_file").name  # strip any path components
    if not filename:
        return jsonify({"error": "invalid_filename"}), 400

    data = f.read(_REMOTE_DROP_MAX_BYTES + 1)
    if len(data) > _REMOTE_DROP_MAX_BYTES:
        return jsonify({
            "error": "file_too_large",
            "message": f"Drag-and-drop transfer is capped at {_REMOTE_DROP_MAX_BYTES // (1024*1024)} MB "
                       "(the file rides inside a signed job payload, not a streamed transfer).",
        }), 413

    dest_dir = (request.form.get("dest_dir") or "").strip().rstrip("\\/")
    # Do not accept arbitrary privileged filesystem destinations from the
    # browser. Explorer folders inside a local user profile are sufficient
    # for interactive drag/drop; everything else falls back safely.
    platform = endpoint.get("platform") or "windows"
    if not _valid_remote_user_path(endpoint, dest_dir):
        dest_dir = "/Users/Shared" if platform == "darwin" else (
            "/tmp/Warden Transfers" if platform == "linux" else r"C:\Users\Public\Desktop"
        )
    dest_path = str(pathlib.PurePosixPath(dest_dir) / filename) if platform in {"linux", "darwin"} else f"{dest_dir}\\{filename}"
    job = db.create_job(
        company_id=g.company["id"],
        branch_id=endpoint.get("branch_id"),
        endpoint_id=endpoint_id,
        job_type="FILE_PUSH",
        payload={
            "path": dest_path,
            "content_b64": base64.b64encode(data).decode("ascii"),
        },
        created_by=g.admin["id"],
    )
    if not job:
        return jsonify({"error": "failed_to_create_job"}), 500

    db.audit(g.company["id"], g.admin["id"], "remote_session_file_pushed", {
        "endpoint_id": endpoint_id,
        "session_id": session_id,
        "filename": filename,
        "size_bytes": len(data),
        "job_id": str(job["id"]),
    }, endpoint_id=endpoint_id)

    return jsonify({
        "ok": True,
        "job_id": str(job["id"]),
        "dest_path": dest_path,
        "message": f"Queued for {dest_dir}; waiting for the endpoint's next check-in.",
    })


@bp.route("/endpoints/<endpoint_id>/remote-view/<session_id>/file-pull", methods=["POST"])
@login_required
@company_required
def remote_file_pull(endpoint_id, session_id):
    """Queue a file download from a user-profile path on the remote endpoint."""
    endpoint = db.get_endpoint(endpoint_id)
    if not endpoint or str(endpoint["company_id"]) != str(g.company["id"]):
        abort(404)
    require_branch_scope(endpoint.get("branch_id"))
    session = db.get_remote_session(session_id)
    if not session or str(session["endpoint_id"]) != endpoint_id:
        abort(404)
    _require_remote_session_capability(session, "file_transfer")
    if session.get("status") != "active":
        return jsonify({"error": "session_not_active"}), 409

    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict):
        return jsonify({"error": "invalid_payload"}), 400
    src_path = str(body.get("path") or "").strip()
    if not _valid_remote_user_path(endpoint, src_path):
        return jsonify({
            "error": "invalid_path",
            "message": "Enter a full path inside a user Desktop, Documents, Downloads, or the shared transfer folder.",
        }), 400
    if src_path.endswith(("\\", "/")):
        return jsonify({"error": "file_path_required"}), 400

    job = db.create_job(
        company_id=g.company["id"],
        branch_id=endpoint.get("branch_id"),
        endpoint_id=endpoint_id,
        job_type="FILE_PULL",
        payload={"path": src_path},
        created_by=g.admin["id"],
    )
    if not job:
        return jsonify({"error": "failed_to_create_job"}), 500
    db.audit(g.company["id"], g.admin["id"], "remote_session_file_pull_queued", {
        "endpoint_id": endpoint_id,
        "session_id": session_id,
        "path": src_path,
        "job_id": str(job["id"]),
    }, endpoint_id=endpoint_id)
    return jsonify({"ok": True, "job_id": str(job["id"]), "path": src_path})


@bp.route("/endpoints/<endpoint_id>/remote-view/<session_id>/files/browse", methods=["POST"])
@login_required
@company_required
def remote_files_browse(endpoint_id, session_id):
    """Queue a read-only directory listing below C:\\Users."""
    endpoint = db.get_endpoint(endpoint_id)
    session = db.get_remote_session(session_id)
    if (not endpoint or str(endpoint["company_id"]) != str(g.company["id"])
            or not session or str(session["endpoint_id"]) != endpoint_id):
        abort(404)
    require_branch_scope(endpoint.get("branch_id"))
    _require_remote_session_capability(session, "file_transfer")
    if session.get("status") != "active":
        return jsonify({"error": "session_not_active"}), 409
    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict):
        return jsonify({"error": "invalid_payload"}), 400
    path = str(body.get("path") or "::folders::").strip()
    if path != "::folders::" and not _valid_remote_user_path(endpoint, path):
        return jsonify({"error": "invalid_path"}), 400
    job = db.create_job(
        company_id=g.company["id"], branch_id=endpoint.get("branch_id"),
        endpoint_id=endpoint_id, job_type="LIST_DIRECTORY",
        payload={"path": path}, created_by=g.admin["id"],
    )
    if not job:
        return jsonify({"error": "failed_to_queue_directory_listing"}), 500
    return jsonify({"ok": True, "job_id": str(job["id"])})


@bp.route("/endpoints/<endpoint_id>/remote-view/<session_id>/file-job/<job_id>")
@login_required
@company_required
def remote_file_job_status(endpoint_id, session_id, job_id):
    endpoint = db.get_endpoint(endpoint_id)
    job = db.get_job(job_id)
    session = db.get_remote_session(session_id)
    if (not endpoint or str(endpoint["company_id"]) != str(g.company["id"])
            or not session or str(session["endpoint_id"]) != endpoint_id
            or not job or str(job.get("endpoint_id")) != endpoint_id
            or str(job.get("company_id")) != str(g.company["id"])
            or job.get("type") not in ("FILE_PUSH", "FILE_PULL", "LIST_DIRECTORY")):
        abort(404)
    require_branch_scope(endpoint.get("branch_id"))
    _require_remote_session_capability(session, "file_transfer")
    return jsonify({
        "status": job.get("status"),
        "error": job.get("error_msg"),
        "log": job.get("log_output"),
    })


@bp.route("/endpoints/<endpoint_id>/remote-view/<session_id>/file-job/<job_id>/download")
@login_required
@company_required
def remote_file_download(endpoint_id, session_id, job_id):
    """Return completed FILE_PULL content as a browser attachment."""
    endpoint = db.get_endpoint(endpoint_id)
    job = db.get_job(job_id)
    session = db.get_remote_session(session_id)
    if (not endpoint or str(endpoint["company_id"]) != str(g.company["id"])
            or not session or str(session["endpoint_id"]) != endpoint_id
            or not job or str(job.get("endpoint_id")) != endpoint_id
            or str(job.get("company_id")) != str(g.company["id"])
            or job.get("type") != "FILE_PULL"):
        abort(404)
    require_branch_scope(endpoint.get("branch_id"))
    _require_remote_session_capability(session, "file_transfer")
    if job.get("status") != "completed":
        return jsonify({"error": "file_not_ready"}), 409
    try:
        result = json.loads(job.get("log_output") or "{}")
        content = base64.b64decode(result.get("content_b64") or "", validate=True)
    except (ValueError, TypeError, json.JSONDecodeError):
        return jsonify({"error": "invalid_file_result"}), 500
    filename = result.get("download_name") or pathlib.PureWindowsPath(result.get("path") or "remote-file").name
    safe_name = filename.replace('"', "") or "remote-file"
    return Response(
        content,
        mimetype="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_name}"',
            "Cache-Control": "no-store",
        },
    )


@bp.route("/endpoints/<endpoint_id>/end-session/<session_id>", methods=["POST"])
@login_required
@company_required
def end_remote_session(endpoint_id, session_id):
    """
    End a remote session: dispatch REMOVE_REMOTE_ACCESS to agent and revoke token.
    """
    endpoint = db.get_endpoint(endpoint_id)
    if not endpoint or str(endpoint["company_id"]) != str(g.company["id"]):
        abort(404)
    require_branch_scope(endpoint.get("branch_id"))

    session = db.get_remote_session(session_id)
    if not session or str(session["endpoint_id"]) != endpoint_id:
        abort(404)
    _require_remote_session_capability(session, "view")

    # Close the session record
    db.close_remote_session(session_id)

    # Dispatch REMOVE_REMOTE_ACCESS to the agent (best-effort, non-blocking)
    db.create_job(
        company_id=g.company["id"],
        branch_id=endpoint["branch_id"],
        endpoint_id=endpoint_id,
        job_type="REMOVE_REMOTE_ACCESS",
        payload={"session_id": session_id},
        created_by=g.admin["id"],
    )

    db.audit(g.company["id"], g.admin["id"], "remote_session_ended", {
        "endpoint_id": endpoint_id,
        "session_id": session_id,
    }, endpoint_id=endpoint_id)

    return jsonify({"ok": True})
