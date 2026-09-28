"""
Warden — Superadmin routes
Company management, global user management, system overview.
"""
from collections import Counter
from datetime import datetime, timezone
import re

from flask import Blueprint, render_template, request, jsonify, g, redirect, url_for, abort, session, flash

import db
import config
from middleware.auth import login_required, superadmin_required

bp = Blueprint("superadmin", __name__)


def _hash_password(password):
    import bcrypt
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


@bp.route("/admin")
@login_required
@superadmin_required
def index():
    companies = db.get_all_companies()
    subscriptions = {str(s["company_id"]): s for s in db.get_subscriptions()}
    totals = {"tenants": len(companies), "active": 0, "attention": 0,
              "endpoints": 0, "online": 0, "mrr_cents": 0}
    for c in companies:
        usage = db.get_company_usage(c["id"])
        sub = subscriptions.get(str(c["id"])) or db.ensure_company_subscription(c["id"])
        c["_usage"], c["_subscription"] = usage, sub
        totals["endpoints"] += usage["endpoints"]
        totals["online"] += usage["online_endpoints"]
        totals["active"] += int(bool(c.get("is_active")) and (sub or {}).get("lifecycle_state") == "active")
        totals["attention"] += int((sub or {}).get("status") in {"past_due", "unpaid"} or
                                   (sub or {}).get("lifecycle_state") not in {"active", "grace"})
        totals["mrr_cents"] += (sub or {}).get("recurring_amount_cents") or 0
    return render_template("superadmin/overview.html", companies=companies, totals=totals)


@bp.route("/admin/tenants")
@login_required
@superadmin_required
def tenants():
    query = request.args.get("q", "").strip().lower()
    state = request.args.get("state", "").strip()
    subscriptions = {str(s["company_id"]): s for s in db.get_subscriptions()}
    companies = []
    for company in db.get_all_companies():
        sub = subscriptions.get(str(company["id"])) or db.ensure_company_subscription(company["id"])
        company["_subscription"] = sub
        company["_usage"] = db.get_company_usage(company["id"])
        if query and query not in (company.get("name", "") + " " + company.get("slug", "")).lower():
            continue
        if state and (sub or {}).get("lifecycle_state") != state:
            continue
        companies.append(company)
    return render_template("superadmin/tenants.html", companies=companies, query=query, state=state)


@bp.route("/admin/tenants/<company_id>")
@login_required
@superadmin_required
def tenant_detail(company_id):
    company = db.get_company_by_id(company_id)
    if not company:
        abort(404)
    subscription = db.ensure_company_subscription(company_id)
    usage = db.get_company_usage(company_id)
    has_support_access = db.has_active_access_grant(company_id, g.admin["id"])
    endpoints = db.get_endpoints(company_id) if has_support_access else []
    admins = ([a for a in db.get_all_admins()
               if str(a.get("company_id")) == str(company_id)]
              if has_support_access else [])
    company_jobs = db.get_jobs(company_id, limit=100) if has_support_access else []
    company_alerts = (db.get_alerts(company_id, resolved=False, limit=100)
                      if has_support_access else [])
    builds = db.get_build_requests(company_id, limit=20) if has_support_access else []
    version_counts = Counter((e.get("agent_version") or "unknown") for e in endpoints)
    onboarding = db.get_tenant_onboarding(company_id) or {
        "status": "not_started", "steps": {}, "notes": "", "target_date": None,
    }
    from services.entitlements import effective_platform_features
    return render_template(
        "superadmin/tenant_detail.html", company=company, subscription=subscription,
        usage=usage, endpoints=endpoints, admins=admins, branches=db.get_branches(company_id),
        overrides=db.get_active_entitlement_overrides(company_id),
        lifecycle_actions=db.get_lifecycle_actions(company_id), plans=db.get_plans(active_only=True),
        jobs=company_jobs, alerts=company_alerts, builds=builds,
        version_counts=version_counts, onboarding=onboarding,
        feature_flags=db.get_feature_flags(), feature_overrides=db.get_feature_overrides(company_id),
        effective_features=effective_platform_features(company_id),
        has_support_access=has_support_access,
    )


@bp.route("/admin/plans")
@login_required
@superadmin_required
def plans():
    return render_template("superadmin/plans.html", plans=db.get_plans())


@bp.route("/admin/subscriptions")
@login_required
@superadmin_required
def subscriptions():
    return render_template("superadmin/subscriptions.html", subscriptions=db.get_subscriptions())


@bp.route("/admin/platform-health")
@login_required
@superadmin_required
def platform_health():
    companies = db.get_all_companies()
    usage = [db.get_company_usage(c["id"]) for c in companies]
    failed_jobs = db.get_platform_jobs(status="failed", limit=500)
    pending_builds = [b for b in db.get_all_build_requests(limit=100) if b.get("status") in {"pending", "building"}]
    incidents = [i for i in db.get_platform_incidents() if i.get("status") != "resolved"]
    recovery = db.get_recovery_checks(limit=50)
    latest_recovery = {}
    for check in recovery:
        latest_recovery.setdefault(check["check_type"], check)
    try:
        database_state = "operational" if db.healthcheck() else "failed"
    except Exception:
        database_state = "failed"
    health = {
        "database": database_state,
        "tenants": len(companies),
        "endpoints": sum(x["endpoints"] for x in usage),
        "online": sum(x["online_endpoints"] for x in usage),
        "offline": sum(x["endpoints"] - x["online_endpoints"] for x in usage),
        "failed_jobs": len(failed_jobs), "pending_builds": len(pending_builds),
        "incidents": len(incidents),
    }
    return render_template("superadmin/platform_health.html", health=health,
                           incidents=incidents, latest_recovery=latest_recovery)


def _company_and_endpoint_maps():
    companies = db.get_all_companies()
    company_map = {str(c["id"]): c for c in companies}
    endpoint_map = {}
    for company in companies:
        for endpoint in db.get_endpoints(company["id"]):
            endpoint_map[str(endpoint["id"])] = endpoint
    return companies, company_map, endpoint_map


@bp.route("/admin/operations")
@login_required
@superadmin_required
def operations():
    companies, company_map, endpoint_map = _company_and_endpoint_maps()
    jobs = db.get_platform_jobs(limit=200)
    alerts = db.get_platform_alerts(limit=100)
    builds = db.get_all_build_requests(limit=100)
    for row in jobs + alerts + builds:
        row["_company"] = company_map.get(str(row.get("company_id")))
        row["_endpoint"] = endpoint_map.get(str(row.get("endpoint_id")))
    endpoints = list(endpoint_map.values())
    version_counts = Counter((e.get("agent_version") or "unknown") for e in endpoints)
    platform_counts = Counter((e.get("platform") or "windows").lower() for e in endpoints)
    return render_template("superadmin/operations.html", companies=companies, jobs=jobs,
        alerts=alerts, builds=builds, incidents=db.get_platform_incidents(),
        version_counts=version_counts, platform_counts=platform_counts,
        online=sum(1 for e in endpoints if e.get("status") == "online"), endpoints=len(endpoints))


@bp.route("/admin/incidents/create", methods=["POST"])
@login_required
@superadmin_required
def create_incident():
    title = request.form.get("title", "").strip()
    severity = request.form.get("severity", "medium")
    summary = request.form.get("summary", "").strip()
    tenants = request.form.getlist("company_id")
    if len(title) < 3 or severity not in {"low", "medium", "high", "critical"}:
        flash("Incident title and valid severity are required.", "error")
        return redirect(url_for("superadmin.operations"))
    incident = db.create_platform_incident(title, severity, summary, tenants, g.admin["id"])
    db.audit(None, g.admin["id"], "platform_incident_created", {"incident_id": incident["id"], "severity": severity})
    flash("Incident opened.", "success")
    return redirect(url_for("superadmin.operations"))


@bp.route("/admin/incidents/<incident_id>/status", methods=["POST"])
@login_required
@superadmin_required
def update_incident(incident_id):
    status = request.form.get("status", "")
    if status not in {"investigating", "identified", "monitoring", "resolved"}:
        abort(400)
    db.update_platform_incident(incident_id, status, g.admin["id"])
    db.audit(None, g.admin["id"], "platform_incident_updated", {"incident_id": incident_id, "status": status})
    return redirect(url_for("superadmin.operations"))


@bp.route("/admin/features")
@login_required
@superadmin_required
def features():
    companies = db.get_all_companies()
    company_map = {str(c["id"]): c for c in companies}
    overrides = db.get_feature_overrides()
    for override in overrides:
        override["_company"] = company_map.get(str(override.get("company_id")))
    return render_template("superadmin/features.html", flags=db.get_feature_flags(),
                           overrides=overrides, companies=companies)


@bp.route("/admin/features/create", methods=["POST"])
@login_required
@superadmin_required
def create_feature():
    key = request.form.get("key", "").strip().lower()
    name = request.form.get("name", "").strip()
    stage = request.form.get("stage", "alpha")
    try:
        rollout = int(request.form.get("rollout_percent", 0))
    except ValueError:
        rollout = -1
    platforms = [p for p in request.form.getlist("platform") if p in {"windows", "macos", "linux"}]
    if not re.fullmatch(r"[a-z0-9_]+", key) or not name or stage not in {"alpha", "beta", "ga", "retired"} or not 0 <= rollout <= 100:
        flash("Use a valid key, name, stage and rollout percentage.", "error")
        return redirect(url_for("superadmin.features"))
    flag = db.create_feature_flag(key, name, request.form.get("description", "").strip(), stage,
        request.form.get("is_enabled") == "on", rollout, platforms or ["windows"], g.admin["id"])
    db.audit(None, g.admin["id"], "platform_feature_created", {"key": key, "flag_id": flag["id"]})
    return redirect(url_for("superadmin.features"))


@bp.route("/admin/features/<flag_id>/update", methods=["POST"])
@login_required
@superadmin_required
def update_feature(flag_id):
    stage = request.form.get("stage", "alpha")
    try:
        rollout = min(100, max(0, int(request.form.get("rollout_percent", 0))))
    except ValueError:
        rollout = 0
    db.update_feature_flag(flag_id, {"stage": stage, "rollout_percent": rollout,
        "is_enabled": request.form.get("is_enabled") == "on"})
    db.audit(None, g.admin["id"], "platform_feature_updated", {"flag_id": flag_id, "stage": stage, "rollout": rollout})
    return redirect(url_for("superadmin.features"))


@bp.route("/admin/features/override", methods=["POST"])
@login_required
@superadmin_required
def feature_override():
    flag_id = request.form.get("flag_id", "")
    company_id = request.form.get("company_id", "")
    reason = request.form.get("reason", "").strip()
    if not db.get_company_by_id(company_id) or len(reason) < 3:
        flash("Tenant and reason are required.", "error")
        return redirect(url_for("superadmin.features"))
    enabled = request.form.get("enabled") == "true"
    db.set_feature_override(flag_id, company_id, enabled, reason, request.form.get("expires_at") or None, g.admin["id"])
    db.audit(company_id, g.admin["id"], "tenant_feature_override", {"flag_id": flag_id, "enabled": enabled, "reason": reason})
    return redirect(url_for("superadmin.features"))


@bp.route("/admin/security-center")
@login_required
@superadmin_required
def security_center():
    admins = db.get_all_admins()
    grants = db.list_all_access_grants()
    companies = {str(c["id"]): c for c in db.get_all_companies()}
    for grant in grants:
        grant["_company"] = companies.get(str(grant.get("company_id")))
    endpoints = [
        endpoint
        for company in companies.values()
        for endpoint in db.get_endpoints(company["id"])
    ]
    certificate_count = sum(1 for endpoint in endpoints if endpoint.get("client_cert_fingerprint"))
    mtls = {
        "private_ca_enabled": bool(config.DEVICE_CERTIFICATES_ENABLED),
        "enforced": bool(config.REQUIRE_CLIENT_CERT),
        "eligible": len(endpoints),
        "certificates": certificate_count,
        "ready": bool(endpoints) and certificate_count == len(endpoints)
                 and bool(config.DEVICE_CERTIFICATES_ENABLED),
    }
    try:
        audit_integrity = db.verify_audit_chain()
    except Exception:
        audit_integrity = {"valid": False, "broken": None, "rows": None, "unavailable": True}
    return render_template("superadmin/security_center.html", admins=admins, grants=grants,
                           blocked_ips=db.list_blocked_ips(), companies=companies,
                           mtls=mtls, audit_integrity=audit_integrity)


@bp.route("/admin/security-center/firewall/block", methods=["POST"])
@login_required
@superadmin_required
def security_firewall_block():
    import ipaddress
    ip = request.form.get("ip_address", "").strip()
    reason = request.form.get("reason", "").strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        flash("Enter a valid IP address.", "error")
        return redirect(url_for("superadmin.security_center"))
    if len(reason) < 3:
        flash("A reason is required.", "error")
        return redirect(url_for("superadmin.security_center"))
    db.block_ip(ip, reason, created_by=g.admin["id"], expires_at=request.form.get("expires_at") or None)
    db.audit(None, g.admin["id"], "firewall_ip_blocked", {"ip_address": ip, "reason": reason})
    return redirect(url_for("superadmin.security_center"))


@bp.route("/admin/security-center/firewall/unblock", methods=["POST"])
@login_required
@superadmin_required
def security_firewall_unblock():
    ip = request.form.get("ip_address", "").strip()
    if not ip:
        abort(400)
    db.unblock_ip(ip)
    db.audit(None, g.admin["id"], "firewall_ip_unblocked", {"ip_address": ip})
    return redirect(url_for("superadmin.security_center"))


@bp.route("/admin/recovery")
@login_required
@superadmin_required
def recovery():
    checks = db.get_recovery_checks()
    latest = {}
    for check in checks:
        latest.setdefault(check["check_type"], check)
    return render_template("superadmin/recovery.html", checks=checks, latest=latest)


@bp.route("/admin/recovery/check", methods=["POST"])
@login_required
@superadmin_required
def record_recovery_check():
    check_type = request.form.get("check_type", "")
    status = request.form.get("status", "")
    allowed_types = {"database_backup", "restore_test", "uploads_backup", "agent_artifacts", "tenant_export", "disaster_recovery"}
    if check_type not in allowed_types or status not in {"passed", "warning", "failed"}:
        abort(400)
    db.create_recovery_check(check_type, status, request.form.get("notes", "").strip(),
                             request.form.get("evidence", "").strip(), g.admin["id"])
    db.audit(None, g.admin["id"], "recovery_check_recorded", {"check_type": check_type, "status": status})
    return redirect(url_for("superadmin.recovery"))


@bp.route("/admin/usage")
@login_required
@superadmin_required
def usage():
    companies = db.get_all_companies()
    company_map = {str(c["id"]): c for c in companies}
    snapshots = db.get_usage_snapshots(limit=300)
    for snapshot in snapshots:
        snapshot["_company"] = company_map.get(str(snapshot.get("company_id")))
    return render_template("superadmin/usage.html", companies=companies, snapshots=snapshots,
                           subscriptions=db.get_subscriptions())


@bp.route("/admin/usage/capture", methods=["POST"])
@login_required
@superadmin_required
def capture_usage():
    company_id = request.form.get("company_id")
    targets = [db.get_company_by_id(company_id)] if company_id else db.get_all_companies()
    captured = 0
    for company in [c for c in targets if c]:
        if db.capture_usage_snapshot(company["id"]):
            captured += 1
    db.audit(None, g.admin["id"], "usage_snapshots_captured", {"tenants": captured})
    flash(f"Captured usage for {captured} tenant(s).", "success")
    return redirect(url_for("superadmin.usage"))


@bp.route("/admin/tenants/<company_id>/onboarding", methods=["POST"])
@login_required
@superadmin_required
def update_onboarding(company_id):
    if not db.get_company_by_id(company_id):
        abort(404)
    known_steps = {"tenant", "admin", "plan", "branding", "vault", "enrollment", "first_endpoint", "handoff"}
    steps = {step: request.form.get(step) == "on" for step in known_steps}
    status = "complete" if all(steps.values()) else request.form.get("status", "in_progress")
    if status not in {"not_started", "in_progress", "blocked", "complete"}:
        status = "in_progress"
    db.save_tenant_onboarding(company_id, {"status": status, "steps": steps,
        "owner_id": g.admin["id"], "target_date": request.form.get("target_date") or None,
        "notes": request.form.get("notes", "").strip()})
    db.audit(company_id, g.admin["id"], "tenant_onboarding_updated", {"status": status, "completed_steps": sum(steps.values())})
    return redirect(url_for("superadmin.tenant_detail", company_id=company_id))


@bp.route("/admin/plans/<plan_id>/update", methods=["POST"])
@login_required
@superadmin_required
def update_plan(plan_id):
    plan = db.get_plan(plan_id)
    if not plan:
        abort(404)
    def limit(name):
        raw = request.form.get(name, "").strip()
        return None if raw == "" else max(0, int(raw))
    try:
        fields = {
            "name": request.form.get("name", "").strip() or plan["name"],
            "endpoint_limit": limit("endpoint_limit"),
            "admin_limit": limit("admin_limit"),
            "branch_limit": limit("branch_limit"),
            "audit_retention_days": max(1, int(request.form.get("audit_retention_days", 30))),
            "is_active": request.form.get("is_active") == "on",
        }
    except ValueError:
        flash("Limits must be whole numbers or blank for unlimited.", "error")
        return redirect(url_for("superadmin.plans"))
    db.update_plan(plan_id, fields)
    db.audit(None, g.admin["id"], "saas_plan_updated", {"plan": plan["code"], **fields})
    flash(f"{fields['name']} updated.", "success")
    return redirect(url_for("superadmin.plans"))


@bp.route("/admin/tenants/<company_id>/subscription", methods=["POST"])
@login_required
@superadmin_required
def update_tenant_subscription(company_id):
    company = db.get_company_by_id(company_id)
    plan = db.get_plan(request.form.get("plan_id", ""))
    reason = request.form.get("reason", "").strip()
    if not company or not plan:
        abort(404)
    if len(reason) < 3:
        flash("A reason is required for subscription changes.", "error")
        return redirect(url_for("superadmin.tenant_detail", company_id=company_id))
    old = db.ensure_company_subscription(company_id) or {}
    db.update_subscription(company_id, {"plan_id": plan["id"]})
    db.create_lifecycle_action(company_id, "plan_changed",
                               (old.get("plans") or {}).get("code"), plan["code"],
                               reason, g.admin["id"])
    db.audit(company_id, g.admin["id"], "tenant_plan_changed",
             {"from": (old.get("plans") or {}).get("code"), "to": plan["code"], "reason": reason})
    flash(f"{company['name']} moved to {plan['name']}.", "success")
    return redirect(url_for("superadmin.tenant_detail", company_id=company_id))


@bp.route("/admin/tenants/<company_id>/lifecycle", methods=["POST"])
@login_required
@superadmin_required
def update_tenant_lifecycle(company_id):
    company = db.get_company_by_id(company_id)
    new_state = request.form.get("lifecycle_state", "")
    reason = request.form.get("reason", "").strip()
    allowed = {"active", "grace", "read_only", "suspended", "deletion_pending"}
    if not company:
        abort(404)
    if new_state not in allowed or len(reason) < 3:
        flash("Select a valid lifecycle and provide a reason.", "error")
        return redirect(url_for("superadmin.tenant_detail", company_id=company_id))
    if new_state == "deletion_pending" and request.form.get("confirmation", "").strip() != company["slug"]:
        flash(f"Type {company['slug']} to schedule deletion.", "error")
        return redirect(url_for("superadmin.tenant_detail", company_id=company_id))
    old = db.ensure_company_subscription(company_id) or {}
    db.update_subscription(company_id, {"lifecycle_state": new_state})
    expires_at = None
    if new_state == "deletion_pending":
        from datetime import timedelta
        expires_at = (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    db.create_lifecycle_action(company_id, "lifecycle_changed", old.get("lifecycle_state"),
                               new_state, reason, g.admin["id"], expires_at=expires_at)
    db.audit(company_id, g.admin["id"], "tenant_lifecycle_changed",
             {"from": old.get("lifecycle_state"), "to": new_state, "reason": reason})
    flash(f"Lifecycle changed to {new_state.replace('_', ' ')}.", "success")
    return redirect(url_for("superadmin.tenant_detail", company_id=company_id))


@bp.route("/admin/tenants/<company_id>/overrides", methods=["POST"])
@login_required
@superadmin_required
def create_override(company_id):
    key = request.form.get("entitlement_key", "").strip()
    raw_value = request.form.get("value", "").strip()
    reason = request.form.get("reason", "").strip()
    if key not in {"endpoints", "admins", "branches", "remote_control", "file_transfer",
                   "policy_management", "advanced_reporting", "api_access"} or len(reason) < 3:
        flash("Valid entitlement and reason are required.", "error")
        return redirect(url_for("superadmin.tenant_detail", company_id=company_id))
    try:
        value = raw_value.lower() == "true" if raw_value.lower() in {"true", "false"} else int(raw_value)
    except ValueError:
        flash("Value must be a number, true, or false.", "error")
        return redirect(url_for("superadmin.tenant_detail", company_id=company_id))
    db.create_entitlement_override(company_id, key, value, reason,
                                   request.form.get("expires_at") or None, g.admin["id"])
    db.audit(company_id, g.admin["id"], "entitlement_override_created",
             {"key": key, "value": value, "reason": reason})
    flash("Temporary entitlement override added.", "success")
    return redirect(url_for("superadmin.tenant_detail", company_id=company_id))


@bp.route("/admin/tenants/<company_id>/overrides/<override_id>/revoke", methods=["POST"])
@login_required
@superadmin_required
def revoke_override(company_id, override_id):
    active = {
        str(row["id"]): row for row in db.get_active_entitlement_overrides(company_id)
    }
    override = active.get(str(override_id))
    if not override:
        abort(404)
    reason = request.form.get("reason", "").strip()
    if len(reason) < 3:
        flash("A reason is required to revoke an override.", "error")
        return redirect(url_for("superadmin.tenant_detail", company_id=company_id))
    db.revoke_entitlement_override(override_id, g.admin["id"])
    db.audit(company_id, g.admin["id"], "entitlement_override_revoked", {
        "override_id": override_id, "key": override["entitlement_key"], "reason": reason,
    })
    flash("Entitlement override revoked.", "success")
    return redirect(url_for("superadmin.tenant_detail", company_id=company_id))


@bp.route("/admin/companies/<company_id>/open")
@login_required
@superadmin_required
def open_company(company_id):
    """"Open" a tenant's console. This deployment has no per-company
    subdomain routing (see middleware/auth.py's load_current_user()), so a
    superadmin can't just visit <slug>.warden.<domain> the way the original
    design assumed — instead, once they hold an active access grant for
    this company (see request_access below), this stores the choice in
    their own session and every subsequent request resolves g.company from
    it, same as company_required's existing grant re-check on every call."""
    company = db.get_company_by_id(company_id)
    if not company:
        abort(404)
    if not db.has_active_access_grant(company_id, g.admin["id"]):
        return redirect(url_for("superadmin.request_access", company_id=company_id))
    session["viewing_company_id"] = company_id
    return redirect(url_for("dashboard.index"))


@bp.route("/admin/exit-company-view")
@login_required
@superadmin_required
def exit_company_view():
    session.pop("viewing_company_id", None)
    return redirect(url_for("superadmin.index"))


def _enriched_audit_entries(company_id=None, event_type=None):
    entries = db.get_all_audit_log(company_id=company_id, action=event_type)
    company_cache = {}
    admin_cache = {}
    endpoint_cache = {}
    access_cache = {}
    for e in entries:
        cid = e.get("company_id")
        if cid and cid not in company_cache:
            company_cache[cid] = db.get_company_by_id(cid)
        company = company_cache.get(cid)

        if cid and cid not in access_cache:
            access_cache[cid] = db.has_active_access_grant(cid, g.admin["id"])
        tenant_detail_allowed = not cid or access_cache.get(cid, False)

        if not tenant_detail_allowed:
            e["event"] = e.get("action", "")
            e["company_slug"] = company["slug"] if company else "—"
            e["actor"] = "Tenant user"
            e["endpoint_hostname"] = None
            e["detail"] = {}
            e["detail_summary"] = "Tenant detail redacted — support access required"
            e["redacted"] = True
            continue

        aid = e.get("actor_id")
        if aid and aid not in admin_cache:
            admin_cache[aid] = db.get_admin_by_id(aid)
        actor = admin_cache.get(aid)

        eid = e.get("endpoint_id")
        if eid and eid not in endpoint_cache:
            endpoint_cache[eid] = db.get_endpoint(eid)
        endpoint = endpoint_cache.get(eid)

        detail = e.get("detail") or {}
        e["event"] = e.get("action", "")
        e["company_slug"] = company["slug"] if company else "—"
        e["actor"] = (actor.get("full_name") or actor.get("email")) if actor else "system"
        e["endpoint_hostname"] = endpoint["hostname"] if endpoint else None
        e["detail_summary"] = ", ".join(f"{k}={v}" for k, v in detail.items()) if detail else ""
    return entries


@bp.route("/admin/audit")
@login_required
@superadmin_required
def audit_log():
    company_id = request.args.get("company_id") or None
    event_type = request.args.get("event_type") or None
    entries = _enriched_audit_entries(company_id, event_type)

    if request.headers.get("HX-Request"):
        return render_template("superadmin/_audit_rows.html", entries=entries)

    companies = db.get_all_companies()
    return render_template("superadmin/audit.html", entries=entries, companies=companies)


@bp.route("/admin/audit/export")
@login_required
@superadmin_required
def export_audit():
    import csv
    import io
    from flask import Response

    company_id = request.args.get("company_id") or None
    event_type = request.args.get("event_type") or None
    entries = _enriched_audit_entries(company_id, event_type)

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Time", "Event", "Company", "Actor", "Endpoint", "Detail"])
    for e in entries:
        writer.writerow([
            e.get("created_at", ""), e.get("event", ""), e.get("company_slug", ""),
            e.get("actor", ""), e.get("endpoint_hostname") or "", e.get("detail_summary", ""),
        ])
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=warden-audit-log.csv"},
    )


@bp.route("/admin/companies/create", methods=["POST"])
@login_required
@superadmin_required
def create_company():
    slug = request.form.get("slug", "").strip().lower()
    name = request.form.get("name", "").strip()
    admin_email = request.form.get("admin_email", "").strip().lower()
    admin_name = request.form.get("admin_name", "").strip()

    if not slug or not name:
        return jsonify({"error": "Slug and name required"}), 400
    if not admin_email:
        return jsonify({"error": "Initial admin email required"}), 400

    import re
    if not re.match(r'^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$', slug):
        return jsonify({"error": "Invalid slug format"}), 400

    existing = db.get_company_by_slug(slug)
    if existing:
        return jsonify({"error": "Slug already in use"}), 409
    if db.get_admin_by_email(admin_email):
        return jsonify({"error": "That admin email is already in use"}), 409

    # Warden has no VPN — see agent/wireguard.py. `vpn_subnet` is a legacy
    # NOT-NULL column kept only so existing rows don't need a migration;
    # this just writes a unique internal placeholder, never shown or
    # editable in the UI.
    vpn_subnet = f"10.{10 + len(db.get_all_companies())}.0.0/24"
    company = db.create_company(slug, name, vpn_subnet, created_by_id=g.admin["id"])
    if company:
        db.ensure_company_subscription(company["id"])
    db.audit(None, g.admin["id"], "company_created", {"slug": slug, "name": name})

    # The form asks for this up front, but until now nothing actually
    # created the admin — a new company had no way to be logged into at
    # all short of a superadmin separately using /admin/users/create.
    import secrets as _secrets
    import string as _string
    alphabet = _string.ascii_letters + _string.digits
    generated_password = "".join(_secrets.choice(alphabet) for _ in range(20))
    admin = db.create_admin_user(
        email=admin_email,
        password_hash=_hash_password(generated_password),
        full_name=admin_name or admin_email,
        role="company_admin",
        company_id=company["id"] if company else None,
        created_by=g.admin["id"],
    )
    db.audit(company["id"] if company else None, g.admin["id"], "admin_user_created_by_superadmin",
             {"email": admin_email, "role": "company_admin"})

    if not request.headers.get("HX-Request"):
        from flask import flash
        flash(
            f"Company \"{name}\" created. Admin login — email: {admin_email}, "
            f"password: {generated_password} (copy this now, it won't be shown again).",
            "credential",
        )

    if request.headers.get("HX-Request"):
        companies = db.get_all_companies()
        for c in companies:
            endpoints = db.get_endpoints(c["id"])
            c["_endpoint_count"] = len(endpoints)
            c["_online_count"] = sum(1 for e in endpoints if e.get("status") == "online")
        return render_template("superadmin/companies.html", companies=companies)

    return redirect(url_for("superadmin.tenants"))


@bp.route("/admin/companies/<id>/toggle", methods=["POST"])
@login_required
@superadmin_required
def toggle_company(id):
    company = db.get_company_by_id(id)
    if not company:
        abort(404)

    new_active = not company["is_active"]
    db.update_company(id, {"is_active": new_active})
    db.audit(None, g.admin["id"], "company_toggled", {
        "company_id": str(id), "is_active": new_active,
    })

    if request.headers.get("HX-Request"):
        companies = db.get_all_companies()
        for c in companies:
            endpoints = db.get_endpoints(c["id"])
            c["_endpoint_count"] = len(endpoints)
            c["_online_count"] = sum(1 for e in endpoints if e.get("status") == "online")
        return render_template("superadmin/companies.html", companies=companies)

    return redirect(url_for("superadmin.index"))


@bp.route("/admin/companies/<company_id>/request-access", methods=["GET", "POST"])
@login_required
@superadmin_required
def request_access(company_id):
    """Superadmin's entry point for viewing a tenant's own console
    (company_required's gate — see middleware/auth.py) when they don't
    already have an active grant. GET shows the form / current grant
    status; POST creates a pending request for the tenant to
    approve/deny (see settings.py's access_grants routes)."""
    company = db.get_company_by_id(company_id)
    if not company:
        abort(404)

    if request.method == "POST":
        reason = request.form.get("reason", "").strip()
        if not reason:
            return jsonify({"error": "A reason is required"}), 400
        grant = db.create_access_grant_request(company_id, g.admin["id"], reason)
        db.audit(company_id, g.admin["id"], "tenant_access_requested", {"reason": reason})
        if request.headers.get("Accept", "").startswith("application/json"):
            return jsonify({"ok": True, "grant": grant})
        return redirect(url_for("superadmin.request_access", company_id=company_id))

    grants = db.list_access_grants(company_id)
    mine = [g_ for g_ in grants if str(g_.get("requested_by")) == str(g.admin["id"])]
    return render_template("superadmin/request_access.html", company=company, grants=mine)


@bp.route("/admin/companies/<company_id>/branches")
@login_required
@superadmin_required
def company_branches(company_id):
    companies = db.get_all_companies()
    company = next((c for c in companies if str(c["id"]) == company_id), None)
    if not company:
        abort(404)
    if not db.has_active_access_grant(company_id, g.admin["id"]):
        return redirect(url_for("superadmin.request_access", company_id=company_id))
    branches = db.get_branches(company_id)
    return render_template("superadmin/branches.html", company=company, branches=branches)


@bp.route("/admin/companies/<company_id>/branches/create", methods=["POST"])
@login_required
@superadmin_required
def create_branch(company_id):
    name = request.form.get("name", "").strip()
    city = request.form.get("city", "").strip()
    if not name:
        return jsonify({"error": "Branch name required"}), 400
    from services.entitlements import check_capacity
    capacity = check_capacity(company_id, "branches")
    if not capacity.allowed:
        return jsonify({"error": capacity.code, "message": capacity.message}), 403

    branch = db.create_branch(company_id, name, city)
    db.audit(None, g.admin["id"], "branch_created",
             {"company_id": company_id, "name": name})
    return jsonify({"ok": True, "branch_id": str(branch["id"]) if branch else None})


@bp.route("/admin/users")
@login_required
@superadmin_required
def users():
    all_admins = db.get_all_admins()
    companies = db.get_all_companies()
    company_map = {str(c["id"]): c for c in companies}
    allowed_company_ids = {
        str(c["id"]) for c in companies
        if db.has_active_access_grant(c["id"], g.admin["id"])
    }
    all_admins = [
        a for a in all_admins
        if not a.get("company_id") or str(a.get("company_id")) in allowed_company_ids
    ]
    for a in all_admins:
        a["_company"] = company_map.get(str(a.get("company_id")))
    visible_companies = [c for c in companies if str(c["id"]) in allowed_company_ids]
    return render_template("superadmin/users.html", admins=all_admins, companies=visible_companies)


@bp.route("/admin/users/create", methods=["POST"])
@login_required
@superadmin_required
def create_admin():
    email = request.form.get("email", "").strip().lower()
    full_name = request.form.get("full_name", "").strip()
    role = request.form.get("role", "company_admin").strip()
    company_id = request.form.get("company_id") or None
    password = request.form.get("password", "")

    destination = url_for("superadmin.users")
    wants_json = request.is_json or request.headers.get("Accept", "").startswith("application/json")

    def fail(message, status=400):
        if wants_json:
            return jsonify({"error": message}), status
        flash(message, "error")
        return redirect(destination)

    if not all([email, full_name, password]):
        return fail("Name, email and password are required.")
    if role not in {"superadmin", "company_admin"}:
        return fail("Select a valid administrator role.")
    if role == "superadmin":
        company_id = None
    elif not company_id or not db.get_company_by_id(company_id):
        return fail("A tenant is required for a tenant administrator.")
    elif not db.has_active_access_grant(company_id, g.admin["id"]):
        return fail("Tenant-approved support access is required.", 403)
    if company_id:
        from services.entitlements import check_capacity
        capacity = check_capacity(company_id, "admins")
        if not capacity.allowed:
            return fail(capacity.message, 403)
    if len(password) < 12:
        return fail("Password must be at least 12 characters.")

    existing = db.get_admin_by_email(email)
    if existing:
        return fail("Email is already in use.", 409)

    admin = db.create_admin_user(
        email=email,
        password_hash=_hash_password(password),
        full_name=full_name,
        role=role,
        company_id=company_id,
        created_by=g.admin["id"],
    )
    db.audit(None, g.admin["id"], "admin_user_created_by_superadmin",
             {"email": email, "role": role, "company_id": company_id})
    if wants_json:
        return jsonify({"ok": True, "admin_id": str(admin["id"]) if admin else None})
    flash(f"Administrator {email} created.", "success")
    return redirect(destination)


@bp.route("/admin/users/<admin_id>/toggle", methods=["POST"])
@login_required
@superadmin_required
def toggle_admin(admin_id):
    target = db.get_admin_by_id(admin_id)
    if not target:
        abort(404)
    if target.get("company_id") and not db.has_active_access_grant(
            target["company_id"], g.admin["id"]):
        abort(403)
    if str(target["id"]) == str(g.admin["id"]):
        flash("You cannot disable your own platform account.", "error")
        return redirect(url_for("superadmin.users"))
    active = not bool(target.get("is_active"))
    db.update_admin(admin_id, {"is_active": active, "failed_attempts": 0, "locked_until": None})
    if not active:
        db.revoke_all_tokens_for_admin(admin_id)
    db.audit(None, g.admin["id"], "admin_user_enabled" if active else "admin_user_disabled",
             {"target_email": target["email"], "platform_action": True})
    flash(f"{target['email']} {'enabled' if active else 'disabled'}.", "success")
    return redirect(url_for("superadmin.users"))


@bp.route("/admin/users/<admin_id>/reset-password", methods=["POST"])
@login_required
@superadmin_required
def reset_admin_password(admin_id):
    target = db.get_admin_by_id(admin_id)
    if not target:
        abort(404)
    if target.get("company_id") and not db.has_active_access_grant(
            target["company_id"], g.admin["id"]):
        abort(403)
    password = request.form.get("new_password", "")
    if len(password) < 12:
        flash("The new password must be at least 12 characters.", "error")
        return redirect(url_for("superadmin.users"))
    db.update_admin_password(admin_id, _hash_password(password))
    db.update_admin(admin_id, {"failed_attempts": 0, "locked_until": None})
    db.revoke_all_tokens_for_admin(admin_id)
    db.audit(None, g.admin["id"], "admin_password_reset",
             {"target_email": target["email"], "platform_action": True})
    flash(f"Password reset for {target['email']}; active sessions were revoked.", "success")
    return redirect(url_for("superadmin.users"))


@bp.route("/admin/build-requests")
@login_required
@superadmin_required
def build_requests():
    requests_list = db.get_pending_build_requests()
    return jsonify([dict(r) for r in requests_list])


# ── Firewall block list (app-level, see middleware/security.py) ──────────────

@bp.route("/admin/firewall")
@login_required
@superadmin_required
def firewall_list():
    return jsonify([dict(r) for r in db.list_blocked_ips()])


@bp.route("/admin/firewall/block", methods=["POST"])
@login_required
@superadmin_required
def firewall_block():
    body = request.get_json(silent=True) or {}
    ip = body.get("ip_address", "").strip()
    reason = body.get("reason", "").strip()
    expires_at = body.get("expires_at") or None
    if not ip:
        return jsonify({"error": "ip_address is required"}), 400
    row = db.block_ip(ip, reason, created_by=g.admin["id"], expires_at=expires_at)
    if not row:
        return jsonify({"error": "failed_to_block"}), 500
    db.audit(None, g.admin["id"], "firewall_ip_blocked", {"ip_address": ip, "reason": reason})
    return jsonify({"ok": True, "rule": row})


@bp.route("/admin/firewall/unblock", methods=["POST"])
@login_required
@superadmin_required
def firewall_unblock():
    body = request.get_json(silent=True) or {}
    ip = body.get("ip_address", "").strip()
    if not ip:
        return jsonify({"error": "ip_address is required"}), 400
    db.unblock_ip(ip)
    db.audit(None, g.admin["id"], "firewall_ip_unblocked", {"ip_address": ip})
    return jsonify({"ok": True})
