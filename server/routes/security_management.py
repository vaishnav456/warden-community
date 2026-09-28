"""Effective policy, network analysis and vulnerability management views."""

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for

import db
from middleware.auth import company_required, login_required, require_branch_scope, role_required
from services.effective_policy import resolve_effective_policy
from services.vulnerability_svc import build_findings, fetch_cisa_kev


bp = Blueprint("security_management", __name__)


def _scoped_endpoints():
    branch_id = g.admin.get("branch_id") if g.admin.get("role") == "branch_admin" else None
    if g.admin.get("role") == "branch_admin" and not branch_id:
        abort(403)
    return db.get_endpoints(g.company["id"], branch_id=branch_id)


@bp.route("/effective-policy")
@login_required
@company_required
def effective_policy():
    endpoints = _scoped_endpoints()
    assignments = db.get_policy_assignments(g.company["id"])
    endpoint_id = request.args.get("endpoint_id", "")
    endpoint = next((item for item in endpoints if str(item["id"]) == endpoint_id), None)
    resolution = resolve_effective_policy(endpoint, assignments) if endpoint else None
    return render_template(
        "security/effective_policy.html", endpoints=endpoints, assignments=assignments,
        templates=db.get_policy_templates(g.company["id"]), branches=db.get_branches(g.company["id"]),
        selected_endpoint=endpoint, resolution=resolution, active_page="effective_policy",
    )


@bp.route("/effective-policy/assignments", methods=["POST"])
@login_required
@company_required
@role_required("company_admin", "branch_admin")
def create_policy_assignment():
    template_id = request.form.get("template_id", "").strip()
    template = db.get_policy_template(template_id)
    if not template or str(template.get("company_id")) != str(g.company["id"]):
        abort(404)
    scope_type = request.form.get("scope_type", "").strip()
    scope_value = None
    if scope_type not in {"tenant", "branch", "tag", "endpoint"}:
        abort(400)
    if scope_type == "tenant":
        scope_value = None
    elif scope_type == "branch":
        scope_value = request.form.get("branch_id", "").strip()
    elif scope_type == "tag":
        scope_value = request.form.get("tag", "").strip()[:64]
    elif scope_type == "endpoint":
        scope_value = request.form.get("endpoint_id", "").strip()
    if scope_type != "tenant" and not scope_value:
        abort(400)
    if scope_type == "branch":
        branch = db.get_branch(scope_value)
        if not branch or str(branch.get("company_id")) != str(g.company["id"]):
            abort(404)
        require_branch_scope(scope_value)
    elif scope_type == "endpoint":
        endpoint = db.get_endpoint(scope_value)
        if not endpoint or str(endpoint.get("company_id")) != str(g.company["id"]):
            abort(404)
        require_branch_scope(endpoint.get("branch_id"))
    elif g.admin.get("role") == "branch_admin":
        # Organization/tag assignments can affect endpoints outside a branch admin's scope.
        abort(403)
    try:
        priority = int(request.form.get("priority", "0"))
    except ValueError:
        abort(400)
    if not -1000 <= priority <= 1000:
        abort(400)
    assignment = db.create_policy_assignment(
        g.company["id"], template_id, scope_type, scope_value, priority, g.admin["id"],
    )
    db.audit(g.company["id"], g.admin["id"], "policy_assignment_created", {
        "assignment_id": assignment["id"], "template_id": template_id,
        "scope_type": scope_type, "scope_value": scope_value, "priority": priority,
    })
    flash("Policy assignment created. Review its effective result before deployment.", "success")
    return redirect(url_for("security_management.effective_policy"))


@bp.route("/effective-policy/assignments/<assignment_id>", methods=["DELETE"])
@login_required
@company_required
@role_required("company_admin", "branch_admin")
def delete_policy_assignment(assignment_id):
    assignments = db.get_policy_assignments(g.company["id"])
    assignment = next((item for item in assignments if str(item["id"]) == assignment_id), None)
    if not assignment:
        abort(404)
    if g.admin.get("role") == "branch_admin":
        if assignment.get("scope_type") != "branch":
            abort(403)
        require_branch_scope(assignment.get("scope_value"))
    db.delete_policy_assignment(assignment_id, g.company["id"])
    db.audit(g.company["id"], g.admin["id"], "policy_assignment_deleted", {"assignment_id": assignment_id})
    return "", 204


@bp.route("/effective-policy/deploy", methods=["POST"])
@login_required
@company_required
@role_required("company_admin", "branch_admin")
def deploy_effective_policy():
    from policy_settings import validate_settings_dict
    endpoint_id = request.form.get("endpoint_id", "").strip()
    targets = _scoped_endpoints()
    if endpoint_id:
        targets = [endpoint for endpoint in targets if str(endpoint["id"]) == endpoint_id]
        if not targets:
            abort(404)
    assignments = db.get_policy_assignments(g.company["id"])
    queued = 0
    skipped_conflicts = 0
    for endpoint in targets:
        resolution = resolve_effective_policy(endpoint, assignments)
        if not resolution["settings"]:
            continue
        if resolution["conflicts"]:
            skipped_conflicts += 1
            continue
        try:
            validate_settings_dict(resolution["settings"])
        except ValueError:
            skipped_conflicts += 1
            continue
        payload = {
            "settings": resolution["settings"], "policy_version": resolution["fingerprint"],
            "effective_policy": True,
        }
        if db.create_job(g.company["id"], endpoint.get("branch_id"), endpoint["id"],
                         "PUSH_LOCAL_POLICY", payload, g.admin["id"]):
            queued += 1
    db.audit(g.company["id"], g.admin["id"], "effective_policy_deployed", {
        "endpoint_id": endpoint_id or None, "queued": queued,
        "skipped_conflicts": skipped_conflicts,
    })
    if skipped_conflicts:
        flash(f"Queued {queued}; skipped {skipped_conflicts} endpoint(s) with conflicts or invalid settings.", "warning")
    else:
        flash(f"Effective policy queued for {queued} endpoint(s).", "success")
    return redirect(url_for("security_management.effective_policy", endpoint_id=endpoint_id or None))


@bp.route("/network")
@login_required
@company_required
def network_analysis():
    endpoints = _scoped_endpoints()
    allowed = {str(endpoint["id"]) for endpoint in endpoints}
    flows = [flow for flow in db.get_network_flows(g.company["id"]) if str(flow["endpoint_id"]) in allowed]
    endpoint_names = {str(endpoint["id"]): endpoint.get("display_name") or endpoint["hostname"] for endpoint in endpoints}
    return render_template("security/network.html", endpoints=endpoints, flows=flows,
                           endpoint_names=endpoint_names, active_page="network")


@bp.route("/network/collect", methods=["POST"])
@login_required
@company_required
@role_required("company_admin", "branch_admin", "technician")
def collect_network():
    endpoint_id = request.form.get("endpoint_id", "").strip()
    targets = _scoped_endpoints()
    if endpoint_id:
        targets = [endpoint for endpoint in targets if str(endpoint["id"]) == endpoint_id]
        if not targets:
            abort(404)
    queued = 0
    for endpoint in targets:
        if endpoint.get("platform") != "windows":
            continue
        if db.create_job(g.company["id"], endpoint.get("branch_id"), endpoint["id"],
                         "COLLECT_NETWORK_FLOWS", {}, g.admin["id"]):
            queued += 1
    db.audit(g.company["id"], g.admin["id"], "network_flow_collection_queued", {"count": queued})
    flash(f"Network observation queued for {queued} endpoint(s).", "success")
    return redirect(url_for("security_management.network_analysis"))


@bp.route("/vulnerabilities")
@login_required
@company_required
def vulnerabilities():
    endpoints = _scoped_endpoints()
    allowed = {str(endpoint["id"]) for endpoint in endpoints}
    status_filter = request.args.get("status", "open")
    if status_filter not in {"open", "accepted", "remediated", "false_positive", "all"}:
        status_filter = "open"
    findings = [row for row in db.get_vulnerability_findings(
                    g.company["id"], status=None if status_filter == "all" else status_filter)
                if str(row.get("endpoint_id")) in allowed]
    stats = {
        "open": sum(row.get("status") == "open" for row in findings),
        "exploited": sum(bool((row.get("vulnerability_advisories") or {}).get("known_exploited")) and row.get("status") == "open" for row in findings),
        "exact": sum(row.get("confidence") == "exact" and row.get("status") == "open" for row in findings),
        "potential": sum(row.get("confidence") == "potential" and row.get("status") == "open" for row in findings),
    }
    return render_template("security/vulnerabilities.html", findings=findings, stats=stats,
                           endpoints=endpoints, status_filter=status_filter, active_page="vulnerabilities")


@bp.route("/vulnerabilities/sync-kev", methods=["POST"])
@login_required
@company_required
@role_required("company_admin")
def sync_kev():
    rows = fetch_cisa_kev()
    db.upsert_vulnerability_advisories(rows)
    db.audit(g.company["id"], g.admin["id"], "vulnerability_feed_synced", {"source": "CISA KEV", "count": len(rows)})
    flash(f"CISA Known Exploited Vulnerabilities feed updated: {len(rows)} advisories.", "success")
    return redirect(url_for("security_management.vulnerabilities"))


@bp.route("/vulnerabilities/scan", methods=["POST"])
@login_required
@company_required
@role_required("company_admin", "branch_admin", "technician")
def scan_vulnerabilities():
    endpoint_id = request.form.get("endpoint_id", "").strip()
    targets = _scoped_endpoints()
    if endpoint_id:
        targets = [endpoint for endpoint in targets if str(endpoint["id"]) == endpoint_id]
        if not targets:
            abort(404)
    advisories = db.get_vulnerability_advisories()
    total = 0
    for endpoint in targets:
        software = db.get_software(endpoint["id"], limit=5000)
        findings = build_findings(software, advisories)
        db.replace_vulnerability_findings(g.company["id"], endpoint["id"], findings)
        total += len(findings)
    db.audit(g.company["id"], g.admin["id"], "vulnerability_scan_completed", {
        "endpoints": len(targets), "matches": total,
    })
    flash(f"Scanned {len(targets)} endpoint(s); {total} evidence-backed matches found.", "success")
    return redirect(url_for("security_management.vulnerabilities"))


@bp.route("/vulnerabilities/<finding_id>/status", methods=["POST"])
@login_required
@company_required
@role_required("company_admin", "branch_admin", "technician")
def set_vulnerability_status(finding_id):
    status = request.form.get("status", "").strip()
    if status not in {"open", "accepted", "remediated", "false_positive"}:
        abort(400)
    finding = db.get_vulnerability_finding(finding_id)
    if not finding or str(finding.get("company_id")) != str(g.company["id"]):
        abort(404)
    endpoint = db.get_endpoint(finding["endpoint_id"])
    if not endpoint:
        abort(404)
    require_branch_scope(endpoint.get("branch_id"))
    db.update_vulnerability_finding(finding_id, status)
    db.audit(g.company["id"], g.admin["id"], "vulnerability_finding_status_changed", {
        "finding_id": finding_id, "status": status,
    }, endpoint_id=endpoint["id"])
    flash("Finding status updated.", "success")
    if request.form.get("return_to_endpoint") == "1":
        return redirect(url_for("endpoints.detail", endpoint_id=endpoint["id"], tab="software"))
    return redirect(url_for("security_management.vulnerabilities"))
