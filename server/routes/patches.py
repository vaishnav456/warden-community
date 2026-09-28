"""Windows patch visibility and deployment console."""

from collections import defaultdict
from datetime import datetime, timezone

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for

import db
from middleware.auth import company_required, login_required, require_branch_scope, role_required
from services.patch_rollout import assign_rings, endpoint_in_scope


bp = Blueprint("patches", __name__)


@bp.route("/patches")
@login_required
@company_required
def index():
    company_id = g.company["id"]
    endpoints = db.get_endpoints(company_id)
    if g.admin.get("role") == "branch_admin":
        branch_id = g.admin.get("branch_id")
        if not branch_id:
            abort(403)
        endpoints = [
            endpoint for endpoint in endpoints
            if str(endpoint.get("branch_id")) == str(branch_id)
        ]

    windows_endpoints = [
        endpoint for endpoint in endpoints
        if str(endpoint.get("platform") or "windows").lower() == "windows"
    ]
    allowed_ids = {str(endpoint["id"]) for endpoint in windows_endpoints}
    patches = [
        patch for patch in db.get_patch_inventory(company_id)
        if str(patch.get("endpoint_id")) in allowed_ids
    ]
    by_endpoint = defaultdict(list)
    for patch in patches:
        by_endpoint[str(patch["endpoint_id"])].append(patch)

    critical_labels = {"critical", "important"}
    critical_count = sum(
        1 for patch in patches
        if str(patch.get("severity") or "").lower() in critical_labels
    )
    reboot_count = len({
        str(patch["endpoint_id"]) for patch in patches if patch.get("reboot_required")
    })
    scanned_count = sum(1 for endpoint in windows_endpoints if by_endpoint[str(endpoint["id"])])

    return render_template(
        "patches/index.html",
        endpoints=windows_endpoints,
        patches=patches,
        patches_by_endpoint=dict(by_endpoint),
        critical_count=critical_count,
        reboot_count=reboot_count,
        scanned_count=scanned_count,
        patch_policies=db.get_patch_policies(company_id),
        deployments=db.get_patch_deployments(company_id),
        branches=db.get_branches(company_id),
        active_page="patches",
    )


@bp.route("/patches/policies", methods=["POST"])
@login_required
@company_required
@role_required("company_admin", "branch_admin")
def create_policy():
    name = request.form.get("name", "").strip()[:120]
    scope_type = request.form.get("scope_type", "").strip()
    if not name or scope_type not in {"tenant", "branch", "tag", "endpoints"}:
        abort(400)
    if scope_type == "tenant":
        scope_value = None
    elif scope_type == "endpoints":
        scope_value = list(dict.fromkeys(request.form.getlist("endpoint_ids")))
        if not scope_value:
            abort(400)
    elif scope_type == "branch":
        scope_value = request.form.get("branch_id", "").strip()
        if not scope_value:
            abort(400)
    else:
        scope_value = request.form.get("tag", "").strip()[:64]
        if not scope_value:
            abort(400)
    if scope_type == "branch":
        branch = db.get_branch(scope_value)
        if not branch or str(branch.get("company_id")) != str(g.company["id"]):
            abort(404)
        require_branch_scope(scope_value)
    elif g.admin.get("role") == "branch_admin":
        abort(403)
    allowed_severities = {"Critical", "Important", "Moderate", "Low", "Unspecified"}
    severities = [value for value in request.form.getlist("severities") if value in allowed_severities]
    if not severities:
        abort(400)
    try:
        pilot = int(request.form.get("pilot_percentage", "10"))
        broad_after = int(request.form.get("broad_after_hours", "24"))
        deadline = int(request.form.get("deadline_hours", "168"))
    except ValueError:
        abort(400)
    if not 1 <= pilot <= 100 or not 0 <= broad_after <= 720 or not 1 <= deadline <= 2160 or broad_after > deadline:
        abort(400)
    reboot = request.form.get("reboot_mode", "notify")
    if reboot not in {"never", "notify", "force_at_deadline"}:
        abort(400)
    policy = db.create_patch_policy({
        "company_id": g.company["id"], "name": name, "scope_type": scope_type,
        "scope_value": scope_value, "severities": severities,
        "pilot_percentage": pilot, "broad_after_hours": broad_after,
        "deadline_hours": deadline, "reboot_mode": reboot, "created_by": g.admin["id"],
    })
    db.audit(g.company["id"], g.admin["id"], "patch_policy_created", {"policy_id": policy["id"], "name": name})
    flash("Patch policy created.", "success")
    return redirect(url_for("patches.index"))


@bp.route("/patches/policies/<policy_id>/deploy", methods=["POST"])
@login_required
@company_required
@role_required("company_admin", "branch_admin")
def deploy_policy(policy_id):
    policy = db.get_patch_policy(policy_id)
    if not policy or str(policy.get("company_id")) != str(g.company["id"]):
        abort(404)
    if policy.get("scope_type") == "branch":
        require_branch_scope(policy.get("scope_value"))
    elif g.admin.get("role") == "branch_admin":
        abort(403)
    endpoints = [endpoint for endpoint in db.get_endpoints(g.company["id"])
                 if endpoint.get("platform") == "windows" and endpoint_in_scope(endpoint, policy)]
    deployment_seed = f"{policy_id}:{datetime.now(timezone.utc).strftime('%Y%m%d%H%M')}"
    rings = assign_rings(endpoints, deployment_seed, policy["pilot_percentage"])
    payload = {
        "action": "install", "severities": policy.get("severities") or [],
        "reboot_mode": policy.get("reboot_mode") or "notify",
        "policy_id": str(policy_id),
    }
    deployment_id = db.create_patch_deployment(
        g.company, policy, [item["id"] for item in rings["pilot"]],
        [item["id"] for item in rings["broad"]], payload, g.admin["id"],
    )
    db.audit(g.company["id"], g.admin["id"], "patch_deployment_started", {
        "deployment_id": deployment_id, "policy_id": policy_id,
        "pilot": len(rings["pilot"]), "broad": len(rings["broad"]),
    })
    flash(f"Patch rollout started: {len(rings['pilot'])} pilot and {len(rings['broad'])} broad-ring endpoints.", "success")
    return redirect(url_for("patches.index"))
