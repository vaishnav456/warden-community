"""
Warden — Compliance routes
Policy management, compliance scan dispatch, and result views.
"""
from flask import Blueprint, render_template, request, jsonify, g, abort

import db
from middleware.auth import login_required, company_required, role_required, require_branch_scope

bp = Blueprint("compliance", __name__)

ALL_CHECKS = [
    "bitlocker_enabled",
    "firewall_enabled",
    "antivirus_present",
    "screen_lock_enabled",
    "auto_update_enabled",
    "password_min_length",
    "guest_account_disabled",
    "disk_encryption_enabled",
]
CHECKS_BY_PLATFORM = {
    "windows": set(ALL_CHECKS) - {"disk_encryption_enabled"},
    "linux": {"firewall_enabled"},
    "darwin": {"firewall_enabled", "disk_encryption_enabled"},
}
VALID_CHECKS = set(ALL_CHECKS) | {"disk_encryption_enabled"}


def _validated_checks(value):
    if not isinstance(value, list) or not value:
        return None
    names = []
    for item in value:
        name = item.get("check") if isinstance(item, dict) else item
        enabled = item.get("enabled", True) if isinstance(item, dict) else True
        if not isinstance(name, str) or name not in VALID_CHECKS:
            return None
        if enabled and name not in names:
            names.append(name)
    return names or None


def _checks_for_endpoint(endpoint, policy):
    platform = str(endpoint.get("platform") or "windows").lower()
    supported = CHECKS_BY_PLATFORM.get(platform, set())
    if policy:
        requested = _validated_checks(policy.get("checks") or []) or []
        return [check for check in requested if check in supported]
    return [check for check in ALL_CHECKS if check in supported] or sorted(supported)


@bp.route("/compliance")
@login_required
@company_required
def index():
    company_id = g.company["id"]
    policies = db.get_compliance_policies(company_id)
    branches = db.get_branches(company_id)
    endpoints = db.get_endpoints(company_id)
    results = db.get_compliance_results_for_company(company_id)
    if g.admin.get("role") == "branch_admin":
        branch_id = g.admin.get("branch_id")
        if not branch_id:
            abort(403)
        policies = [
            p for p in policies
            if p.get("branch_id") is None or str(p.get("branch_id")) == str(branch_id)
        ]
        branches = [b for b in branches if str(b.get("id")) == str(branch_id)]
        endpoints = [e for e in endpoints if str(e.get("branch_id")) == str(branch_id)]
        endpoint_ids = {str(e["id"]) for e in endpoints}
        results = [r for r in results if str(r.get("endpoint_id")) in endpoint_ids]
    result_map = {str(r["endpoint_id"]): r for r in results}
    return render_template(
        "compliance/index.html",
        policies=policies,
        branches=branches,
        endpoints=endpoints,
        results=results,
        result_map=result_map,
        all_checks=ALL_CHECKS,
        active_page="compliance",
    )


@bp.route("/compliance/policies", methods=["POST"])
@login_required
@company_required
@role_required("company_admin")
def create_policy():
    company_id = g.company["id"]
    body = request.get_json(silent=True) or {}

    if not isinstance(body, dict) or not isinstance(body.get("name", ""), str) or not isinstance(body.get("description", ""), str):
        return jsonify({"error": "name and description must be strings"}), 400

    name = (body.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400

    description = (body.get("description") or "").strip()
    branch_id = body.get("branch_id") or None
    checks = body.get("checks") or []
    checks = _validated_checks(checks)
    if checks is None:
        return jsonify({"error": "checks must contain one or more supported compliance checks"}), 400
    from services.entitlements import check_mutation
    decision = check_mutation(company_id)
    if not decision.allowed:
        return jsonify({"error": decision.code, "message": decision.message}), 403

    # Validate branch ownership if provided
    if branch_id:
        branch = db.get_branch(branch_id)
        if not branch or str(branch["company_id"]) != str(company_id):
            return jsonify({"error": "branch not found"}), 404

    policy = db.create_compliance_policy(
        company_id=company_id,
        branch_id=branch_id,
        name=name,
        description=description,
        checks=checks,
        created_by=g.admin["id"],
    )

    db.audit(company_id, g.admin["id"], "compliance_policy_created", {
        "policy_id": str(policy["id"]),
        "name": name,
    })

    return jsonify({"ok": True, "policy_id": str(policy["id"])})


@bp.route("/compliance/policies/<policy_id>/update", methods=["POST"])
@login_required
@company_required
@role_required("company_admin")
def update_policy(policy_id):
    company_id = g.company["id"]

    policy = db.get_compliance_policy(policy_id)
    if not policy or str(policy["company_id"]) != str(company_id):
        abort(404)

    body = request.get_json(silent=True) or {}

    if not isinstance(body, dict) or not isinstance(body.get("name", ""), str) or not isinstance(body.get("description", ""), str):
        return jsonify({"error": "name and description must be strings"}), 400
    if "enabled" in body and not isinstance(body["enabled"], bool):
        return jsonify({"error": "enabled must be a boolean"}), 400

    name = (body.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400

    description = (body.get("description") or "").strip()
    checks = body.get("checks") or []
    checks = _validated_checks(checks)
    if checks is None:
        return jsonify({"error": "checks must contain one or more supported compliance checks"}), 400
    from services.entitlements import check_mutation
    decision = check_mutation(company_id)
    if not decision.allowed:
        return jsonify({"error": decision.code, "message": decision.message}), 403
    enabled = body.get("enabled", policy.get("enabled", True))

    db.update_compliance_policy(
        policy_id=policy_id,
        name=name,
        description=description,
        checks=checks,
        enabled=enabled,
    )

    db.audit(company_id, g.admin["id"], "compliance_policy_updated", {
        "policy_id": str(policy_id),
        "name": name,
    })

    return jsonify({"ok": True})


@bp.route("/compliance/policies/<policy_id>/delete", methods=["POST"])
@login_required
@company_required
@role_required("company_admin")
def delete_policy(policy_id):
    company_id = g.company["id"]
    from services.entitlements import check_mutation
    decision = check_mutation(company_id)
    if not decision.allowed:
        return jsonify({"error": decision.code, "message": decision.message}), 403

    policy = db.get_compliance_policy(policy_id)
    if not policy or str(policy["company_id"]) != str(company_id):
        abort(404)

    db.delete_compliance_policy(policy_id)

    db.audit(company_id, g.admin["id"], "compliance_policy_deleted", {
        "policy_id": str(policy_id),
        "name": policy.get("name"),
    })

    return jsonify({"ok": True})


@bp.route("/compliance/scan/<endpoint_id>", methods=["POST"])
@login_required
@company_required
@role_required("company_admin", "branch_admin", "technician")
def scan_endpoint(endpoint_id):
    company_id = g.company["id"]

    endpoint = db.get_endpoint(endpoint_id)
    if not endpoint or str(endpoint["company_id"]) != str(company_id):
        abort(404)
    require_branch_scope(endpoint.get("branch_id"))
    from services.entitlements import check_job
    decision = check_job(company_id, "COMPLIANCE_SCAN")
    if not decision.allowed:
        return jsonify({"error": decision.code, "message": decision.message}), 403
    capabilities = set(endpoint.get("capabilities") or [])
    if capabilities and "COMPLIANCE_SCAN" not in capabilities:
        return jsonify({"error": "operation_not_supported"}), 409

    endpoint_branch_id = endpoint.get("branch_id")

    # Find the first enabled policy that applies to this endpoint:
    # prefer a policy whose branch_id matches, then fall back to a company-wide policy (branch_id=None)
    policies = db.get_compliance_policies(company_id)
    matched_policy = None
    fallback_policy = None

    for p in policies:
        if not p.get("enabled", True):
            continue
        p_branch = p.get("branch_id")
        if p_branch is None:
            if fallback_policy is None:
                fallback_policy = p
        elif str(p_branch) == str(endpoint_branch_id):
            matched_policy = p
            break

    active_policy = matched_policy or fallback_policy

    if active_policy:
        check_names = _checks_for_endpoint(endpoint, active_policy)
        policy_id = str(active_policy["id"])
    else:
        check_names = _checks_for_endpoint(endpoint, None)
        policy_id = None
    if not check_names:
        return jsonify({"error": "policy_has_no_checks_for_platform"}), 409

    payload = {
        "policy_id": policy_id,
        "checks": check_names,
    }
    from services.compliance_state import fingerprint
    payload["policy_fingerprint"] = fingerprint(endpoint, active_policy)

    job = db.create_job(
        company_id=company_id,
        branch_id=endpoint_branch_id,
        endpoint_id=endpoint_id,
        job_type="COMPLIANCE_SCAN",
        payload=payload,
        created_by=g.admin["id"],
    )

    db.audit(company_id, g.admin["id"], "compliance_scan_dispatched", {
        "endpoint_id": endpoint_id,
        "policy_id": policy_id,
        "checks": check_names,
        "job_id": str(job["id"]) if job else None,
    }, endpoint_id=endpoint_id)

    return jsonify({"ok": True, "job_id": str(job["id"]) if job else None})


@bp.route("/compliance/scan-all", methods=["POST"])
@login_required
@company_required
@role_required("company_admin", "branch_admin")
def scan_all():
    company_id = g.company["id"]
    from services.entitlements import check_job
    decision = check_job(company_id, "COMPLIANCE_SCAN")
    if not decision.allowed:
        return jsonify({"error": decision.code, "message": decision.message}), 403
    body = request.get_json(silent=True) or {}
    branch_id = body.get("branch_id") or None

    if g.admin.get("role") == "branch_admin":
        admin_branch_id = g.admin.get("branch_id")
        if not admin_branch_id:
            abort(403)
        branch_id = str(admin_branch_id)

    if branch_id:
        branch = db.get_branch(branch_id)
        if not branch or str(branch["company_id"]) != str(company_id):
            return jsonify({"error": "branch not found"}), 404

    endpoints = db.get_endpoints(company_id, branch_id=branch_id)
    online_endpoints = [e for e in endpoints if e.get("status") == "online"]

    policies = db.get_compliance_policies(company_id)
    enabled_policies = [p for p in policies if p.get("enabled", True)]

    dispatched = 0
    skipped = 0
    for ep in online_endpoints:
        ep_id = ep["id"]
        ep_branch_id = ep.get("branch_id")

        # Same policy-matching logic: branch-specific first, then company-wide
        matched_policy = None
        fallback_policy = None
        for p in enabled_policies:
            p_branch = p.get("branch_id")
            if p_branch is None:
                if fallback_policy is None:
                    fallback_policy = p
            elif str(p_branch) == str(ep_branch_id):
                matched_policy = p
                break

        active_policy = matched_policy or fallback_policy

        if active_policy:
            check_names = _checks_for_endpoint(ep, active_policy)
            policy_id = str(active_policy["id"])
        else:
            check_names = _checks_for_endpoint(ep, None)
            policy_id = None

        capabilities = set(ep.get("capabilities") or [])
        if (capabilities and "COMPLIANCE_SCAN" not in capabilities) or not check_names:
            skipped += 1
            continue

        payload = {"policy_id": policy_id, "checks": check_names}
        from services.compliance_state import fingerprint
        payload["policy_fingerprint"] = fingerprint(ep, active_policy)

        created = db.create_job(
            company_id=company_id,
            branch_id=ep_branch_id,
            endpoint_id=ep_id,
            job_type="COMPLIANCE_SCAN",
            payload=payload,
            created_by=g.admin["id"],
        )
        if created:
            dispatched += 1
        else:
            skipped += 1

    db.audit(company_id, g.admin["id"], "compliance_scan_all_dispatched", {
        "branch_id": branch_id,
        "dispatched": dispatched,
    })

    return jsonify({"ok": True, "dispatched": dispatched, "skipped": skipped})
