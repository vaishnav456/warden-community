"""
Warden — Scheduled jobs routes
Create, toggle, delete, and manually trigger recurring scheduled jobs.
"""
from flask import Blueprint, render_template, request, jsonify, g, abort

import db
from middleware.auth import login_required, company_required, role_required, require_branch_scope

bp = Blueprint("schedule", __name__)

VALID_SCHEDULED_JOB_TYPES = [
    "COLLECT_SYSINFO", "COLLECT_SOFTWARE", "COLLECT_USERS",
    "COMPLIANCE_SCAN", "GET_EVENT_LOGS", "CHECK_POLICY_DRIFT", "WINDOWS_UPDATE",
]

@bp.route("/schedule")
@login_required
@company_required
def index():
    company_id = g.company["id"]
    jobs = db.get_scheduled_jobs(company_id)
    if g.admin.get("role") == "branch_admin":
        jobs = [j for j in jobs if str(j.get("branch_id")) == str(g.admin.get("branch_id"))]
    branches = db.get_branches(company_id)
    endpoints = db.get_endpoints(company_id)
    return render_template(
        "schedule/index.html",
        jobs=jobs,
        branches=branches,
        endpoints=endpoints,
        valid_job_types=VALID_SCHEDULED_JOB_TYPES,
        active_page="schedule",
    )


@bp.route("/schedule/create", methods=["POST"])
@login_required
@company_required
@role_required("superadmin", "company_admin", "branch_admin")
def create_job():
    company_id = g.company["id"]
    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict):
        return jsonify({"error": "request body must be a JSON object"}), 400

    name = (body.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400
    if len(name) > 120:
        return jsonify({"error": "name must be 120 characters or fewer"}), 400

    job_type = (body.get("job_type") or "").strip()
    if job_type not in VALID_SCHEDULED_JOB_TYPES:
        return jsonify({"error": f"job_type must be one of {VALID_SCHEDULED_JOB_TYPES}"}), 400
    from services.entitlements import check_job
    decision = check_job(company_id, job_type)
    if not decision.allowed:
        return jsonify({"error": decision.code, "message": decision.message}), 403

    try:
        interval_seconds = int(body.get("interval_seconds", 0))
    except (TypeError, ValueError):
        return jsonify({"error": "interval_seconds must be an integer"}), 400

    if interval_seconds < 3600 or interval_seconds > 31536000:
        return jsonify({"error": "interval_seconds must be between 3600 and 31536000"}), 400

    branch_id = body.get("branch_id") or None
    endpoint_id = body.get("endpoint_id") or None
    payload = body.get("payload") or {}
    if not isinstance(payload, dict):
        return jsonify({"error": "payload must be a JSON object"}), 400

    if g.admin.get("role") == "branch_admin":
        admin_branch_id = g.admin.get("branch_id")
        if not admin_branch_id:
            abort(403)
        # A branch_admin can't create a company-wide (branch_id=None) or
        # other-branch scheduled job — force it to their own branch rather
        # than just validating it, the same way bulk_dispatch does.
        branch_id = str(admin_branch_id)
        if endpoint_id:
            ep = db.get_endpoint(endpoint_id)
            if not ep or str(ep.get("branch_id")) != str(admin_branch_id):
                return jsonify({"error": "endpoint not found"}), 404

    # Validate branch ownership if provided
    if branch_id:
        branch = db.get_branch(branch_id)
        if not branch or str(branch["company_id"]) != str(company_id):
            return jsonify({"error": "branch not found"}), 404

    # Validate endpoint ownership if provided
    if endpoint_id:
        endpoint = db.get_endpoint(endpoint_id)
        if not endpoint or str(endpoint["company_id"]) != str(company_id):
            return jsonify({"error": "endpoint not found"}), 404
        if branch_id and str(endpoint.get("branch_id")) != str(branch_id):
            return jsonify({"error": "endpoint does not belong to branch"}), 400

    job = db.create_scheduled_job(
        company_id=company_id,
        branch_id=branch_id,
        endpoint_id=endpoint_id,
        name=name,
        job_type=job_type,
        payload=payload,
        interval_seconds=interval_seconds,
        created_by=g.admin["id"],
    )

    db.audit(company_id, g.admin["id"], "scheduled_job_created", {
        "job_id": str(job["id"]),
        "name": name,
        "job_type": job_type,
        "interval_seconds": interval_seconds,
    })

    return jsonify({"ok": True, "id": str(job["id"])})


@bp.route("/schedule/<job_id>/toggle", methods=["POST"])
@login_required
@company_required
@role_required("superadmin", "company_admin", "branch_admin")
def toggle_job(job_id):
    company_id = g.company["id"]
    from services.entitlements import check_mutation
    decision = check_mutation(company_id)
    if not decision.allowed:
        return jsonify({"error": decision.code, "message": decision.message}), 403

    job = db.get_scheduled_job(job_id)
    if not job or str(job["company_id"]) != str(company_id):
        abort(404)
    require_branch_scope(job.get("branch_id"))

    new_enabled = not job["enabled"]
    db.update_scheduled_job(job_id=job_id, enabled=new_enabled)

    db.audit(company_id, g.admin["id"], "scheduled_job_toggled", {
        "job_id": str(job_id),
        "name": job.get("name"),
        "enabled": new_enabled,
    })

    return jsonify({"ok": True, "enabled": new_enabled})


@bp.route("/schedule/<job_id>/delete", methods=["POST"])
@login_required
@company_required
@role_required("superadmin", "company_admin", "branch_admin")
def delete_job(job_id):
    company_id = g.company["id"]
    from services.entitlements import check_mutation
    decision = check_mutation(company_id)
    if not decision.allowed:
        return jsonify({"error": decision.code, "message": decision.message}), 403

    job = db.get_scheduled_job(job_id)
    if not job or str(job["company_id"]) != str(company_id):
        abort(404)
    require_branch_scope(job.get("branch_id"))

    db.delete_scheduled_job(job_id)

    db.audit(company_id, g.admin["id"], "scheduled_job_deleted", {
        "job_id": str(job_id),
        "name": job.get("name"),
    })

    return jsonify({"ok": True})


@bp.route("/schedule/<job_id>/run-now", methods=["POST"])
@login_required
@company_required
@role_required("superadmin", "company_admin", "branch_admin", "technician")
def run_now(job_id):
    """
    Immediately dispatch the scheduled job to its target endpoints.
    Target resolution mirrors services/scheduler.py _dispatch_job():
      - endpoint_id set → that single endpoint (regardless of status)
      - branch_id set  → all online endpoints in that branch
      - neither        → all online endpoints in the company
    """
    company_id = g.company["id"]

    job = db.get_scheduled_job(job_id)
    if not job or str(job["company_id"]) != str(company_id):
        abort(404)
    require_branch_scope(job.get("branch_id"))

    branch_id = job.get("branch_id")
    job_type = job["job_type"]
    payload = job.get("payload") or {}
    from services.entitlements import check_job
    decision = check_job(company_id, job_type)
    if not decision.allowed:
        return jsonify({"error": decision.code, "message": decision.message}), 403

    # Resolve targets (same logic as scheduler._dispatch_job)
    if job.get("endpoint_id"):
        ep = db.get_endpoint(job["endpoint_id"])
        targets = [ep] if ep else []
    elif branch_id:
        targets = [
            e for e in db.get_endpoints(company_id, branch_id=branch_id)
            if e.get("status") == "online"
        ]
    else:
        targets = [
            e for e in db.get_endpoints(company_id)
            if e.get("status") == "online"
        ]

    dispatched = 0
    skipped = 0
    for ep in targets:
        capabilities = set(ep.get("capabilities") or [])
        if capabilities and job_type not in capabilities:
            skipped += 1
            continue
        created = db.create_job(
            company_id,
            ep.get("branch_id"),
            ep["id"],
            job_type,
            payload,
            created_by=g.admin["id"],
        )
        if created:
            dispatched += 1
        else:
            skipped += 1

    db.audit(company_id, g.admin["id"], "scheduled_job_run_now", {
        "job_id": str(job_id),
        "name": job.get("name"),
        "dispatched": dispatched,
    })

    return jsonify({"ok": True, "dispatched": dispatched, "skipped": skipped})
