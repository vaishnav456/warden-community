"""
Warden — Jobs routes
Job list, detail with live log streaming, retry, cancel.
"""
import json
from datetime import datetime, timedelta, timezone
from flask import Blueprint, render_template, request, jsonify, g, abort, Response

import db
from services.dashboard_view import selected_branch, scoped_url
from middleware.auth import login_required, company_required, require_branch_scope

bp = Blueprint("jobs", __name__)


def _since():
    return (datetime.now(timezone.utc) - timedelta(days=1)).isoformat() if request.args.get("window") == "24h" else None


@bp.route("/jobs")
@login_required
@company_required
def list_jobs():
    company_id = g.company["id"]
    endpoint_id = request.args.get("endpoint_id")
    status = request.args.get("status")
    branch_id = selected_branch()
    try:
        page = max(1, int(request.args.get("page", 1)))
    except (TypeError, ValueError):
        page = 1
    limit = 30
    offset = (page - 1) * limit

    jobs = db.get_jobs(company_id, endpoint_id=endpoint_id, status=status, branch_id=branch_id,
                       limit=limit, offset=offset, created_since=_since())

    # Enrich with endpoint info
    endpoint_cache = {}
    for j in jobs:
        eid = j.get("endpoint_id")
        if eid and eid not in endpoint_cache:
            endpoint_cache[eid] = db.get_endpoint(eid)
        j["_endpoint"] = endpoint_cache.get(eid)

    return render_template(
        "jobs/list.html",
        jobs=jobs,
        status_filter=status,
        endpoint_id=endpoint_id,
        page=page,
        has_more=len(jobs) == limit,
        scoped_url=lambda path, **filters: scoped_url(path, branch_id, **filters),
        selected_branch=branch_id, time_window=request.args.get("window", ""),
    )


@bp.route("/partials/jobs-table")
@login_required
@company_required
def jobs_table_partial():
    endpoint_id = request.args.get("endpoint_id")
    status = request.args.get("status") or None
    branch_id = selected_branch()
    jobs = db.get_jobs(g.company["id"], endpoint_id=endpoint_id, status=status,
                       branch_id=branch_id, limit=30, created_since=_since())
    endpoint_cache = {}
    for job in jobs:
        endpoint_key = job.get("endpoint_id")
        if endpoint_key and endpoint_key not in endpoint_cache:
            endpoint_cache[endpoint_key] = db.get_endpoint(endpoint_key)
        job["_endpoint"] = endpoint_cache.get(endpoint_key)
    return render_template("partials/jobs_table_rows.html", jobs=jobs)


@bp.route("/jobs/<job_id>")
@login_required
@company_required
def detail(job_id):
    job = db.get_job(job_id)
    if not job or str(job["company_id"]) != str(g.company["id"]):
        abort(404)
    require_branch_scope(job.get("branch_id"))
    endpoint = db.get_endpoint(job["endpoint_id"]) if job.get("endpoint_id") else None
    output_data = None
    if job.get("log_output"):
        try:
            output_data = json.loads(job["log_output"])
        except (TypeError, ValueError, json.JSONDecodeError):
            pass
    # Never render base64 file contents in an admin page. The dedicated
    # download endpoint is the correct presentation for those bytes.
    if isinstance(output_data, dict) and "content_b64" in output_data:
        encoded = output_data.pop("content_b64") or ""
        output_data["content"] = f"Binary transfer payload ({len(encoded):,} encoded characters)"
    payload_data = dict(job.get("payload") or {})
    if "content_b64" in payload_data:
        encoded = payload_data.pop("content_b64") or ""
        payload_data["content"] = f"Binary transfer payload ({len(encoded):,} encoded characters)"
    return render_template(
        "jobs/detail.html", job=job, endpoint=endpoint,
        output_data=output_data, payload_data=payload_data,
    )


@bp.route("/partials/job-log/<job_id>")
@login_required
@company_required
def job_log_partial(job_id):
    """HTMX partial — live log polling for running jobs."""
    job = db.get_job(job_id)
    if not job or str(job["company_id"]) != str(g.company["id"]):
        abort(404)
    require_branch_scope(job.get("branch_id"))
    html = render_template("partials/job_log.html", job=job)
    # HTMX treats 286 as a normal response that also stops a polling trigger.
    # Without this, every completed job detail kept issuing a request every
    # three seconds for as long as the page remained open.
    status = 200 if job.get("status") == "running" else 286
    return Response(html, status=status, mimetype="text/html")


@bp.route("/partials/job-status/<job_id>")
@login_required
@company_required
def job_status_partial(job_id):
    job = db.get_job(job_id)
    if not job or str(job.get("company_id")) != str(g.company["id"]):
        abort(404)
    require_branch_scope(job.get("branch_id"))
    endpoint = db.get_endpoint(job["endpoint_id"]) if job.get("endpoint_id") else None
    return render_template("partials/job_status_card.html", job=job, endpoint=endpoint)


@bp.route("/jobs/<job_id>/cancel", methods=["POST"])
@login_required
@company_required
def cancel(job_id):
    job = db.get_job(job_id)
    if not job or str(job["company_id"]) != str(g.company["id"]):
        abort(404)
    require_branch_scope(job.get("branch_id"))
    if job["status"] not in ("pending", "approved"):
        return jsonify({"error": "Job cannot be cancelled in current state"}), 400

    if not db.cancel_job(job_id, g.admin["id"]):
        return jsonify({"error": "Job started before cancellation could be applied"}), 409
    db.audit(g.company["id"], g.admin["id"], "job_cancelled",
             {"job_id": job_id, "type": job["type"]},
             endpoint_id=job.get("endpoint_id"))
    return jsonify({"ok": True})
