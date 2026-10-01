"""
Warden — Status routes
Real-time health of the server background services and agent fleet.
"""
from flask import Blueprint, render_template, jsonify, g, abort

import db
from middleware.auth import login_required, company_required
from services import health_tracker

bp = Blueprint("status", __name__)


def _branch_scope():
    if g.admin.get("role") == "branch_admin":
        branch_id = g.admin.get("branch_id")
        if not branch_id:
            abort(403)
        return branch_id
    return None


@bp.route("/status")
@login_required
@company_required
def index():
    branch_id = _branch_scope()
    server_status = health_tracker.get_status()
    job_stats = db.get_job_queue_stats(g.company["id"], branch_id=branch_id)
    endpoint_summary = db.get_endpoint_summary(g.company["id"], branch_id=branch_id)
    endpoints = db.get_endpoints(g.company["id"], branch_id=branch_id)
    return render_template(
        "status/index.html",
        server_status=server_status,
        job_stats=job_stats,
        endpoint_summary=endpoint_summary,
        endpoints=endpoints,
    )


@bp.route("/status/partial")
@login_required
@company_required
def partial():
    """HTMX partial — refreshed every 15s to update service health cards."""
    server_status = health_tracker.get_status()
    branch_id = _branch_scope()
    job_stats = db.get_job_queue_stats(g.company["id"], branch_id=branch_id)
    endpoint_summary = db.get_endpoint_summary(g.company["id"], branch_id=branch_id)
    return render_template(
        "status/_cards.html",
        server_status=server_status,
        job_stats=job_stats,
        endpoint_summary=endpoint_summary,
    )


@bp.route("/status/json")
@login_required
@company_required
def status_json():
    """JSON endpoint for external monitoring."""
    branch_id = _branch_scope()
    return jsonify({
        "server": health_tracker.get_status(),
        "jobs": db.get_job_queue_stats(g.company["id"], branch_id=branch_id),
        "endpoints": db.get_endpoint_summary(g.company["id"], branch_id=branch_id),
    })
