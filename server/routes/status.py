"""
Warden — Status routes
Real-time health of the server background services and agent fleet.
"""
from flask import Blueprint, render_template, jsonify, g, abort

import db
from middleware.auth import login_required, company_required, role_required
from services import health_tracker

bp = Blueprint("status", __name__)


@bp.get("/status/performance")
@login_required
@company_required
@role_required('company_admin')
def performance():
    from services.operational_metrics import metrics, BOUNDS
    from services.operational_requests import admission
    from services.lifecycle import stopping
    from services.load_control import controller
    response = jsonify(scope='process-local', draining=stopping.is_set(),
                       bucket_upper_seconds=BOUNDS, metrics=metrics.snapshot(),
                       heavy_requests=admission.snapshot(), load=controller.snapshot(),
                       relay_connections=health_tracker.get_status()['active_connections'])
    response.headers['Cache-Control'] = 'no-store'
    return response


@bp.get("/status/queue")
@login_required
@company_required
def queue_health():
    from services.operations import queue_snapshot
    response = jsonify(queue_snapshot(g.company['id'], _branch_scope()))
    response.headers['Cache-Control'] = 'no-store'
    return response


@bp.get("/status/mail-queue")
@login_required
@company_required
@role_required('company_admin')
def mail_queue_health():
    company = db._q(g.company['id'])
    response = jsonify(
        failed_messages=db._count(f"mail_outbox?company_id=eq.{company}&status=eq.failed"),
        pending_messages=db._count(f"mail_outbox?company_id=eq.{company}&status=eq.pending"),
        dead_lettered_events=db._count(f"mail_events?company_id=eq.{company}&dead_lettered_at=not.is.null"),
        failed_events=db._get(f"mail_events?company_id=eq.{company}&dead_lettered_at=not.is.null"
                             "&select=id,created_at,attempts,result_code&order=created_at.desc,id.desc&limit=20"))
    response.headers['Cache-Control'] = 'no-store'
    return response


@bp.get("/operations/storage/reconciliation")
@login_required
@company_required
@role_required('company_admin')
def storage_reconciliation():
    from services.storage_reconciliation import reconcile
    response = jsonify(reconcile(g.company['id']))
    response.headers['Cache-Control'] = 'no-store'
    return response


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
