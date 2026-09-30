"""
Warden — Dashboard routes
Main company dashboard: overview, stats, recent activity.
"""
from flask import Blueprint, render_template, g, request, jsonify, abort, redirect, url_for

import db
from middleware.auth import login_required, company_required

bp = Blueprint("dashboard", __name__)


@bp.route("/")
def entry():
    """Community opens the local application, never a marketing page."""
    return redirect(url_for("dashboard.index" if g.get("admin") else "auth.login"))


@bp.route("/dashboard")
@login_required
@company_required
def index():
    company = g.company
    company_id = company["id"]
    branch_id = g.admin.get("branch_id") if g.admin.get("role") == "branch_admin" else None
    if g.admin.get("role") == "branch_admin" and not branch_id:
        abort(403)

    # Summary stats
    endpoints = db.get_endpoints(company_id, branch_id=branch_id)
    online_count = sum(1 for e in endpoints if e.get("status") == "online")
    offline_count = len(endpoints) - online_count

    pending_esc = db.count_pending_escalations(company_id, branch_id=branch_id)
    open_alerts = db.count_open_alerts(company_id, branch_id=branch_id)
    recent_jobs = db.get_jobs(company_id, branch_id=branch_id, limit=5)
    recent_alerts = db.get_alerts(
        company_id, resolved=False, branch_id=branch_id, limit=5,
    )
    notifications = db.get_notifications(g.admin["id"], unread_only=False, limit=10)
    unread_count = db.count_unread_notifications(g.admin["id"])

    return render_template(
        "dashboard.html",
        company=company,
        endpoints=endpoints,
        online_count=online_count,
        offline_count=offline_count,
        pending_escalations=pending_esc,
        open_alerts=open_alerts,
        recent_jobs=recent_jobs,
        recent_alerts=recent_alerts,
        notifications=notifications,
        unread_count=unread_count,
    )


@bp.route("/partials/stats")
@login_required
@company_required
def stats_partial():
    """HTMX partial — refreshes dashboard stat cards."""
    company_id = g.company["id"]
    branch_id = g.admin.get("branch_id") if g.admin.get("role") == "branch_admin" else None
    if g.admin.get("role") == "branch_admin" and not branch_id:
        abort(403)
    endpoints = db.get_endpoints(company_id, branch_id=branch_id)
    online_count = sum(1 for e in endpoints if e.get("status") == "online")
    offline_count = len(endpoints) - online_count
    pending_esc = db.count_pending_escalations(company_id, branch_id=branch_id)
    open_alerts = db.count_open_alerts(company_id, branch_id=branch_id)

    return render_template(
        "partials/dashboard_stats.html",
        online_count=online_count,
        offline_count=offline_count,
        total_count=len(endpoints),
        pending_escalations=pending_esc,
        open_alerts=open_alerts,
    )


@bp.route("/partials/notifications")
@login_required
def notifications_partial():
    notifications = db.get_notifications(g.admin["id"], limit=10)
    unread_count = db.count_unread_notifications(g.admin["id"])
    return render_template(
        "partials/notifications.html",
        notifications=notifications,
        unread_count=unread_count,
    )


@bp.route("/notifications/read", methods=["POST"])
@login_required
def mark_read():
    db.mark_notifications_read(g.admin["id"])
    return jsonify({"ok": True})
