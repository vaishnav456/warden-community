"""
Warden — Dashboard routes
Main company dashboard: overview, stats, recent activity.
"""
from flask import Blueprint, render_template, g, request, jsonify, abort, redirect, url_for

import db
import urllib.error
from datetime import datetime, timedelta, timezone
from services.dashboard_view import selected_branch, scoped_url, prepare_endpoints, group_alerts
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
    return render_template("dashboard.html", **_data())


@bp.route("/partials/stats")
@login_required
@company_required
def stats_partial():
    """Refresh totals, fleet reports and activity as a single snapshot."""
    response = render_template("partials/dashboard_content.html", **_data())
    return response, 200, {"Cache-Control": "private, no-store"}

def _data():
    branch_id = selected_branch()
    company_id = g.company["id"]
    now = datetime.now(timezone.utc)
    from services.dashboard_fleet import snapshot
    fleet = snapshot(company_id, branch_id, now)
    endpoints = fleet['endpoints'] if fleet is not None else prepare_endpoints(
        db.get_endpoints(company_id, branch_id=branch_id, sort_names=False),
        db.get_compliance_results_for_company(company_id, branch_id=branch_id, summary_only=True),
        db.get_patch_inventory(company_id, branch_id=branch_id, summary_only=True), now)
    visible = {str(ep["id"]): ep for ep in endpoints}
    alerts = db.get_alerts(company_id, resolved=False, branch_id=branch_id, limit=50)
    for alert in alerts:
        ep = visible.get(str(alert.get("endpoint_id")))
        if ep:
            alert["_label"] = ep.get("display_name") or ep.get("hostname")
    totals = db.dashboard_counts(company_id, branch_id=branch_id, now=now)
    jobs = db.get_jobs(company_id, branch_id=branch_id, limit=8)
    for job in jobs:
        ep = visible.get(str(job.get("endpoint_id")))
        job["_label"] = (ep.get("display_name") or ep.get("hostname")) if ep else "Organization task"
    missing_ids = {str(row['endpoint_id']) for row in alerts + jobs if row.get('endpoint_id')} - visible.keys()
    if fleet is not None and missing_ids:
        extra = db.get_endpoints_bulk(company_id, branch_id=branch_id, endpoint_ids=sorted(missing_ids))
        visible.update({str(row['id']): row for row in extra})
        for row in alerts + jobs:
            ep = visible.get(str(row.get('endpoint_id')))
            if ep:
                row['_label'] = ep.get('display_name') or ep.get('hostname')
    return dict(
        company=g.company, endpoints=endpoints, total_count=fleet['total_count'] if fleet is not None else len(endpoints),
        online_count=fleet['online_count'] if fleet is not None else sum(ep["_online"] for ep in endpoints),
        offline_count=fleet['offline_count'] if fleet is not None else sum(not ep["_online"] for ep in endpoints),
        stale_count=fleet['stale_count'] if fleet is not None else sum(ep.get("status") == "online" and not ep["_fresh"] for ep in endpoints),
        **totals,
        fleet_health=fleet['health'] if fleet is not None else {},
        recent_jobs=jobs, recent_alerts=group_alerts(alerts)[:6],
        alert_sample=len(alerts), selected_branch=branch_id,
        branches=[b for b in db.get_branches(company_id) if g.admin.get("role") != "branch_admin" or str(b["id"]) == branch_id],
        refreshed_at=now.isoformat(), scoped_url=lambda path, **filters: scoped_url(path, branch_id, **filters),
        notifications=db.get_notifications(g.admin["id"], unread_only=False, limit=10),
        unread_count=db.count_unread_notifications(g.admin["id"]),
    )


@bp.route("/partials/dashboard-storage")
@login_required
@company_required
def storage_partial():
    if g.admin.get("role") not in ("company_admin",):
        abort(403)
    from services.tenant_storage import usage
    try:
        storage = usage(g.company["id"])
        storage_limit = None
        return render_template("partials/dashboard_storage.html", storage=storage, storage_limit=storage_limit)
    except (OSError, RuntimeError, ValueError, urllib.error.URLError):
        return render_template("partials/dashboard_storage.html", storage=None, storage_limit=None)



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
