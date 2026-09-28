"""
Warden — Alerts routes
"""
from datetime import datetime, timedelta, timezone
from flask import Blueprint, render_template, request, jsonify, g, abort

import db
from middleware.auth import login_required, company_required, require_branch_scope

bp = Blueprint("alerts", __name__)


@bp.route("/alerts")
@login_required
@company_required
def list_alerts():
    company_id = g.company["id"]
    branch_id = g.admin.get("branch_id") if g.admin.get("role") == "branch_admin" else None
    if g.admin.get("role") == "branch_admin" and not branch_id:
        abort(403)
    show_resolved = request.args.get("resolved", "false").lower() == "true"
    show_snoozed = request.args.get("snoozed", "false").lower() == "true" and not show_resolved
    try:
        page = max(1, int(request.args.get("page", 1)))
    except (TypeError, ValueError):
        page = 1
    limit = 30
    offset = (page - 1) * limit
    alerts = db.get_alerts(
        company_id, resolved=show_resolved, branch_id=branch_id,
        limit=limit, offset=offset, snoozed=show_snoozed,
    )

    endpoint_cache = {}
    for a in alerts:
        eid = a.get("endpoint_id")
        if eid and eid not in endpoint_cache:
            endpoint_cache[eid] = db.get_endpoint(eid)
        a["_endpoint"] = endpoint_cache.get(eid)

    return render_template(
        "alerts/list.html",
        alerts=alerts,
        show_resolved=show_resolved,
        show_snoozed=show_snoozed,
        page=page,
        has_more=len(alerts) == limit,
        admins=db.get_admins_for_company(company_id),
    )


@bp.route("/alerts/<alert_id>/resolve", methods=["POST"])
@login_required
@company_required
def resolve(alert_id):
    alert = db.get_alert(alert_id)
    if not alert or str(alert["company_id"]) != str(g.company["id"]):
        abort(404)
    require_branch_scope(alert.get("branch_id"))
    note = request.form.get("note", "").strip()
    db.resolve_alert(alert_id, g.admin["id"], note)
    db.audit(g.company["id"], g.admin["id"], "alert_resolved",
             {"alert_id": alert_id, "type": alert["type"]},
             endpoint_id=alert.get("endpoint_id"))
    if request.headers.get("HX-Request"):
        return "", 200
    return jsonify({"ok": True})


@bp.route("/alerts/<alert_id>/reopen", methods=["POST"])
@login_required
@company_required
def reopen(alert_id):
    alert = db.get_alert(alert_id)
    if not alert or str(alert["company_id"]) != str(g.company["id"]):
        abort(404)
    require_branch_scope(alert.get("branch_id"))
    db.reopen_alert(alert_id)
    db.audit(g.company["id"], g.admin["id"], "alert_reopened", {"alert_id": alert_id})
    return jsonify({"ok": True})


@bp.route("/alerts/<alert_id>/assign", methods=["POST"])
@login_required
@company_required
def assign(alert_id):
    alert = db.get_alert(alert_id)
    if not alert or str(alert["company_id"]) != str(g.company["id"]):
        abort(404)
    require_branch_scope(alert.get("branch_id"))
    admin_id = request.form.get("admin_id") or None
    if admin_id:
        admin = db.get_admin_by_id(admin_id)
        if not admin or str(admin.get("company_id")) != str(g.company["id"]):
            return jsonify({"error": "administrator not found"}), 404
    db.assign_alert(alert_id, admin_id)
    db.audit(g.company["id"], g.admin["id"], "alert_assigned", {
        "alert_id": alert_id, "assigned_to": admin_id,
    })
    return jsonify({"ok": True})


@bp.route("/alerts/<alert_id>/snooze", methods=["POST"])
@login_required
@company_required
def snooze(alert_id):
    alert = db.get_alert(alert_id)
    if not alert or str(alert["company_id"]) != str(g.company["id"]):
        abort(404)
    require_branch_scope(alert.get("branch_id"))
    try:
        hours = int(request.form.get("hours", "4"))
    except ValueError:
        return jsonify({"error": "invalid snooze duration"}), 400
    if hours not in {1, 4, 24, 168}:
        return jsonify({"error": "invalid snooze duration"}), 400
    until = (datetime.now(timezone.utc) + timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    db.snooze_alert(alert_id, until)
    db.audit(g.company["id"], g.admin["id"], "alert_snoozed", {
        "alert_id": alert_id, "hours": hours,
    })
    return jsonify({"ok": True, "snoozed_until": until})


@bp.route("/alerts/<alert_id>/unsnooze", methods=["POST"])
@login_required
@company_required
def unsnooze(alert_id):
    alert = db.get_alert(alert_id)
    if not alert or str(alert["company_id"]) != str(g.company["id"]):
        abort(404)
    require_branch_scope(alert.get("branch_id"))
    db.snooze_alert(alert_id, None)
    db.audit(g.company["id"], g.admin["id"], "alert_unsnoozed", {"alert_id": alert_id})
    return jsonify({"ok": True})


@bp.route("/partials/alert-badge")
@login_required
@company_required
def badge():
    branch_id = g.admin.get("branch_id") if g.admin.get("role") == "branch_admin" else None
    if g.admin.get("role") == "branch_admin" and not branch_id:
        abort(403)
    count = db.count_open_alerts(g.company["id"], branch_id=branch_id)
    return render_template("partials/alert_badge.html", count=count, type="alert")
