"""
Warden — Audit Log routes
"""
from flask import Blueprint, render_template, request, g

import db
from middleware.auth import login_required, company_required

bp = Blueprint("audit", __name__)


@bp.route("/audit")
@login_required
@company_required
def log():
    company_id = g.company["id"]
    try:
        page = max(1, int(request.args.get("page", 1)))
    except (TypeError, ValueError):
        page = 1
    limit = 50
    offset = (page - 1) * limit
    endpoint_id = request.args.get("endpoint_id")
    actor_id = request.args.get("actor_id")
    branch_id = g.admin.get("branch_id") if g.admin.get("role") == "branch_admin" else None

    entries = db.get_audit_log(
        company_id, limit=limit, offset=offset,
        endpoint_id=endpoint_id, actor_id=actor_id, branch_id=branch_id
    )

    endpoint_cache = {}
    admin_cache = {}
    for e in entries:
        eid = e.get("endpoint_id")
        if eid and eid not in endpoint_cache:
            endpoint_cache[eid] = db.get_endpoint(eid)
        e["_endpoint"] = endpoint_cache.get(eid)

        aid = e.get("actor_id")
        if aid and aid not in admin_cache:
            admin_cache[aid] = db.get_admin_by_id(aid)
        e["_actor"] = admin_cache.get(aid)

    return render_template(
        "audit/log.html",
        entries=entries,
        page=page,
        has_more=len(entries) == limit,
        endpoint_id=endpoint_id,
        actor_id=actor_id,
    )
