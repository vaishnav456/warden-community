"""
Warden — Escalations routes
Pending queue, approve/deny, saved policies, dual approval.
"""
from flask import Blueprint, render_template, request, jsonify, g, abort

import db
from middleware.auth import login_required, company_required, role_required, require_branch_scope

bp = Blueprint("escalations", __name__)


@bp.route("/escalations")
@login_required
@company_required
def queue():
    company_id = g.company["id"]
    status_filter = request.args.get("status", "pending")
    try:
        page = max(1, int(request.args.get("page", 1)))
    except (TypeError, ValueError):
        page = 1
    limit = 20
    offset = (page - 1) * limit
    branch_id = g.admin.get("branch_id") if g.admin.get("role") == "branch_admin" else None
    if g.admin.get("role") == "branch_admin" and not branch_id:
        abort(403)

    db.expire_stale_escalations()

    requests_list = db.get_escalation_requests(
        company_id, status=status_filter if status_filter != "all" else None,
        branch_id=branch_id,
        limit=limit, offset=offset
    )

    # Enrich with endpoint and admin info
    endpoint_cache = {}
    for r in requests_list:
        eid = r.get("endpoint_id")
        if eid and eid not in endpoint_cache:
            endpoint_cache[eid] = db.get_endpoint(eid)
        r["_endpoint"] = endpoint_cache.get(eid)

    return render_template(
        "escalations/queue.html",
        requests=requests_list,
        status_filter=status_filter,
        page=page,
        has_more=len(requests_list) == limit,
    )


@bp.route("/escalations/saved")
@login_required
@company_required
def saved():
    company_id = g.company["id"]
    policies = db.get_saved_escalations(company_id)
    if g.admin.get("role") == "branch_admin":
        policies = [p for p in policies if str(p.get("branch_id")) == str(g.admin.get("branch_id"))]

    endpoint_cache = {}
    for p in policies:
        eid = p.get("endpoint_id")
        if eid and eid not in endpoint_cache:
            endpoint_cache[eid] = db.get_endpoint(eid)
        p["_endpoint"] = endpoint_cache.get(eid)

    return render_template("escalations/saved.html", policies=policies)


@bp.route("/escalations/<req_id>/approve", methods=["POST"])
@login_required
@company_required
@role_required("superadmin", "company_admin", "branch_admin")
def approve(req_id):
    esc = db.get_escalation_request(req_id)
    if not esc or str(esc["company_id"]) != str(g.company["id"]):
        abort(404)
    require_branch_scope(esc.get("branch_id"))
    if esc["status"] not in ("pending", "pending_secondary"):
        return jsonify({"error": "Cannot approve in current state"}), 400

    if esc.get("requested_by") and str(esc["requested_by"]) == str(g.admin["id"]):
        return jsonify({"error": "Requester cannot approve their own privileged action"}), 403

    # Prevent same admin approving both steps
    if esc.get("reviewed_by") == g.admin["id"] and esc["status"] == "pending_secondary":
        return jsonify({"error": "Same admin cannot provide both approvals"}), 403

    # Parse + validate the "approve and save policy" option BEFORE mutating
    # any state below. This used to run after db.approve_escalation() —
    # a bad valid_days value (e.g. the escalation_card.html "Permanent"
    # option, which Alpine's x-model.number turns into JS `null`, which
    # FormData then serializes as the literal string "null") threw here,
    # crashing the request with a 500 *after* the escalation was already
    # persisted as approved but *before* the job got created below. The
    # admin saw a failure and the approved operation (reboot, shutdown,
    # whatever) silently never ran, with no job and no way to retry short
    # of denying and re-requesting. Validating first means a bad request
    # fails clean with a 400 and changes nothing.
    save_policy = request.form.get("save_policy") == "1" or (
        request.get_json(silent=True) or {}
    ).get("save_policy")

    scope = "this_user_this_endpoint"
    valid_days = None
    note = ""
    if save_policy:
        body = request.get_json(silent=True) or {}
        scope = request.form.get("scope") or body.get("scope", "this_user_this_endpoint")
        valid_days_raw = request.form.get("valid_days") or body.get("valid_days")
        if valid_days_raw not in (None, "", "null"):
            try:
                valid_days = int(valid_days_raw)
            except (TypeError, ValueError):
                return jsonify({"error": f"invalid valid_days: {valid_days_raw!r}"}), 400
        note = request.form.get("note") or body.get("note", "")

    is_secondary = esc["status"] == "pending_secondary"
    token, updated = db.approve_escalation(
        req_id, g.admin["id"], esc["status"], is_secondary=is_secondary
    )
    if token is None:
        # Lost the race — another request already approved/changed this
        # escalation between our read above and this write. Whichever
        # request won already created the job (if applicable); this one
        # must not create a second.
        return jsonify({"error": "Escalation was already updated by another request"}), 409

    if save_policy:
        db.create_saved_escalation(
            company_id=g.company["id"],
            scope=scope,
            operation=esc["operation"],
            payload_match=esc.get("payload") or {},
            approved_by=g.admin["id"],
            valid_days=valid_days,
            note=note,
            branch_id=esc.get("branch_id") if "branch" in scope else None,
            endpoint_id=esc.get("endpoint_id") if "endpoint" in scope else None,
            windows_user=esc.get("windows_user") if "user" in scope else None,
        )
        action = "escalation_approved_saved"
    else:
        action = "escalation_approved"

    db.audit(
        g.company["id"], g.admin["id"], action,
        {"request_id": req_id, "operation": esc["operation"]},
        endpoint_id=esc.get("endpoint_id"),
        escalation_id=req_id,
    )

    # If approved (not just primary step), create the job. `updated` is the
    # row the CAS-guarded approve_escalation() call above actually wrote —
    # this request is guaranteed to be the one that made that transition (if
    # any), so no re-fetch or re-check is needed here.
    if updated["status"] == "approved":
        db.create_job(
            company_id=g.company["id"],
            branch_id=esc.get("branch_id"),
            endpoint_id=esc["endpoint_id"],
            job_type=esc["operation"],
            payload=esc.get("payload") or {},
            created_by=g.admin["id"],
            escalation_id=req_id,
        )

    # HTMX partial response: replace the card with updated state
    if request.headers.get("HX-Request"):
        endpoint = db.get_endpoint(esc["endpoint_id"]) if esc.get("endpoint_id") else None
        updated["_endpoint"] = endpoint
        return render_template("partials/escalation_card.html", req=updated)

    return jsonify({"ok": True, "token": token, "status": updated["status"]})


@bp.route("/escalations/<req_id>/deny", methods=["POST"])
@login_required
@company_required
@role_required("superadmin", "company_admin", "branch_admin")
def deny(req_id):
    esc = db.get_escalation_request(req_id)
    if not esc or str(esc["company_id"]) != str(g.company["id"]):
        abort(404)
    require_branch_scope(esc.get("branch_id"))
    if esc["status"] not in ("pending", "pending_secondary"):
        return jsonify({"error": "Cannot deny in current state"}), 400

    db.deny_escalation(req_id, g.admin["id"])
    db.audit(
        g.company["id"], g.admin["id"], "escalation_denied",
        {"request_id": req_id, "operation": esc["operation"]},
        endpoint_id=esc.get("endpoint_id"),
        escalation_id=req_id,
    )

    if request.headers.get("HX-Request"):
        updated = db.get_escalation_request(req_id)
        endpoint = db.get_endpoint(esc["endpoint_id"]) if esc.get("endpoint_id") else None
        updated["_endpoint"] = endpoint
        return render_template("partials/escalation_card.html", req=updated)

    return jsonify({"ok": True})


@bp.route("/escalations/saved/<policy_id>/revoke", methods=["POST"])
@login_required
@company_required
@role_required("superadmin", "company_admin", "branch_admin")
def revoke_policy(policy_id):
    policy = db.get_saved_escalation(policy_id)
    if not policy or str(policy["company_id"]) != str(g.company["id"]):
        abort(404)
    require_branch_scope(policy.get("branch_id"))

    db.revoke_saved_escalation(policy_id, g.admin["id"])
    db.audit(g.company["id"], g.admin["id"], "saved_escalation_revoked",
             {"policy_id": policy_id, "operation": policy["operation"]})

    if request.headers.get("HX-Request"):
        return "", 200  # Remove the card via hx-swap="delete"

    return jsonify({"ok": True})


@bp.route("/partials/escalation-badge")
@login_required
@company_required
def badge():
    """HTMX partial — pending escalation count badge."""
    branch_id = g.admin.get("branch_id") if g.admin.get("role") == "branch_admin" else None
    if g.admin.get("role") == "branch_admin" and not branch_id:
        abort(403)
    count = db.count_pending_escalations(g.company["id"], branch_id=branch_id)
    return render_template("partials/alert_badge.html", count=count, type="escalation")


@bp.route("/partials/escalation-cards")
@login_required
@company_required
def cards_partial():
    """HTMX partial — pending escalation cards for live polling."""
    db.expire_stale_escalations()
    branch_id = g.admin.get("branch_id") if g.admin.get("role") == "branch_admin" else None
    if g.admin.get("role") == "branch_admin" and not branch_id:
        abort(403)
    requests_list = db.get_escalation_requests(
        g.company["id"], status="pending", branch_id=branch_id, limit=20,
    )
    endpoint_cache = {}
    for r in requests_list:
        eid = r.get("endpoint_id")
        if eid and eid not in endpoint_cache:
            endpoint_cache[eid] = db.get_endpoint(eid)
        r["_endpoint"] = endpoint_cache.get(eid)
    return render_template("partials/escalation_cards.html", requests=requests_list)
