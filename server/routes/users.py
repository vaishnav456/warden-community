"""
Warden — Users (admin user management) routes
Create/edit/disable admin users within a company.
"""
from flask import Blueprint, render_template, request, jsonify, g, redirect, url_for, abort

import db
from middleware.auth import login_required, company_required, role_required

bp = Blueprint("users", __name__)


def _hash_password(password):
    import bcrypt
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


@bp.route("/users")
@login_required
@company_required
@role_required("company_admin")
def list_users():
    company_id = g.company["id"]
    admins = db.get_admins_for_company(company_id)
    branches = db.get_branches(company_id)
    return render_template("users/list.html", admins=admins, branches=branches)


@bp.route("/users/create", methods=["POST"])
@login_required
@company_required
@role_required("company_admin")
def create():
    email = request.form.get("email", "").strip().lower()
    full_name = request.form.get("full_name", "").strip()
    role = request.form.get("role", "technician").strip()
    branch_id = request.form.get("branch_id") or None
    password = request.form.get("password", "")
    confirm = request.form.get("confirm_password", "")

    if not all([email, full_name, password]):
        return jsonify({"error": "All fields required"}), 400
    if password != confirm:
        return jsonify({"error": "Passwords do not match"}), 400
    if len(password) < 12:
        return jsonify({"error": "Password must be at least 12 characters"}), 400
    if role not in ("company_admin", "branch_admin", "technician"):
        return jsonify({"error": "Invalid role"}), 400
    from services.entitlements import check_capacity
    capacity = check_capacity(g.company["id"], "admins")
    if not capacity.allowed:
        return jsonify({"error": capacity.code, "message": capacity.message}), 403

    # Branch admin must have a branch
    if role == "branch_admin" and not branch_id:
        return jsonify({"error": "Branch admin requires a branch selection"}), 400
    if branch_id:
        branch = db.get_branch(branch_id)
        if not branch or str(branch.get("company_id")) != str(g.company["id"]):
            return jsonify({"error": "Branch not found"}), 404

    existing = db.get_admin_by_email(email)
    if existing:
        return jsonify({"error": "Email already in use"}), 409

    admin = db.create_admin_user(
        email=email,
        password_hash=_hash_password(password),
        full_name=full_name,
        role=role,
        company_id=g.company["id"],
        branch_id=branch_id,
        created_by=g.admin["id"],
    )
    db.audit(g.company["id"], g.admin["id"], "admin_user_created",
             {"email": email, "role": role})

    if request.headers.get("HX-Request"):
        admins = db.get_admins_for_company(g.company["id"])
        branches = db.get_branches(g.company["id"])
        return render_template("partials/user_row.html", admin=admin, branches=branches)

    # Alpine submits through wardenFetchJSON. Redirects become HTML after fetch
    # follows them, causing a false failure even though the account was created.
    if request.accept_mimetypes.best == "application/json":
        return jsonify({"ok": True}), 201

    return redirect(url_for("users.list_users"))


@bp.route("/users/<admin_id>/disable", methods=["POST"])
@login_required
@company_required
@role_required("company_admin")
def disable(admin_id):
    target = db.get_admin_by_id(admin_id)
    if not target or str(target.get("company_id")) != str(g.company["id"]):
        abort(404)
    if str(target["id"]) == str(g.admin["id"]):
        return jsonify({"error": "Cannot disable your own account"}), 400

    db.update_admin(admin_id, {"is_active": False})
    db.revoke_all_tokens_for_admin(admin_id)
    db.audit(g.company["id"], g.admin["id"], "admin_user_disabled",
             {"target_email": target["email"]})
    return jsonify({"ok": True})


@bp.route("/users/<admin_id>/enable", methods=["POST"])
@login_required
@company_required
@role_required("company_admin")
def enable(admin_id):
    target = db.get_admin_by_id(admin_id)
    if not target or str(target.get("company_id")) != str(g.company["id"]):
        abort(404)
    db.update_admin(admin_id, {"is_active": True, "failed_attempts": 0, "locked_until": None})
    db.audit(g.company["id"], g.admin["id"], "admin_user_enabled",
             {"target_email": target["email"]})
    return jsonify({"ok": True})


@bp.route("/users/<admin_id>/reset-password", methods=["POST"])
@login_required
@company_required
@role_required("company_admin")
def reset_password(admin_id):
    import secrets as _s
    target = db.get_admin_by_id(admin_id)
    if not target or str(target.get("company_id")) != str(g.company["id"]):
        abort(404)

    new_password = request.form.get("new_password") or _s.token_urlsafe(16)
    if len(new_password) < 12:
        return jsonify({"error": "Password must be at least 12 characters"}), 400

    db.update_admin_password(admin_id, _hash_password(new_password))
    db.revoke_all_tokens_for_admin(admin_id)
    db.audit(g.company["id"], g.admin["id"], "admin_password_reset",
             {"target_email": target["email"]})
    return jsonify({"ok": True, "new_password": new_password})


@bp.route("/users/<admin_id>/update", methods=["POST"])
@login_required
@company_required
@role_required("company_admin")
def update(admin_id):
    target = db.get_admin_by_id(admin_id)
    if not target or str(target.get("company_id")) != str(g.company["id"]):
        abort(404)
    body = request.get_json(silent=True) or {}
    full_name = str(body.get("full_name") or "").strip()
    role = str(body.get("role") or "").strip()
    branch_id = body.get("branch_id") or None
    if not full_name or len(full_name) > 160:
        return jsonify({"error": "A valid name is required"}), 400
    if role not in ("company_admin", "branch_admin", "technician"):
        return jsonify({"error": "Invalid role"}), 400
    if str(target["id"]) == str(g.admin["id"]) and role != target.get("role"):
        return jsonify({"error": "You cannot change your own role"}), 400
    if role == "branch_admin" and not branch_id:
        return jsonify({"error": "Branch admin requires a branch"}), 400
    if role != "branch_admin":
        branch_id = None
    if branch_id:
        branch = db.get_branch(branch_id)
        if not branch or str(branch.get("company_id")) != str(g.company["id"]):
            return jsonify({"error": "Branch not found"}), 404
    from services.entitlements import check_mutation
    decision = check_mutation(g.company["id"])
    if not decision.allowed:
        return jsonify({"error": decision.code, "message": decision.message}), 403
    db.update_admin(admin_id, {"full_name": full_name, "role": role, "branch_id": branch_id})
    db.revoke_all_tokens_for_admin(admin_id)
    db.audit(g.company["id"], g.admin["id"], "admin_user_updated", {
        "target_email": target["email"], "role": role, "branch_id": branch_id,
    })
    return jsonify({"ok": True})
