"""
Warden — Users (admin user management) routes
Create/edit/disable admin users within a company.
"""
from flask import Blueprint, render_template, request, jsonify, g, redirect, url_for, abort
import urllib.error

import db
from middleware.auth import login_required, company_required, role_required
from routes.directory import LOGIN_EMAIL_RE, _normalize_profile_photo, _profile_photo_response

bp = Blueprint("users", __name__)


def _hash_password(password):
    import bcrypt
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def _profile_fields(target, body):
    name = str(body.get("full_name") or "").strip()
    email = str(body.get("email", target.get("email") or "")).strip().lower()
    if not name or len(name) > 160:
        return None, "A valid name is required"
    if len(email) > 254 or not LOGIN_EMAIL_RE.fullmatch(email) or "." not in email.rsplit("@", 1)[1]:
        return None, "Enter a valid email address"
    existing = db.get_admin_by_email(email)
    if existing and str(existing["id"]) != str(target["id"]):
        return None, "Email already in use"
    if str(target["id"]) == str(g.admin["id"]) and email != target.get("email"):
        from routes.auth import _check_password
        if not _check_password(str(body.get("current_password") or ""), target["password_hash"]):
            return None, "Current password is required to change your login email"
    fields = {"full_name": name, "email": email}
    if "profile_photo" in body:
        photo, mime, error = _normalize_profile_photo(body["profile_photo"])
        if error:
            return None, error
        from services.platform_secrets import encrypt_platform_field
        fields.update(profile_photo=encrypt_platform_field(target["id"], "admin.profile_photo", photo) if photo else None,
                      profile_photo_mime=mime or None)
    return fields, None


def _save_profile(admin_id, fields):
    try:
        if "profile_photo" in fields:
            from services.tenant_storage import admission
            def growth():
                previous = db.get_admin_by_id(admin_id) or {}
                return max(0, len((fields.get("profile_photo") or "").encode()) -
                           len((previous.get("profile_photo") or "").encode()))
            with admission(g.admin.get("company_id") if str(admin_id) == str(g.admin["id"]) else g.company["id"], growth):
                db.update_admin(admin_id, fields)
        else:
            db.update_admin(admin_id, fields)
    except urllib.error.HTTPError as exc:
        if exc.code == 409:
            return jsonify({"error": "Email already in use"}), 409
        raise


@bp.route("/users/profile", methods=["POST"])
@login_required
def profile():
    fields, error = _profile_fields(g.admin, request.get_json(silent=True) or {})
    if error:
        return jsonify({"error": error}), 400
    conflict = _save_profile(g.admin["id"], fields)
    if conflict:
        return conflict
    email_changed = fields["email"] != g.admin.get("email")
    if email_changed:
        db.revoke_all_tokens_for_admin(g.admin["id"])
    db.audit(g.admin.get("company_id"), g.admin["id"], "admin_profile_updated", {"email_changed": email_changed})
    return jsonify({"ok": True, "sign_in_required": email_changed})


@bp.route("/users/<admin_id>/photo")
@login_required
def photo(admin_id):
    target = db.get_admin_by_id(admin_id)
    if not target or (str(admin_id) != str(g.admin["id"]) and
                      (not g.company or str(target.get("company_id")) != str(g.company["id"]))):
        abort(404)
    def serve():
        if not target.get("profile_photo"):
            abort(404)
        from services.platform_secrets import decrypt_platform_field
        data = decrypt_platform_field(admin_id, "admin.profile_photo", target["profile_photo"])
        response = _profile_photo_response(data, target.get("profile_photo_mime"))
        response.headers["Cache-Control"] = "private, no-store"
        return response
    if str(admin_id) == str(g.admin["id"]):
        return serve()
    return company_required(serve)()


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
    if len(password) < 12 or len(password.encode()) > 72:
        return jsonify({"error": "Password must be at least 12 characters and at most 72 UTF-8 bytes"}), 400
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
        return render_template("users/list.html", admins=admins, branches=branches)

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

    if str(target["id"]) == str(g.admin["id"]):
        return jsonify({"error": "Use Change Password in your account settings for your own password"}), 400
    body = request.get_json(silent=True) or request.form
    new_password = body.get("new_password") or _s.token_urlsafe(16)
    if not isinstance(new_password, str) or len(new_password) < 12 or len(new_password.encode()) > 72:
        return jsonify({"error": "Password must be at least 12 characters and at most 72 UTF-8 bytes"}), 400

    db.update_admin_password(admin_id, _hash_password(new_password))
    db.revoke_all_tokens_for_admin(admin_id)
    db.audit(g.company["id"], g.admin["id"], "admin_password_reset",
             {"target_email": target["email"]})
    response = jsonify({"ok": True, "new_password": new_password})
    response.headers["Cache-Control"] = "no-store"
    return response


@bp.route("/users/<admin_id>/update", methods=["POST"])
@login_required
@company_required
@role_required("company_admin")
def update(admin_id):
    target = db.get_admin_by_id(admin_id)
    if not target or str(target.get("company_id")) != str(g.company["id"]):
        abort(404)
    body = request.get_json(silent=True) or {}
    fields, error = _profile_fields(target, body)
    if error:
        return jsonify({"error": error}), 400
    role = str(body.get("role") or "").strip()
    branch_id = body.get("branch_id") or None
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
    fields.update(role=role, branch_id=branch_id)
    conflict = _save_profile(admin_id, fields)
    if conflict:
        return conflict
    if any(fields[key] != target.get(key) for key in ("email", "role", "branch_id")):
        db.revoke_all_tokens_for_admin(admin_id)
    db.audit(g.company["id"], g.admin["id"], "admin_user_updated", {
        "target_email": target["email"], "role": role, "branch_id": branch_id,
    })
    return jsonify({"ok": True})
