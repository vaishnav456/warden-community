"""SMTP administration, self-service email preferences and password recovery."""
import hashlib
import logging
import re
from flask import Blueprint, abort, flash, g, jsonify, make_response, redirect, render_template, request
import db
from middleware.auth import login_required, company_required, role_required
from middleware.security import check_rate_limit
from services import mail

bp = Blueprint("mail", __name__)
log = logging.getLogger("warden.mail.routes")


@bp.after_request
def private_mail_response(response):
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


def _scope():
    return g.company["id"]


@bp.route("/settings/mail", methods=["GET", "POST"])
@login_required
@company_required
@role_required("company_admin")
def settings():
    company_id = _scope()
    if request.method == "POST":
        if not check_rate_limit("smtp-config", 20, fail_closed=True):
            abort(429)
        previous = mail.get_settings(company_id)
        body = dict(request.form)
        body["enabled"] = request.form.get("enabled") == "1"
        body["clear_password"] = request.form.get("clear_password") == "1"
        try:
            saved = mail.validate_settings(body, previous)
            mail.save_settings(company_id, g.admin["id"], saved)
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect("/settings/mail")
        db.audit(company_id, g.admin["id"], "smtp_settings_updated", {"enabled": saved["enabled"], "mode": saved["mode"]})
        flash("SMTP settings saved. Send a test email to verify delivery.", "success")
        return redirect("/settings/mail")
    saved = mail.public_settings(mail.get_settings(company_id))
    key = mail.scope_key(company_id)
    query = "mail_outbox?select=id,category,status,attempts,result_code,created_at,sent_at&order=created_at.desc&limit=30"
    if mail.SCOPE_MODE == "company":
        query += "&company_id=eq." + db._q(company_id)
    response = make_response(render_template("settings/mail.html", smtp=saved, mail_rows=db._get(query), mail_path="/settings/mail", platform_mail=mail.SCOPE_MODE == "platform"))
    response.headers["Cache-Control"] = "private, no-store"
    return response


@bp.route("/settings/mail/test", methods=["POST"])
@login_required
@company_required
@role_required("company_admin")
def test():
    if not check_rate_limit("smtp-test", 3, fail_closed=True):
        abort(429)
    try:
        queued = mail.enqueue(g.admin, "test", "Warden SMTP test", "Your Warden SMTP configuration accepted this test for delivery.\n\n" + mail.base_url())
    except Exception:
        queued = False
    flash("Test email queued to your own login email. Check the delivery status below." if queued else "SMTP is disabled or unavailable. Check the settings first.", "success" if queued else "error")
    return redirect("/settings/mail")


@bp.route("/settings/email-notifications", methods=["GET", "POST"])
@login_required
def preferences():
    if request.method == "POST":
        prefs = dict(g.admin.get("notification_prefs") or {})
        prefs["email_categories"] = {key: request.form.get(key) == "1" for key in mail.CATEGORIES}
        db.update_admin(g.admin["id"], {"notification_prefs": prefs})
        db.audit(g.admin.get("company_id"), g.admin["id"], "email_preferences_updated")
        flash("Email notification preferences saved.", "success")
        return redirect("/settings/email-notifications")
    return render_template("settings/email_notifications.html", categories=mail.CATEGORIES,
                           email_prefs={**{"alerts_critical": True, "jobs_failed": True},
                                        **((g.admin.get("notification_prefs") or {}).get("email_categories") or {})})


@bp.route("/auth/forgot-password", methods=["GET", "POST"])
def forgot_password():
    done = False
    if request.method == "POST":
        if not check_rate_limit("forgot-password", 5, fail_closed=True):
            return render_template("password_recovery.html", mode="forgot", error="Too many requests. Please try again later."), 429
        email = request.form.get("email", "").strip().lower()
        fingerprint = hashlib.sha256(email.encode()).hexdigest()
        if check_rate_limit("forgot-password:" + fingerprint, 2, fail_closed=True):
            try:
                admin = db.get_admin_by_email(email)
                # A tenant subdomain cannot initiate another tenant's recovery.
                slug = g.get("company_slug")
                company = db.get_company_by_slug(slug) if slug else None
                if admin and (not slug or (company and str(admin.get("company_id")) == str(company["id"]))):
                    mail.request_reset(admin)
            except Exception as exc:
                log.warning("Password recovery request deferred (%s)", type(exc).__name__)
        done = True
    response = make_response(render_template("password_recovery.html", mode="forgot", done=done))
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@bp.route("/auth/reset-password", methods=["GET", "POST"])
def reset_password():
    completed, error = False, None
    if request.method == "POST":
        if not check_rate_limit("reset-password", 10, fail_closed=True):
            return render_template("password_recovery.html", mode="reset", error="Too many attempts. Try again later."), 429
        token = request.form.get("token", "")
        password = request.form.get("password", "")
        if len(password) < 12 or len(password.encode()) > 72:
            error = "Use at least 12 characters and at most 72 UTF-8 bytes."
        elif password != request.form.get("confirm_password"):
            error = "Passwords do not match."
        elif not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
            error = "This reset link is invalid or expired. Request another link."
        else:
            from routes.auth import _hash_password
            try:
                completed = bool(db._rpc("complete_admin_password_reset", {
                    "p_token_hash": hashlib.sha256(token.encode()).hexdigest(), "p_password_hash": _hash_password(password)}))
            except Exception as exc:
                log.warning("Password recovery temporarily unavailable (%s)", type(exc).__name__)
                error = "Password recovery is temporarily unavailable. Please try again later."
            if not completed and not error:
                error = "This reset link is invalid, expired or already used. Request another link."
    response = make_response(render_template("password_recovery.html", mode="reset", completed=completed, error=error,
                                            recovery_token=request.form.get("token", "") if request.method == "POST" and not completed else ""))
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@bp.route("/users/<admin_id>/welcome-email", methods=["POST"])
@login_required
@company_required
@role_required("company_admin")
def admin_welcome(admin_id):
    target = db.get_admin_by_id(admin_id)
    if not target or str(target.get("company_id")) != str(g.company["id"]):
        abort(404)
    if not target.get("is_active"):
        return jsonify({"error": "This account is inactive."}), 409
    if not check_rate_limit("admin-welcome", 10, fail_closed=True):
        abort(429)
    subject, text, path = mail.event_copy({"kind": "account_created"})
    queued = mail.enqueue(target, "security", subject, text + "\n\n" + mail.base_url() + path,
                          template="welcome", action_url=mail.base_url()+path, action_label="Sign in to Warden")
    if not queued:
        return jsonify({"error": "SMTP is disabled or unavailable."}), 409
    db.audit(g.company["id"], g.admin["id"], "admin_welcome_email_requested", {"target_id": admin_id})
    return jsonify({"ok": True, "message": "Welcome email queued; no password is included."})


@bp.route("/users/<admin_id>/reset-link", methods=["POST"])
@login_required
@company_required
@role_required("company_admin")
def admin_reset_link(admin_id):
    target = db.get_admin_by_id(admin_id)
    if not target or str(target.get("company_id")) != str(g.company["id"]):
        abort(404)
    if not check_rate_limit("admin-reset-link", 10, fail_closed=True):
        abort(429)
    queued = mail.request_reset(target)
    if not queued:
        return jsonify({"error": "Email delivery is disabled, a reset was recently requested, or the account is unavailable. Contact your SMTP administrator."}), 409
    db.audit(g.company["id"], g.admin["id"], "admin_password_reset_link_requested", {"target_id": admin_id})
    return jsonify({"ok": True, "message": "A single-use reset link was queued. The current password remains unchanged."})
