"""
Warden — Auth routes
Login, logout, MFA setup/verify, token refresh, password change.
"""
import hashlib
import secrets
import base64
import io
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, render_template, redirect, url_for, jsonify, g, make_response, abort

import config
import db
from middleware.auth import (
    issue_access_token, issue_refresh_token, rotate_refresh_token, decode_access_token,
    load_current_user, login_required
)
from middleware.security import check_rate_limit, get_client_ip
from services.platform_secrets import backup_code_matches

bp = Blueprint("auth", __name__)

# A valid bcrypt value used when an email does not exist. Performing the same
# expensive password check makes account enumeration by response timing much
# less useful. This hash is intentionally not the password of any account.
_DUMMY_PASSWORD_HASH = "$2b$12$C6UzMDM.H6dfI/f/IKcEe.ou2g0sgBZbP7DBbkTTrT7W9xXwKJDu6"


def _hash_password(password):
    import bcrypt
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def _check_password(password, hashed):
    import bcrypt
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False


def _get_client_ip():
    return get_client_ip()


def _set_auth_cookies(response, access_token, refresh_token):
    """Set HTTPOnly+Secure cookies for access and refresh tokens."""
    secure = config.SESSION_COOKIE_SECURE
    # Remove the legacy, overly narrow cookie. Its /auth/refresh path meant
    # logout could never receive and revoke it. Browsers may otherwise retain
    # both same-named cookies and keep sending the stale, more-specific one.
    response.delete_cookie(
        "warden_refresh", path="/auth/refresh", secure=secure,
        httponly=True, samesite="Strict",
    )
    response.set_cookie(
        "warden_token", access_token,
        max_age=config.JWT_ACCESS_MINUTES * 60,
        httponly=True, secure=secure, samesite="Strict", path="/"
    )
    response.set_cookie(
        "warden_refresh", refresh_token,
        max_age=config.JWT_REFRESH_DAYS * 86400,
        httponly=True, secure=secure, samesite="Strict", path="/auth"
    )
    return response


def _mfa_setup_template_context(secret, backup_codes, error=None):
    """Build the complete MFA setup view for initial and failed submissions."""
    import pyotp
    import qrcode

    slug = "community"
    provisioning_url = pyotp.TOTP(secret).provisioning_uri(
        g.admin["email"], issuer_name=f"{config.BRAND_NAME}/{slug}"
    )
    img = qrcode.make(provisioning_url)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return {
        "qr_b64": base64.b64encode(buf.getvalue()).decode(),
        "secret": secret,
        "backup_codes": backup_codes,
        "error": error,
    }


@bp.route("/login", methods=["GET"])
def login():
    if g.admin:
        return redirect(url_for("dashboard.index"))
    company = db.get_single_company()
    resp = make_response(render_template("login.html", company=company, slug=""))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    resp.headers["Pragma"] = "no-cache"
    return resp


@bp.route("/login", methods=["POST"])
def login_post():
    if not check_rate_limit("login", 10, fail_closed=True):
        return render_template("login.html", error="Too many attempts. Please wait a minute."), 429

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    company = db.get_single_company()
    slug = ""

    if not email or not password:
        return render_template("login.html", company=company, slug=slug,
                               error="Email and password are required."), 400

    admin = db.get_admin_by_email(email)
    ip = _get_client_ip()

    # Generic error message — don't reveal whether account exists
    _BAD = "Invalid email or password."

    if not admin:
        _check_password(password, _DUMMY_PASSWORD_HASH)
        return render_template("login.html", company=company, slug=slug, error=_BAD), 401

    # Community accounts must belong to the one configured organization.
    if (admin.get("role") not in {"company_admin", "branch_admin", "technician"} or
            str(admin.get("company_id")) != str(company.get("id"))):
        return render_template("login.html", company=company, slug="", error=_BAD), 401

    # Lockout check
    if admin.get("locked_until"):
        locked = datetime.fromisoformat(admin["locked_until"].replace("Z", "+00:00"))
        if locked > datetime.now(timezone.utc):
            return render_template("login.html", company=company, slug=slug,
                                   error="Account temporarily locked. Try again later."), 403

    if not _check_password(password, admin["password_hash"]):
        new_count = (admin.get("failed_attempts") or 0) + 1
        locked_until = None
        if new_count >= config.MAX_FAILED_LOGINS:
            locked_until = (
                datetime.now(timezone.utc) + timedelta(minutes=config.LOCKOUT_MINUTES)
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
        db.update_admin_failed_attempts(admin["id"], new_count, locked_until)
        return render_template("login.html", company=company, slug=slug, error=_BAD), 401

    if not admin.get("is_active"):
        return render_template("login.html", company=company, slug=slug,
                               error="Account disabled. Contact your administrator."), 403

    # Retained as non-authoritative token metadata for compatibility.
    admin["_company_slug"] = company["slug"]

    # MFA check
    if admin.get("mfa_enabled"):
        # Store intermediate state in a short-lived token for MFA step
        mfa_state = secrets.token_urlsafe(24)
        resp = make_response(redirect(url_for("auth.mfa_verify")))
        resp.set_cookie(
            "warden_mfa_state", mfa_state,
            max_age=300, httponly=True,
            secure=config.SESSION_COOKIE_SECURE, samesite="Strict"
        )
        # Store in DB — could be a short-lived table; here we reuse notifications as a store
        # For simplicity store in signed cookie payload (admin_id encoded)
        import jwt
        mfa_token = jwt.encode(
            {
                "sub": admin["id"],
                "state": mfa_state,
                "exp": int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp()),
            },
            config.SECRET_KEY + ":mfa",
            algorithm="HS256",
        )
        resp.set_cookie(
            "warden_mfa_token", mfa_token,
            max_age=300, httponly=True,
            secure=config.SESSION_COOKIE_SECURE, samesite="Strict"
        )
        return resp

    # No MFA — issue tokens
    db.update_admin_last_login(admin["id"], ip)
    access_token = issue_access_token(admin)
    refresh_token = issue_refresh_token(admin["id"], ip, request.user_agent.string)

    dest = url_for("dashboard.index")

    resp = make_response(redirect(dest))
    _set_auth_cookies(resp, access_token, refresh_token)
    return resp


@bp.route("/mfa", methods=["GET"])
def mfa_verify():
    mfa_token = request.cookies.get("warden_mfa_token", "")
    if not mfa_token:
        return redirect(url_for("auth.login"))
    return render_template("mfa.html")


@bp.route("/mfa", methods=["POST"])
def mfa_verify_post():
    import pyotp
    import jwt

    mfa_token = request.cookies.get("warden_mfa_token", "")
    if not mfa_token:
        return redirect(url_for("auth.login"))

    try:
        claims = jwt.decode(mfa_token, config.SECRET_KEY + ":mfa", algorithms=["HS256"])
    except Exception:
        return redirect(url_for("auth.login"))

    admin_id = claims["sub"]
    if not check_rate_limit(f"mfa:{admin_id}", 10, fail_closed=True):
        return render_template(
            "mfa.html", error="Too many attempts. Please wait a minute."
        ), 429
    admin = db.get_admin_by_id(admin_id)
    if not admin or not admin.get("is_active"):
        return redirect(url_for("auth.login"))
    cookie_state = request.cookies.get("warden_mfa_state", "")
    token_state = str(claims.get("state") or "")
    if not cookie_state or not token_state or not secrets.compare_digest(cookie_state, token_state):
        return redirect(url_for("auth.login"))

    totp_code = request.form.get("code", "").strip()
    totp = pyotp.TOTP(admin["mfa_secret"])

    # Check code or backup code
    valid = totp.verify(totp_code, valid_window=1)
    if not valid:
        backup = admin.get("mfa_backup_codes") or []
        matched = next((code for code in backup if backup_code_matches(totp_code, code)), None)
        if matched is not None:
            valid = True
            # Remove used backup code
            new_backup = [c for c in backup if c != matched]
            db.update_admin(admin_id, {"mfa_backup_codes": new_backup})

    if not valid:
        return render_template("mfa.html", error="Invalid code."), 401

    ip = _get_client_ip()
    db.update_admin_last_login(admin["id"], ip)

    # Rebuild admin with slug context
    company = db.get_single_company()
    admin["_company_slug"] = company["slug"]

    access_token = issue_access_token(admin)
    refresh_token = issue_refresh_token(admin["id"], ip, request.user_agent.string)

    dest = url_for("dashboard.index")

    resp = make_response(redirect(dest))
    _set_auth_cookies(resp, access_token, refresh_token)
    # Clear MFA cookies
    resp.delete_cookie("warden_mfa_token")
    resp.delete_cookie("warden_mfa_state")
    return resp


@bp.route("/auth/refresh", methods=["POST"])
def refresh():
    refresh_token = request.cookies.get("warden_refresh", "")
    if not refresh_token:
        return jsonify({"error": "No refresh token"}), 401

    ip = _get_client_ip()
    new_refresh, stored = rotate_refresh_token(
        refresh_token, ip, request.user_agent.string
    )
    if not stored:
        return jsonify({"error": "Invalid, expired, idle, or reused refresh token"}), 401

    admin = db.get_admin_by_id(stored["admin_id"])
    if not admin or not admin.get("is_active"):
        # Rotation has already minted the successor token. Revoke it before
        # rejecting an account that became unavailable between sessions.
        db.revoke_refresh_token(stored["id"])
        return jsonify({"error": "Account unavailable"}), 401

    company = db.get_single_company()
    admin["_company_slug"] = company["slug"]

    new_access = issue_access_token(admin)
    resp = jsonify({"ok": True})
    _set_auth_cookies(resp, new_access, new_refresh)
    return resp


@bp.route("/auth/logout", methods=["POST"])
@bp.route("/logout", methods=["POST"])
def logout():
    refresh_token = request.cookies.get("warden_refresh", "")
    if refresh_token:
        token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
        stored = db.get_refresh_token(token_hash)
        if stored:
            db.revoke_refresh_token(stored["id"])

    resp = make_response(redirect(url_for("auth.login")))
    # Cookie deletion must use the same Path attributes used when setting the
    # cookies. Also clear the legacy /auth/refresh path during migration.
    secure = config.SESSION_COOKIE_SECURE
    resp.delete_cookie(
        "warden_token", path="/", secure=secure,
        httponly=True, samesite="Strict",
    )
    resp.delete_cookie(
        "warden_refresh", path="/auth", secure=secure,
        httponly=True, samesite="Strict",
    )
    resp.delete_cookie(
        "warden_refresh", path="/auth/refresh", secure=secure,
        httponly=True, samesite="Strict",
    )
    resp.delete_cookie("warden_mfa_token", path="/")
    resp.delete_cookie("warden_mfa_state", path="/")
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    resp.headers["Clear-Site-Data"] = '"cache"'
    if request.headers.get("HX-Request"):
        # Force a top-level navigation. Otherwise HTMX follows the redirect
        # and can render login.html inside the old application shell.
        resp.headers["HX-Redirect"] = url_for("auth.login")
    return resp


@bp.route("/change-password", methods=["POST"])
@login_required
def change_password():
    current = request.form.get("current_password", "")
    new_pw = request.form.get("new_password", "")
    confirm = request.form.get("confirm_password", "")

    if new_pw != confirm:
        return jsonify({"error": "Passwords do not match"}), 400
    if len(new_pw) < 12 or len(new_pw.encode()) > 72:
        return jsonify({"error": "Password must be at least 12 characters and at most 72 UTF-8 bytes"}), 400
    if not _check_password(current, g.admin["password_hash"]):
        return jsonify({"error": "Current password incorrect"}), 401

    db.update_admin_password(g.admin["id"], _hash_password(new_pw))
    db.revoke_all_tokens_for_admin(g.admin["id"])
    db.audit(g.admin.get("company_id"), g.admin["id"], "password_changed")

    resp = make_response(redirect(url_for("auth.login")))
    secure = config.SESSION_COOKIE_SECURE
    resp.delete_cookie(
        "warden_token", path="/", secure=secure,
        httponly=True, samesite="Strict",
    )
    resp.delete_cookie(
        "warden_refresh", path="/auth", secure=secure,
        httponly=True, samesite="Strict",
    )
    resp.delete_cookie(
        "warden_refresh", path="/auth/refresh", secure=secure,
        httponly=True, samesite="Strict",
    )
    return resp


@bp.route("/setup-mfa", methods=["GET"])
@login_required
def setup_mfa():
    import pyotp

    if g.admin.get("mfa_enabled"):
        return redirect(url_for("settings.index"))

    secret = pyotp.random_base32()

    # Generate backup codes
    backup_codes = [secrets.token_hex(5).upper() for _ in range(10)]

    # Store temporarily in session (5 min window to confirm)
    import jwt
    mfa_setup_token = jwt.encode(
        {
            "sub": g.admin["id"],
            "secret": secret,
            "backup_codes": backup_codes,
            "exp": int((datetime.now(timezone.utc) + timedelta(minutes=10)).timestamp()),
        },
        config.SECRET_KEY + ":mfa_setup",
        algorithm="HS256",
    )

    resp = make_response(render_template(
        "settings/mfa_setup.html", **_mfa_setup_template_context(secret, backup_codes)
    ))
    resp.set_cookie(
        "warden_mfa_setup", mfa_setup_token,
        max_age=600, httponly=True,
        secure=config.SESSION_COOKIE_SECURE, samesite="Strict"
    )
    return resp


@bp.route("/setup-mfa", methods=["POST"])
@login_required
def setup_mfa_confirm():
    import pyotp, jwt

    setup_token = request.cookies.get("warden_mfa_setup", "")
    if not setup_token:
        return redirect(url_for("auth.setup_mfa"))
    try:
        claims = jwt.decode(setup_token, config.SECRET_KEY + ":mfa_setup", algorithms=["HS256"])
    except Exception:
        return redirect(url_for("auth.setup_mfa"))

    code = request.form.get("code", "").strip()
    totp = pyotp.TOTP(claims["secret"])
    if not totp.verify(code, valid_window=1):
        return render_template(
            "settings/mfa_setup.html",
            **_mfa_setup_template_context(
                claims["secret"], claims["backup_codes"], "Invalid code. Try again."
            ),
        ), 400

    db.update_admin_mfa(g.admin["id"], claims["secret"], claims["backup_codes"])
    db.audit(g.admin.get("company_id"), g.admin["id"], "mfa_enabled")

    resp = make_response(redirect(url_for("settings.index")))
    resp.delete_cookie("warden_mfa_setup")
    return resp
