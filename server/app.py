"""
Warden — Flask Application
Single-organization community endpoint management system.

Run:
    python app.py
    gunicorn -c gunicorn.conf.py app:app
"""
import logging
import secrets
import time
from flask import Flask, g, request, redirect, url_for, render_template, jsonify
from werkzeug.middleware.proxy_fix import ProxyFix

import config
from middleware.auth import load_current_user
from middleware.security import apply_security_headers, check_firewall
from middleware.csrf import get_csrf_token, csrf_protect
from services.page_help import page_help_for

# ── App factory ───────────────────────────────────────────────────────────────
app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = config.SECRET_KEY
from services.tenant_storage import StorageError

@app.errorhandler(StorageError)
def storage_error(error):
    return jsonify(error=error.code,message=str(error)),error.status
app.config.update(
    MAX_CONTENT_LENGTH=500 * 1024 * 1024,  # 500 MB upload limit
    SESSION_COOKIE_NAME="warden_session",
    SESSION_COOKIE_SECURE=config.SESSION_COOKIE_SECURE,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
)

# Cache-busting query string for static assets (see base.html's ?v={{ asset_v
# }} on every CSS/JS tag) — computed once here at import time, not per
# request. Warden intentionally uses one threaded Gunicorn worker because its
# relay registry and schedulers are process-local (see gunicorn.conf.py), so
# this value remains consistent for every request. It changes on each deploy,
# forcing browsers/CDNs to fetch fresh assets.
ASSET_VERSION = str(int(time.time()))

# Gunicorn only ever binds 127.0.0.1 (see gunicorn.conf.py) and Caddy is the
# sole reverse proxy terminating TLS in front of it, so exactly one hop of
# X-Forwarded-For/X-Forwarded-Proto is trustworthy — anything further back
# in the chain is attacker-controlled and must not be trusted.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

logging.basicConfig(
    level=logging.DEBUG if config.DEBUG else logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(name)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("warden")

# ── Blueprint registration ────────────────────────────────────────────────────
from routes.auth import bp as auth_bp
from routes.dashboard import bp as dashboard_bp
from routes.endpoints import bp as endpoints_bp
from routes.escalations import bp as escalations_bp
from routes.jobs import bp as jobs_bp
from routes.users import bp as users_bp
from routes.apps import bp as apps_bp
from routes.alerts import bp as alerts_bp
from routes.audit import bp as audit_bp
from routes.settings import bp as settings_bp
from routes.enroll import bp as enroll_bp
from routes.agent_api import bp as agent_api_bp
from routes.build_service import bp as build_service_bp
from routes.compliance import bp as compliance_bp
from routes.schedule import bp as schedule_bp
from routes.status import bp as status_bp
from routes.directory import bp as directory_bp
from routes.patches import bp as patches_bp
from routes.assets import bp as assets_bp
from routes.security_management import bp as security_management_bp
from routes.home import bp as home_bp, node_api_bp as home_node_api_bp
from routes.operations import bp as operations_bp
app.register_blueprint(operations_bp)
from routes.fleet_tools import bp as fleet_tools_bp
app.register_blueprint(fleet_tools_bp)
from routes.topology import bp as topology_bp

app.register_blueprint(auth_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(endpoints_bp)
app.register_blueprint(escalations_bp)
app.register_blueprint(jobs_bp)
app.register_blueprint(users_bp)
app.register_blueprint(apps_bp)
app.register_blueprint(alerts_bp)
app.register_blueprint(audit_bp)
app.register_blueprint(settings_bp)
app.register_blueprint(enroll_bp)
app.register_blueprint(agent_api_bp)
app.register_blueprint(build_service_bp)
app.register_blueprint(compliance_bp)
app.register_blueprint(schedule_bp)
app.register_blueprint(status_bp)
app.register_blueprint(directory_bp)
app.register_blueprint(patches_bp)
app.register_blueprint(assets_bp)
app.register_blueprint(security_management_bp)
app.register_blueprint(home_bp)
app.register_blueprint(home_node_api_bp)
app.register_blueprint(topology_bp)

# ── Request hooks ─────────────────────────────────────────────────────────────

@app.before_request
def setup_context():
    """Load the authenticated administrator and sole organization."""
    # Per-request nonce for the few server-rendered inline blocks explicitly
    # authorized by the CSP. All library code and CSS are served locally.
    g.csp_nonce = secrets.token_urlsafe(16)

    blocked = check_firewall()
    if blocked is not None:
        return blocked

    from middleware.request_validation import validate_json_body
    invalid_body = validate_json_body()
    if invalid_body is not None:
        return invalid_body

    # /health endpoint — skip auth entirely
    if request.path == "/health":
        return

    # Aborts (403) on failure — see middleware/csrf.py for what's exempt.
    csrf_protect()

    # Community deployments serve exactly one organization on SERVER_URL.
    # Hostname/subdomain selection is intentionally unsupported.
    g.company_slug = None
    g.is_admin_domain = False

    load_current_user()

@app.after_request
def security_headers(response):
    if request.path == "/health":
        return response
    return apply_security_headers(response)


# ── Template context ──────────────────────────────────────────────────────────

@app.context_processor
def inject_globals():
    import db
    unread = 0
    if g.get("admin"):
        try:
            unread = db.count_unread_notifications(g.admin["id"])
        except Exception:
            pass
    return {
        "csrf_token": get_csrf_token,
        "csp_nonce": g.get("csp_nonce", ""),
        "asset_v": ASSET_VERSION,
        "brand_name": config.BRAND_NAME,
        "brand_tagline": config.BRAND_TAGLINE,
        "brand_logo_path": config.BRAND_LOGO_PATH,
        "session_idle_minutes": config.SESSION_IDLE_MINUTES,
        "jwt_access_minutes": config.JWT_ACCESS_MINUTES,
        "current_user": g.get("admin"),
        "current_company": g.get("company"),
        # Legacy and shared templates consistently use `company`; keep the
        # explicit current_company name too for newer components.
        "company": g.get("company"),
        "unread_notifications": unread,
        "request": request,
        # A route-aware operator guide is available from every authenticated
        # console page.  Keeping the content server-side makes new route
        # coverage testable and avoids shipping help text in JavaScript.
        "page_help": page_help_for(request.path) if g.get("admin") else None,
    }


# ── Jinja2 filters ────────────────────────────────────────────────────────────

@app.template_filter("timeago")
def timeago_filter(dt_str):
    """Convert ISO timestamp to 'X minutes ago' string."""
    if not dt_str:
        return "never"
    from datetime import datetime, timezone
    try:
        dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        diff = int((now - dt).total_seconds())
        if diff < 60:
            return f"{diff}s ago"
        elif diff < 3600:
            return f"{diff // 60}m ago"
        elif diff < 86400:
            return f"{diff // 3600}h ago"
        else:
            return f"{diff // 86400}d ago"
    except Exception:
        return dt_str


@app.template_filter("filesizeformat")
def filesizeformat_filter(size):
    if not size:
        return "0 B"
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


@app.template_filter("duration")
def duration_filter(started_at, ended_at=None):
    """Render an ISO timestamp interval as a compact operational duration."""
    if not started_at:
        return "—"
    from datetime import datetime, timezone
    try:
        start = datetime.fromisoformat(str(started_at).replace("Z", "+00:00"))
        end = (datetime.fromisoformat(str(ended_at).replace("Z", "+00:00"))
               if ended_at else datetime.now(timezone.utc))
        seconds = max(0, int((end - start).total_seconds()))
        if seconds < 60:
            return f"{seconds}s"
        if seconds < 3600:
            return f"{seconds // 60}m {seconds % 60}s"
        hours, remainder = divmod(seconds, 3600)
        return f"{hours}h {remainder // 60}m"
    except (TypeError, ValueError):
        return "—"


@app.template_filter("status_color")
def status_color_filter(status):
    return {
        "online": "emerald",
        "offline": "red",
        "pending": "amber",
        "running": "blue",
        "completed": "emerald",
        "failed": "red",
        "cancelled": "gray",
        "approved": "emerald",
        "denied": "red",
        "expired": "gray",
        "pending_secondary": "amber",
    }.get(status, "gray")


# ── Health check ──────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    from flask import jsonify
    import db
    try:
        db.healthcheck()
    except Exception:
        # Do not leak database/network details from a public endpoint. The
        # exception is still recorded in container logs for operators.
        log.exception("Health check failed: database unavailable")
        return jsonify({"status": "unavailable"}), 503
    from services import ws_proxy
    if not ws_proxy.is_ready():
        log.error("Health check failed: remote relay is not listening")
        return jsonify({"status": "unavailable"}), 503
    return jsonify({"status": "ok"}), 200


@app.route("/favicon.ico")
def favicon_compat():
    """Serve legacy browser favicon probes from the canonical Warden mark."""
    return redirect(url_for("static", filename="favicon.svg"), code=302)


# ── Error handlers ────────────────────────────────────────────────────────────

from services.tenant_crypto import VaultLocked
from services.vault_access import locked_vault_response
app.register_error_handler(VaultLocked, locked_vault_response)

@app.errorhandler(400)
def bad_request(e):
    if request.path.startswith("/api/"):
        from flask import jsonify
        return jsonify({"error": "Bad request"}), 400
    return render_template("errors/400.html"), 400

@app.errorhandler(401)
def unauthorized(e):
    if request.path.startswith("/api/") or request.headers.get("Accept", "").startswith("application/json"):
        from flask import jsonify
        return jsonify({"error": "Unauthorized"}), 401
    if request.headers.get("HX-Request"):
        response = app.make_response(("", 401))
        response.headers["HX-Redirect"] = url_for("auth.login")
        response.headers["Cache-Control"] = "no-store"
        return response
    return redirect(url_for("auth.login"))


@app.errorhandler(403)
def forbidden(e):
    if request.path.startswith("/api/"):
        from flask import jsonify
        return jsonify({"error": "Forbidden"}), 403
    return render_template("errors/403.html"), 403


@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        from flask import jsonify
        return jsonify({"error": "Not found"}), 404
    return render_template("errors/404.html"), 404


@app.errorhandler(500)
def server_error(e):
    log.error(f"Internal server error: {e}", exc_info=True)
    wants_json = (
        request.accept_mimetypes.best == "application/json"
        or request.path.startswith("/api/")
        or request.is_json
        or bool(request.headers.get("X-CSRFToken"))
        or request.headers.get("Sec-Fetch-Dest") == "empty"
    )
    if wants_json:
        from flask import jsonify
        return jsonify({"error": "The server could not complete this request. Please retry."}), 500
    return render_template("errors/500.html"), 500


# ── Startup ───────────────────────────────────────────────────────────────────

def start_background_services():
    import db
    from services.stale_checker import start as start_stale_checker
    from services.ws_proxy import start as start_ws_proxy
    from services.alert_engine import start as start_alert_engine
    from services.scheduler import start as start_scheduler
    try:
        # Relay pairs are process-local and cannot survive a restart. Revoke
        # their browser tokens so the UI creates a fresh session/job instead
        # of reusing a dead database row left by an unclean shutdown.
        db.close_all_active_remote_sessions()
    except Exception:
        log.exception("Could not invalidate remote sessions after relay restart")
    start_stale_checker()
    start_ws_proxy()
    start_alert_engine()
    start_scheduler()


# Start background services inside Warden's single threaded Gunicorn worker
# (preload_app=False) or when run directly. Skip in test/reload workers.
import os as _os
if _os.environ.get("WERKZEUG_RUN_MAIN") != "true":
    with app.app_context():
        start_background_services()

if __name__ == "__main__":
    log.info(f"Warden starting on {config.HOST}:{config.PORT}")
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG, use_reloader=False)
