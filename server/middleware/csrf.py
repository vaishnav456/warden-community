"""
csrf.py — CSRF protection for cookie-authenticated browser sessions
---------------------------------------------------------------------
Synchronizer-token pattern using Flask's built-in signed session cookie
(separate from the warden_token JWT cookie that actually authenticates a
request — this only needs to be unguessable and tied to the browser, not
carry any identity itself).

The frontend side of this was already fully wired (static/js/warden.js's
getCsrfToken() reads the <meta name="csrf-token"> tag set by base.html and
attaches it as X-CSRFToken to every fetch/XHR/HTMX request) — what was
missing was the backend: `csrf_token()` was referenced in templates but
never registered as a real function (a hard crash on every page render),
and no request ever actually validated the token.
"""
import secrets

from flask import session, request, abort


def get_csrf_token() -> str:
    """Registered as a Jinja global (see app.py) — templates call this
    directly as csrf_token()."""
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


# Blueprints that authenticate via a bearer/API-key header, not a browser
# cookie — CSRF (a forged request riding the browser's ambient cookie) does
# not apply to them, since there's no ambient credential for a malicious
# page to ride. `enroll` is a public, pre-session endpoint by design.
_CSRF_EXEMPT_BLUEPRINTS = {"agent_api", "build_service", "enroll", "status", "home_node_api"}


def csrf_protect():
    """Call from app.py's before_request, after routing (so
    request.blueprint is populated) but this doesn't depend on
    load_current_user() having run. Returns a 403 Response to abort the
    request, or None to let it proceed."""
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return None
    if request.path == "/health":
        return None
    if request.blueprint in _CSRF_EXEMPT_BLUEPRINTS:
        return None

    expected = session.get("_csrf_token")
    submitted = request.form.get("csrf_token") or request.headers.get("X-CSRFToken")
    if not submitted:
        body = request.get_json(silent=True)
        if isinstance(body, dict):
            submitted = body.get("csrf_token")

    if (not isinstance(expected, str) or not isinstance(submitted, str)
            or not expected or not submitted
            or not secrets.compare_digest(expected.encode("utf-8"), submitted.encode("utf-8"))):
        abort(403)
    return None
