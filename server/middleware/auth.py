"""
Warden — Auth middleware
JWT-based authentication using HMAC-SHA256.
All tokens are stateless access tokens + stateful refresh tokens (server-side blacklist).
"""
import jwt
import hashlib
import functools
import secrets
from datetime import datetime, timezone, timedelta
from flask import request, session, redirect, url_for, g, abort, make_response

import config
import db

# ── Token generation ─────────────────────────────────────────────────────────

def _make_payload(admin_id, role, company_id, minutes):
    now = datetime.now(timezone.utc)
    return {
        "sub": str(admin_id),
        "role": role,
        "company_id": str(company_id) if company_id else None,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=minutes)).timestamp()),
    }


def issue_access_token(admin):
    payload = _make_payload(
        admin_id=admin["id"],
        role=admin["role"],
        company_id=admin.get("company_id"),
        minutes=config.JWT_ACCESS_MINUTES,
    )
    return jwt.encode(payload, config.SECRET_KEY, algorithm="HS256")


def issue_refresh_token(admin_id, ip, user_agent):
    import secrets
    token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expires_at = (
        datetime.now(timezone.utc) + timedelta(days=config.JWT_REFRESH_DAYS)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    absolute_expires_at = (
        datetime.now(timezone.utc) + timedelta(hours=config.SESSION_ABSOLUTE_HOURS)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    db.create_refresh_token(
        admin_id, token_hash, ip, user_agent, expires_at, absolute_expires_at
    )
    return token


def rotate_refresh_token(old_token, ip, user_agent):
    """Atomically consume a refresh token and create its successor."""
    import secrets
    new_token = secrets.token_urlsafe(48)
    expires_at = (
        datetime.now(timezone.utc) + timedelta(days=config.JWT_REFRESH_DAYS)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    stored = db.rotate_refresh_token(
        hashlib.sha256(old_token.encode()).hexdigest(),
        hashlib.sha256(new_token.encode()).hexdigest(),
        ip, user_agent, expires_at,
    )
    return (new_token, stored) if stored else (None, None)


def decode_access_token(token):
    try:
        return jwt.decode(token, config.SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


# ── Request helpers ───────────────────────────────────────────────────────────

def get_token_from_request():
    """Extract JWT from cookie or Authorization header."""
    # Cookie takes priority (browser sessions)
    token = request.cookies.get("warden_token")
    if token:
        return token
    # Bearer header for API clients
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return None


def load_current_user():
    """Populate g.admin if a valid token is present."""
    g.admin = None
    g.company = None

    token = get_token_from_request()
    if not token:
        return

    claims = decode_access_token(token)
    if not claims:
        return

    admin = db.get_admin_by_id(claims["sub"])
    if not admin or not admin.get("is_active"):
        return

    if admin.get("role") not in {"company_admin", "branch_admin", "technician"} or not admin.get("company_id"):
        return
    company = db.get_single_company()
    if str(admin["company_id"]) != str(company["id"]):
        return
    g.company = db.ensure_company_encryption(company)
    g.admin = admin


# ── Decorators ────────────────────────────────────────────────────────────────

def login_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if g.admin is None:
            if request.headers.get("Accept", "").startswith("application/json"):
                abort(401)
            # A normal redirect is followed by XMLHttpRequest. HTMX would
            # then swap the complete login document into the polling
            # element that made the request (for example a sidebar badge),
            # leaving the authenticated shell visible around it.
            if request.headers.get("HX-Request"):
                response = make_response("", 401)
                response.headers["HX-Redirect"] = url_for("auth.login")
                response.headers["Cache-Control"] = "no-store"
                return response
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated


def role_required(*roles):
    """Require the admin to have one of the specified roles."""
    def decorator(f):
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            if g.admin is None:
                abort(401)
            if g.admin.get("role") not in roles:
                abort(403)
            return f(*args, **kwargs)
        return decorated
    return decorator


def require_branch_scope(resource_branch_id):
    """Call after fetching a resource (endpoint/job/escalation/schedule/
    saved-policy/app) whose company_id has already been checked against
    g.company. A `branch_admin` is meant to be scoped to a single branch
    (branch_id is set on their admin_users row at creation — see
    routes/users.py) but every route that allows the branch_admin role
    only ever checked company_id, never branch_id — letting a branch
    admin dispatch/approve/view resources belonging to any OTHER branch
    in the same company. company_admin/technician are unrestricted by branch
    and this is a no-op for them; call this
    unconditionally right after the existing company_id ownership check,
    the same way that check itself is unconditional."""
    if g.admin.get("role") != "branch_admin":
        return
    admin_branch_id = g.admin.get("branch_id")
    if not admin_branch_id or str(admin_branch_id) != str(resource_branch_id):
        abort(403)


def company_required(f):
    """Require the authenticated administrator's single organization."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if g.company is None:
            abort(403)
        return f(*args, **kwargs)
    return decorated


# ── Agent API key auth ────────────────────────────────────────────────────────

def agent_auth_required(f):
    """Authenticate Windows agent via X-Agent-Key header, plus an mTLS
    client-certificate cross-check when config.REQUIRE_CLIENT_CERT is
    enabled (see services/agent_ca.py). The X-Agent-Key alone identifies
    *which* endpoint is calling; the cert check additionally proves the
    caller holds the private key issued to that specific endpoint at
    enrollment — a leaked API key alone is not enough without it."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get("X-Agent-Key", "")
        if not api_key:
            abort(401)
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        endpoint = db.get_endpoint_by_api_key_hash(key_hash)
        if not endpoint:
            abort(401)

        if config.REQUIRE_CLIENT_CERT:
            # Cf-Client-Cert-Sha256 is only trustworthy if Cloudflare's edge
            # is the ONLY way to reach this origin — otherwise it's just a
            # client-supplied header, and anyone holding a leaked API key
            # could read that endpoint's own (public) certificate off the
            # Windows box and set this header themselves, defeating the
            # entire point of the mTLS check. TRUST_CLOUDFLARE is the same
            # "is Cloudflare confirmed to be the sole ingress path" flag
            # middleware/security.py's get_client_ip() already gates
            # CF-Connecting-IP behind — reuse it here rather than trusting
            # this header unconditionally just because REQUIRE_CLIENT_CERT
            # is on. Enforcing that origin-is-firewalled-to-Cloudflare
            # property is outside this code (network/firewall config), not
            # something Flask can verify from a header alone.
            if not config.TRUST_CLOUDFLARE:
                abort(500)
            expected_fp = (endpoint.get("client_cert_fingerprint") or "").lower().replace(":", "")
            presented_fp = request.headers.get("Cf-Client-Cert-Sha256", "").lower().replace(":", "")
            # Both must be present and match — a missing expected_fp (this
            # endpoint never got a cert issued) or a missing presented_fp
            # (request didn't actually go through Cloudflare's mTLS check,
            # or client_certificate_forwarding isn't enabled on the zone)
            # both fail closed rather than silently skipping the check.
            if not expected_fp or not presented_fp or expected_fp != presented_fp:
                abort(401)

        g.endpoint = endpoint
        return f(*args, **kwargs)
    return decorated


# ── Build service auth ────────────────────────────────────────────────────────

def build_service_auth_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-Build-Key", "")
        if not key or not secrets.compare_digest(key, config.BUILD_SERVICE_KEY):
            abort(401)
        return f(*args, **kwargs)
    return decorated
