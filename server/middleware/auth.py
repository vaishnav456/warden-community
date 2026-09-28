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

def _make_payload(admin_id, role, company_id, company_slug, is_superadmin, minutes):
    now = datetime.now(timezone.utc)
    return {
        "sub": str(admin_id),
        "role": role,
        "company_id": str(company_id) if company_id else None,
        "company_slug": company_slug,
        "superadmin": is_superadmin,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=minutes)).timestamp()),
    }


def issue_access_token(admin):
    # The current database role is the sole platform-privilege authority.
    # Email allowlists and old JWT claims must never preserve an elevation
    # after an administrator is demoted.
    is_sa = admin.get("role") == "superadmin"
    payload = _make_payload(
        admin_id=admin["id"],
        role=admin["role"],
        company_id=admin.get("company_id"),
        company_slug=admin.get("_company_slug"),
        is_superadmin=is_sa,
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
    g.is_superadmin = False

    token = get_token_from_request()
    if not token:
        return

    claims = decode_access_token(token)
    if not claims:
        return

    admin = db.get_admin_by_id(claims["sub"])
    if not admin or not admin.get("is_active"):
        return

    g.admin = admin
    # Re-evaluate privilege from the fresh database row on every request.
    # The JWT claim is informational only and cannot override a demotion.
    g.is_superadmin = admin.get("role") == "superadmin"

    if admin.get("company_id"):
        # Fetch company fresh from DB to pick up any changes after token issue
        g.company = db.get_company_by_id(admin["company_id"])
    elif g.is_superadmin and session.get("viewing_company_id"):
        # Superadmin "viewing as tenant" — see superadmin.open_company. This
        # is the ONLY way g.company gets populated for a superadmin on a
        # deployment with no per-company subdomain routing (company_slug is
        # never set without one — see app.py's host-parsing); company_slug
        # remains the mechanism for deployments that do have it.
        g.company = db.get_company_by_id(session["viewing_company_id"])
        if g.company is None:
            session.pop("viewing_company_id", None)


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
        # MFA is a platform privilege boundary, not merely an /admin page
        # decoration. A superadmin may also enter a tenant console through a
        # time-limited support grant, where routes use login_required and
        # company/role checks instead of superadmin_required. Fail closed here
        # so an old pre-MFA session cannot use that alternate path.
        if (getattr(g, "is_superadmin", False)
                and not g.admin.get("mfa_enabled")
                and request.endpoint not in {
                    "auth.setup_mfa", "auth.setup_mfa_confirm",
                    "auth.change_password",
                }):
            if request.headers.get("Accept", "").startswith("application/json"):
                abort(403)
            if request.headers.get("HX-Request"):
                response = make_response("", 403)
                response.headers["HX-Redirect"] = url_for("auth.setup_mfa")
                response.headers["Cache-Control"] = "no-store"
                return response
            return redirect(url_for("auth.setup_mfa"))
        return f(*args, **kwargs)
    return decorated


def superadmin_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not g.is_superadmin:
            if request.headers.get("Accept", "").startswith("application/json"):
                abort(403)
            abort(403)
        # Platform administrators can reach every control-plane function.
        # Require MFA before permitting that privilege, even if an old access
        # token was issued before MFA enforcement was enabled.
        if not g.admin.get("mfa_enabled"):
            if request.headers.get("Accept", "").startswith("application/json"):
                abort(403)
            return redirect(url_for("auth.setup_mfa"))
        return f(*args, **kwargs)
    return decorated


def role_required(*roles):
    """Require the admin to have one of the specified roles."""
    def decorator(f):
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            if g.admin is None:
                abort(401)
            if g.is_superadmin:
                return f(*args, **kwargs)
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
    in the same company. superadmin/company_admin/technician are
    unrestricted by branch and this is a no-op for them; call this
    unconditionally right after the existing company_id ownership check,
    the same way that check itself is unconditional."""
    if g.admin.get("role") != "branch_admin":
        return
    admin_branch_id = g.admin.get("branch_id")
    if not admin_branch_id or str(admin_branch_id) != str(resource_branch_id):
        abort(403)


def company_required(f):
    """Ensure request is in the context of a valid company (slug subdomain).

    A superadmin viewing a company that isn't their own home company is
    "the platform looking at tenant data" — gated on an active,
    tenant-approved access grant (see db.py's tenant_access_grants
    helpers and routes for the request/approve/deny flow), not
    unconditionally available just because the account has the
    superadmin flag. This is an application-enforced boundary (the
    running server always technically *can* decrypt — see
    services/tenant_crypto.py's module docstring) but it closes the gap
    where any superadmin session could browse any tenant's console
    with zero tenant involvement or audit trail."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if g.company is None:
            # Superadmins on a company subdomain still need g.company populated
            if g.is_superadmin and g.get("company_slug"):
                g.company = db.get_company_by_slug(g.company_slug)
            if g.company is None and not g.is_superadmin:
                abort(403)
            if g.company is None:
                abort(403)
        if g.is_superadmin and str(g.company["id"]) != str(g.admin.get("company_id")):
            if not db.has_active_access_grant(g.company["id"], g.admin["id"]):
                if request.headers.get("Accept", "").startswith("application/json"):
                    abort(403)
                return redirect(url_for("superadmin.request_access", company_id=g.company["id"]))
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
