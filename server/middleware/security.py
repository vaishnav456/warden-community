"""
Warden — Security middleware
Rate limiting and security headers.
Command signing lives in services/signing.py (Ed25519).
"""
import time
import collections
import hashlib
import hmac
import logging
from flask import request, Response, g

import config

log = logging.getLogger("warden.security")

# ── Security headers ──────────────────────────────────────────────────────────


def _build_csp(nonce):
    # style-src/script-src deliberately have no 'unsafe-inline' — the
    # All library code, CSS, and fonts are served from this application.
    #
    # The one extra style-src hash below allowlists htmx's own internal
    # "pantry" element (a fixed, library-internal `element.style.display =
    # "none"` write during every swap — see bigskysoftware/htmx#3753),
    # which happens on every htmx swap regardless of the
    # includeIndicatorStyles config (that only covers a different code
    # path). Its content never varies, so a specific hash allowlists it
    # without granting 'unsafe-inline' generally — only surfaced once a
    # real innerHTML-swap polling page (status/_cards.html) was actually
    # exercised with real data.
    htmx_pantry_hash = "'sha256-+7qUlNrO8BxbweVdN+eERhupOkXork7tmcC7UrvosHM='"
    return (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"style-src 'self' 'nonce-{nonce}' {htmx_pantry_hash}; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "manifest-src 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self';"
    )


def apply_security_headers(response):
    response.headers["Content-Security-Policy"] = _build_csp(g.get("csp_nonce", ""))
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Preserve route-specific stricter policies. One-time setup URLs contain
    # bearer tokens and explicitly use ``no-referrer`` so the token cannot be
    # leaked through navigation to another origin.
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    if config.SESSION_COOKIE_SECURE:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )
    return response


# ── Rate limiting (in-memory, per-IP) ─────────────────────────────────────────
# Simple token bucket; for production use Flask-Limiter with Redis
_rate_buckets = {}
_RATE_WINDOW = 60  # seconds


def get_client_ip():
    # If fronted by Cloudflare Tunnel, prefer CF-Connecting-IP: Cloudflare
    # sets it authoritatively for any request that actually passed through
    # their edge (unlike X-Forwarded-For, which is just whatever the
    # immediate hop reports and can accumulate spoofed entries from
    # further upstream). Only trust it when cloudflared is actually the
    # configured front door — see config.TRUST_CLOUDFLARE.
    if config.TRUST_CLOUDFLARE:
        cf_ip = request.headers.get("CF-Connecting-IP", "").strip()
        if cf_ip:
            return cf_ip
    # Otherwise: ProxyFix (app.py) rewrites remote_addr from the single trusted
    # X-Forwarded-For hop supplied by Caddy, the only process that can reach
    # this app (127.0.0.1-bound).
    return (request.remote_addr or "").strip()


# ── App-level firewall (controllable IP block list) ──────────────────────────
# Deliberately app-scoped, not host-wide iptables/ufw: Warden may share a host,
# and application middleware must not silently change the host network policy.
# Admins manage
# the block list in the database, backed by
# endpt.firewall_blocked_ips. Cached briefly so normal request handling
# doesn't take a DB round-trip on every request.
_FIREWALL_CACHE_TTL = 30  # seconds — normal refresh interval on success
_FIREWALL_RETRY_TTL = 5   # seconds — shorter backoff after a failed refresh, so a
                           # blip doesn't wedge the cache for a full TTL, but a
                           # sustained outage doesn't hammer the DB every request either
_firewall_cache = {"blocked": set(), "loaded_at": 0.0, "last_attempt": 0.0}


def _refresh_firewall_cache():
    import db
    _firewall_cache["last_attempt"] = time.time()
    try:
        rows = db.list_blocked_ips()
    except Exception:
        return  # keep serving the last-known (fail-closed) list if Supabase is briefly unreachable
    now = time.time()
    active = set()
    for row in rows:
        expires_at = row.get("expires_at")
        if expires_at:
            try:
                from datetime import datetime, timezone
                exp = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                if exp <= datetime.now(timezone.utc):
                    continue
            except ValueError:
                pass
        active.add(row["ip_address"])
    _firewall_cache["blocked"] = active
    _firewall_cache["loaded_at"] = now


def is_ip_firewalled(ip: str) -> bool:
    """Return True if `ip` should be rejected before any other request handling."""
    if not ip:
        return False
    now = time.time()
    stale = now - _firewall_cache["loaded_at"] > _FIREWALL_CACHE_TTL
    retry_due = now - _firewall_cache["last_attempt"] > _FIREWALL_RETRY_TTL
    if stale and retry_due:
        _refresh_firewall_cache()
    return ip in _firewall_cache["blocked"]


def check_firewall():
    """Call at the very top of before_request. Returns a 403 Response if blocked, else None."""
    if is_ip_firewalled(get_client_ip()):
        return Response("Forbidden", status=403)
    return None


def check_rate_limit(key_suffix, max_requests, *, fail_closed=False):
    ip = get_client_ip()
    key = f"{ip}:{key_suffix}"
    # Use an HMAC so the durable rate-limit table never stores raw client IPs
    # or password-reset/setup tokens. The value remains stable across workers
    # and replicas that share the same SECRET_KEY.
    durable_key = hmac.new(
        config.SECRET_KEY.encode(), key.encode(), hashlib.sha256
    ).hexdigest()
    try:
        import db
        return db.consume_rate_limit(durable_key, max_requests, _RATE_WINDOW)
    except Exception:
        # Authentication must remain available during a brief PostgREST
        # failure. Fall back to the conservative process-local limiter and
        # emit a security signal so operators know distributed enforcement
        # was degraded.
        log.warning("Distributed rate limiter unavailable; using local fallback")
        if fail_closed:
            return False

    now = time.time()
    # Prune every stale bucket, not only the current IP. The old code created
    # an empty bucket and immediately deleted/accepted it before recording the
    # request, so every login attempt was effectively the "first" attempt.
    for bucket_key, timestamps in list(_rate_buckets.items()):
        fresh = [t for t in timestamps if now - t < _RATE_WINDOW]
        if fresh:
            _rate_buckets[bucket_key] = fresh
        else:
            del _rate_buckets[bucket_key]

    bucket = _rate_buckets.setdefault(key, [])
    if len(bucket) >= max_requests:
        return False
    bucket.append(now)
    return True
