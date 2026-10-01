"""
Warden Server — Configuration
Loads environment from .env in the server directory.
"""
import os as _os
import pathlib as _pathlib
import secrets as _secrets

_env_file = _pathlib.Path(__file__).parent / ".env"
if _env_file.exists():
    for _line in _env_file.read_text().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _, _v = _line.partition("=")
            _os.environ.setdefault(_k.strip(), _v.strip())

# ── Supabase ────────────────────────────────────────────────────────────────
SUPABASE_URL = _os.environ["SUPABASE_URL"]
SUPABASE_SERVICE_KEY = _os.environ["SUPABASE_SERVICE_KEY"]

# ── Flask ────────────────────────────────────────────────────────────────────
SECRET_KEY = _os.environ.get("SECRET_KEY") or ""
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY env var is not set — set it to a random hex-32 string")
DEBUG = _os.environ.get("DEBUG", "false").lower() == "true"
PORT = int(_os.environ.get("PORT", "35020"))
HOST = _os.environ.get("HOST", "127.0.0.1")

# Set to true ONLY when cloudflared (Cloudflare Tunnel) is the sole ingress
# path to this app — it makes middleware/security.py trust the
# CF-Connecting-IP header for firewall/rate-limit IP checks. Trusting that
# header when Cloudflare is NOT actually the only way in would let any
# direct caller spoof their own CF-Connecting-IP and bypass the IP
# block-list entirely. Off by default (matches the existing Caddy-fronted
# deployment, which relies on ProxyFix + X-Forwarded-For instead).
TRUST_CLOUDFLARE = _os.environ.get("TRUST_CLOUDFLARE", "false").lower() == "true"

# ── Cloudflare Client Certificates (mTLS) ────────────────────────────────────
# See server/services/agent_ca.py and docs/MTLS_DEPLOYMENT.md.
# CLOUDFLARE_API_TOKEN needs the "SSL and Certificates: Edit" permission
# scoped to CLOUDFLARE_ZONE_ID (the zone id for the Warden API's hostname).
CLOUDFLARE_API_TOKEN = _os.environ.get("CLOUDFLARE_API_TOKEN", "").strip()
CLOUDFLARE_ZONE_ID = _os.environ.get("CLOUDFLARE_ZONE_ID", "").strip()
# Set to true ONLY once: (a) TRUST_CLOUDFLARE is also true, (b) mTLS is
# enabled for the relevant hostname in the Cloudflare dashboard/API, (c)
# client_certificate_forwarding is enabled on the zone (so
# Cf-Client-Cert-Sha256 actually arrives), AND (d) the origin server is
# firewalled so it's ONLY reachable through Cloudflare's edge (e.g. via
# cloudflared, or an allowlist of Cloudflare's published IP ranges) — (d)
# is enforced at the network layer, not by this code, but is just as
# required as the other three: without it, Cf-Client-Cert-Sha256 is only
# a client-supplied header anyone reaching the origin directly could set
# themselves, and middleware/auth.py's agent_auth_required() will refuse
# to honor it (fails closed with a 500) if TRUST_CLOUDFLARE isn't also
# true, precisely because that combination can't be verified from here.
# Before all four are true, REQUIRE_CLIENT_CERT must stay false —
# turning it on prematurely means agent_auth_required rejects every
# request for lacking a header Cloudflare was never told to send.
REQUIRE_CLIENT_CERT = _os.environ.get("REQUIRE_CLIENT_CERT", "false").lower() == "true"
if REQUIRE_CLIENT_CERT and not TRUST_CLOUDFLARE:
    raise RuntimeError(
        "REQUIRE_CLIENT_CERT requires TRUST_CLOUDFLARE and an origin reachable only through the trusted proxy"
    )

# Warden-managed endpoint/Home Node identities. These private certificates
# are independent of the public HTTPS certificate and have no per-device
# provider quota. Mount DEVICE_CA_DIR on durable, restricted storage.
DEVICE_CERTIFICATES_ENABLED = _os.environ.get("DEVICE_CERTIFICATES_ENABLED", "true").lower() == "true"
DEVICE_CERT_VALIDITY_DAYS = int(_os.environ.get("DEVICE_CERT_VALIDITY_DAYS", "7"))
DEVICE_CERT_CLOCK_SKEW_HOURS = int(_os.environ.get("DEVICE_CERT_CLOCK_SKEW_HOURS", "24"))
DEVICE_CA_DIR = _pathlib.Path(_os.environ.get("DEVICE_CA_DIR", "/var/lib/warden/device-ca"))
DEVICE_CA_AUTO_BOOTSTRAP = _os.environ.get("DEVICE_CA_AUTO_BOOTSTRAP", "true").lower() == "true"
HOME_P2P_STUN_URLS = [
    value.strip() for value in _os.environ.get(
        "HOME_P2P_STUN_URLS",
        "stun:stun.cloudflare.com:3478,stun:stun.l.google.com:19302,stun:stun1.l.google.com:19302",
    ).split(",") if value.strip()
]
HOME_NODE_VERSION = _os.environ.get("HOME_NODE_VERSION", "1.1.6").strip()

# ── Organization encryption ──────────────────────────────────────────────────
# See services/tenant_crypto.py. The environment-variable and module names are
# retained for upgrade compatibility. This wraps the single organization's DEK
# and is never used to encrypt application data directly.
# Generate with: python3 -c "import secrets,base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"
TENANT_MASTER_KEK_B64 = _os.environ.get("TENANT_MASTER_KEK_B64", "").strip()

# ── Auth ─────────────────────────────────────────────────────────────────────
JWT_ACCESS_MINUTES = int(_os.environ.get("JWT_ACCESS_MINUTES", "15"))
JWT_REFRESH_DAYS = int(_os.environ.get("JWT_REFRESH_DAYS", "7"))
SESSION_IDLE_MINUTES = int(_os.environ.get("SESSION_IDLE_MINUTES", "15"))
SESSION_ABSOLUTE_HOURS = int(_os.environ.get("SESSION_ABSOLUTE_HOURS", "12"))
SESSION_COOKIE_SECURE = _os.environ.get("SESSION_COOKIE_SECURE", "true").lower() == "true"
MAX_FAILED_LOGINS = int(_os.environ.get("MAX_FAILED_LOGINS", "5"))
LOCKOUT_MINUTES = int(_os.environ.get("LOCKOUT_MINUTES", "15"))
MAX_CONCURRENT_SESSIONS = int(_os.environ.get("MAX_CONCURRENT_SESSIONS", "3"))

# ── Ed25519 command signing ───────────────────────────────────────────────────
# Generate a keypair once: python -c "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey; import base64; k=Ed25519PrivateKey.generate(); print(base64.b64encode(k.private_bytes_raw()).decode())"
ED25519_PRIVATE_KEY_B64 = _os.environ.get("ED25519_PRIVATE_KEY_B64", "")
COMMAND_MAX_AGE_SEC = int(_os.environ.get("COMMAND_MAX_AGE_SEC", "60"))
REQUIRE_SIGNED_WINDOWS_APPS = _os.environ.get(
    "REQUIRE_SIGNED_WINDOWS_APPS", "true"
).lower() == "true"

# ── Server URL (used to build relay_url for agents) ───────────────────────────
# Set SERVER_URL to the public-facing base URL of the API, e.g. https://warden.example.com
# The TLS pin baked into new installers is fetched live at generate-installer
# time (services/cert_fingerprint.py), not read from a static config value —
# it would otherwise go stale every time Cloudflare rotates its edge cert.
SERVER_URL = _os.environ.get("SERVER_URL", "https://warden.example.com")

# ── Operator branding ───────────────────────────────────────────────────────
# These values affect human-facing console and sign-in surfaces only. Stable
# protocol names, on-disk paths, Windows service identifiers, API routes, and
# database schema names deliberately remain "warden" so rebranding cannot
# break upgrades or strand enrolled devices.
BRAND_NAME = (_os.environ.get("BRAND_NAME", "Warden").strip() or "Warden")[:64]
BRAND_TAGLINE = (
    _os.environ.get("BRAND_TAGLINE", "Endpoint control, made clear.").strip()
    or "Endpoint control, made clear."
)[:160]
BRAND_LOGO_PATH = _os.environ.get("BRAND_LOGO_PATH", "").strip()
if BRAND_LOGO_PATH and (
    not BRAND_LOGO_PATH.startswith("/static/")
    or ".." in BRAND_LOGO_PATH
    or "\\" in BRAND_LOGO_PATH
    or BRAND_LOGO_PATH.startswith("//")
):
    raise RuntimeError(
        "BRAND_LOGO_PATH must be a same-origin /static/... path without traversal"
    )

# ── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR = _pathlib.Path(__file__).parent
UPLOAD_DIR = BASE_DIR.parent / "uploads"
AGENT_DIST_DIR = BASE_DIR.parent / "agent-dist"
HOME_NODE_DIST_DIR = BASE_DIR.parent / "home-node-dist"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
AGENT_DIST_DIR.mkdir(parents=True, exist_ok=True)

# ── Rate limiting ─────────────────────────────────────────────────────────────
RATE_LIMIT_LOGIN = "10 per minute"
RATE_LIMIT_API = "200 per minute"
RATE_LIMIT_ENROLL = "5 per minute"

# ── Enrollment tokens ─────────────────────────────────────────────────────────
ENROLL_TOKEN_HOURS = int(_os.environ.get("ENROLL_TOKEN_HOURS", "24"))

# ── Escalation ───────────────────────────────────────────────────────────────
ESCALATION_WINDOW_MINUTES = int(_os.environ.get("ESCALATION_WINDOW_MINUTES", "15"))

# ── Build service ─────────────────────────────────────────────────────────────
BUILD_SERVICE_KEY = _os.environ.get("BUILD_SERVICE_KEY") or ""
if not BUILD_SERVICE_KEY:
    raise RuntimeError("BUILD_SERVICE_KEY env var is not set")
