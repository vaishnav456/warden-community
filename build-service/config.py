"""
config.py — Warden Build Service Configuration
------------------------------------------------
Loads environment variables from a .env file in the build-service directory
and exposes typed constants.

Uses the same dotenv-parse pattern as printer-agent/config.py: read .env,
split on first '=', os.environ.setdefault each key. Fail loud if required
vars are missing (raise RuntimeError at import time).

Required .env variables:
    SUPABASE_URL       — PostgREST base URL (self-hosted, see db-init/)
    SUPABASE_KEY       — service_role JWT for the endpt schema
    AGENT_GO_SOURCE_DIR — absolute path to warden/agent-go/ (mounted into
                          this container read-only, see docker-compose.yml)
    OUTPUT_DIR         — absolute path to write zip outputs before upload
    WARDEN_SERVER_URL  — Warden API base URL for the upload endpoint

Optional .env variables:
    POLL_INTERVAL_SEC     — seconds between build queue polls (default 15)
    SIGN_PFX_PATH         — path to a .pfx code-signing cert. Signed via
                            osslsigncode (Linux-native, no Windows needed —
                            see builder.py's sign_binary()).
    SIGN_PFX_PASSWORD     — password for SIGN_PFX_PATH
    SIGNING_REQUIRED      — fail the build unless signing is configured and
                            succeeds (default false until the production
                            certificate is provisioned).
    REQUIRE_AUTHENTICODE_UPDATES — make installed agents require Windows to
                            trust the complete signer chain on every update.
                            Enable only when the signer root is deployed to
                            every endpoint (default false). Pinned HTTPS plus
                            the server-provided SHA-256 remain mandatory.
    SIGN_TIMESTAMP_URL   — RFC 3161 timestamp service URL.
    SIGN_CERT_THUMBPRINT  — Windows cert-store thumbprint. NOT supported
                            here (no Linux equivalent) — setting this fails
                            the build loudly rather than silently skipping;
                            use SIGN_PFX_PATH instead, or sign separately on
                            a real Windows host.
    If SIGN_PFX_PATH isn't set, built agents ship unsigned (logged as a
    warning, not a build failure) — see
    agent-go/POLICY_ASSETS.md, which notes the applocker-pin-warden-publisher
    policy template is non-functional without a real signing cert.
"""

import os as _os
import pathlib as _pathlib
import re as _re

# Load .env from the build-service directory
_env_file = _pathlib.Path(__file__).parent / ".env"
if _env_file.exists():
    for _line in _env_file.read_text().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _, _v = _line.partition("=")
            _os.environ.setdefault(_k.strip(), _v.strip())


def _require(name: str) -> str:
    """Read a required environment variable; raise RuntimeError if absent."""
    val = _os.environ.get(name)
    if not val:
        raise RuntimeError(
            f"Warden Build Service: required env var {name} is not set. "
            f"Add it to {_env_file}"
        )
    return val


SUPABASE_URL       = _require("SUPABASE_URL")
SUPABASE_KEY       = _require("SUPABASE_KEY")
AGENT_GO_SOURCE_DIR = _pathlib.Path(_require("AGENT_GO_SOURCE_DIR"))
AGENT_POSIX_SOURCE_DIR = _pathlib.Path(
    _os.environ.get("AGENT_POSIX_SOURCE_DIR", "/agent-posix")
)
CREDENTIAL_PROVIDER_SOURCE_DIR = _pathlib.Path(
    _os.environ.get("CREDENTIAL_PROVIDER_SOURCE_DIR", "/windows-credential-provider")
)
CREDENTIAL_PROVIDER_BINARY = _pathlib.Path(
    _os.environ.get(
        "CREDENTIAL_PROVIDER_BINARY",
        str(CREDENTIAL_PROVIDER_SOURCE_DIR / "dist" / "WardenCredentialProvider.dll"),
    )
)
GO_BINARY = _os.environ.get("GO_BINARY", "/usr/local/go/bin/go").strip()
OUTPUT_DIR         = _pathlib.Path(_require("OUTPUT_DIR"))
WARDEN_SERVER_URL  = _require("WARDEN_SERVER_URL")
BUILD_SERVICE_KEY  = _require("BUILD_SERVICE_KEY")

# Human-facing metadata only. Stable service/path/protocol identifiers remain
# WardenAgent so differently branded builds can still update and uninstall.
AGENT_DISPLAY_NAME = _os.environ.get(
    "AGENT_DISPLAY_NAME", "Warden Endpoint Agent"
).strip()
AGENT_MANUFACTURER = _os.environ.get("AGENT_MANUFACTURER", "Warden").strip()
for _label, _value in {
    "AGENT_DISPLAY_NAME": AGENT_DISPLAY_NAME,
    "AGENT_MANUFACTURER": AGENT_MANUFACTURER,
}.items():
    if not _value or len(_value) > 80 or _re.search(r"[\x00-\x1f\x7f]", _value):
        raise RuntimeError(f"{_label} must be 1-80 printable characters")

POLL_INTERVAL_SEC = int(_os.environ.get("POLL_INTERVAL_SEC", "15"))

# Code signing — optional. See module docstring above.
SIGN_CERT_THUMBPRINT = _os.environ.get("SIGN_CERT_THUMBPRINT", "").strip()
SIGN_PFX_PATH = _os.environ.get("SIGN_PFX_PATH", "").strip()
SIGN_PFX_PASSWORD = _os.environ.get("SIGN_PFX_PASSWORD", "").strip()
SIGNING_REQUIRED = _os.environ.get("SIGNING_REQUIRED", "false").strip().lower() in {
    "1", "true", "yes", "on",
}
REQUIRE_AUTHENTICODE_UPDATES = _os.environ.get(
    "REQUIRE_AUTHENTICODE_UPDATES", "false"
).strip().lower() in {"1", "true", "yes", "on"}
SIGN_TIMESTAMP_URL = _os.environ.get(
    "SIGN_TIMESTAMP_URL", "http://timestamp.digicert.com"
).strip()

if SIGNING_REQUIRED and not SIGN_PFX_PATH:
    raise RuntimeError(
        "SIGNING_REQUIRED is enabled but SIGN_PFX_PATH is not configured"
    )

# Validate at import time. http:// is only safe because postgres/postgrest
# never leave the private warden-net Docker network (see server/db.py).
if not (SUPABASE_URL.startswith("https://") or SUPABASE_URL.startswith("http://")):
    raise RuntimeError(f"SUPABASE_URL must be http:// or https://, got: {SUPABASE_URL!r}")

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
