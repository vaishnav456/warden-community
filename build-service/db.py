"""
db.py — Build Service Supabase Client
----------------------------------------
Polls endpt.build_requests for queued builds and updates their status.
Uses urllib (same pattern as printer-agent/db.py) — no requests library.

SUPABASE_URL must use HTTPS. SSL context verifies against system CA bundle.
"""

import urllib.request
import urllib.parse
import json
import time
import ssl

import config

# http:// is only safe because postgres/postgrest never leave the private
# warden-net Docker network (see server/db.py's identical comment).
if not (config.SUPABASE_URL.startswith("https://") or config.SUPABASE_URL.startswith("http://")):
    raise RuntimeError(f"SUPABASE_URL must be http:// or https://, got: {config.SUPABASE_URL!r}")

_SSL_CTX = ssl.create_default_context()

_HEADERS = {
    "apikey":           config.SUPABASE_KEY,
    "Authorization":    f"Bearer {config.SUPABASE_KEY}",
    "Content-Type":     "application/json",
    "Prefer":           "return=representation",
    "Accept-Profile":   "endpt",
    "Content-Profile":  "endpt",
}


def _get(path: str) -> list:
    """
    GET /rest/v1/<path> and return parsed JSON list.

    Args:
        path: PostgREST path including query parameters

    Returns:
        list of row dicts

    Raises:
        urllib.error.HTTPError: on non-2xx response
    """
    req = urllib.request.Request(
        f"{config.SUPABASE_URL}/{path}", headers=_HEADERS
    )
    return json.loads(urllib.request.urlopen(req, timeout=10, context=_SSL_CTX).read())


def _patch(path: str, data: dict):
    """
    PATCH /rest/v1/<path> with JSON body.

    Args:
        path: PostgREST path with filter query parameters
        data: dict of fields to update

    Raises:
        urllib.error.HTTPError: on non-2xx response
    """
    body = json.dumps(data).encode()
    req = urllib.request.Request(
        f"{config.SUPABASE_URL}/{path}",
        data=body, method="PATCH", headers=_HEADERS,
    )
    raw = urllib.request.urlopen(req, timeout=10, context=_SSL_CTX).read()
    return json.loads(raw) if raw else None


def _post(path: str, data: dict):
    body = json.dumps(data).encode()
    req = urllib.request.Request(
        f"{config.SUPABASE_URL}/{path}", data=body, method="POST", headers=_HEADERS,
    )
    raw = urllib.request.urlopen(req, timeout=10, context=_SSL_CTX).read()
    return json.loads(raw) if raw else None


def claim_next_queued_build() -> dict | None:
    """Atomically claim pending work or an expired lease with fencing."""
    rows = _post("rpc/claim_next_build", {"p_lease_seconds": 900})
    return rows[0] if rows else None


def requeue_stale_builds(max_age_minutes: int = 15) -> None:
    """Compatibility no-op: claim_next_build atomically takes expired leases."""


def renew_build_claim(build_id: str, claim_token: str) -> None:
    result = _post("rpc/renew_build_claim", {
        "p_build_id": build_id, "p_claim_token": claim_token, "p_lease_seconds": 900,
    })
    if result is not True:
        raise RuntimeError("build lease was lost")


# Compatibility for callers outside this service.
next_queued_build = claim_next_queued_build


def set_build_status(build_id: str, status: str,
                     claim_token: str,
                     output_filename: str = None,
                     error_msg: str = None) -> None:
    """Update the status of a build request row."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    data = {"status": status, "updated_at": now}
    if status == "completed":
        data["completed_at"] = now
        if output_filename:
            data["output_filename"] = output_filename
    if status == "failed" and error_msg:
        data["build_log"] = error_msg[:4000]
    rows = _patch(
        f"build_requests?id=eq.{urllib.parse.quote(str(build_id))}"
        f"&claim_token=eq.{urllib.parse.quote(str(claim_token))}&status=eq.building",
        data,
    )
    if not rows:
        raise RuntimeError("build claim was lost; refusing stale status update")
    if status == "failed":
        rows = _get(
            "build_requests"
            f"?id=eq.{urllib.parse.quote(str(build_id))}"
            "&select=enrollment_token_id&limit=1"
        )
        token_id = rows[0].get("enrollment_token_id") if rows else None
        if token_id:
            _patch(
                f"enrollment_tokens?id=eq.{urllib.parse.quote(str(token_id))}",
                {"is_active": False},
            )
