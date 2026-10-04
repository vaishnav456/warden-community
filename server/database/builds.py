"""Builds database operations."""


def create_build_request(company_id, branch_id, enrollment_token_id, config_json, created_by,
                         target_platform="windows-amd64"):
    import db as _db
    rows = _db._post("build_requests", {
        "company_id": company_id,
        "branch_id": branch_id,
        "enrollment_token_id": enrollment_token_id,
        "config_json": config_json,
        "status": "pending",
        "requested_by": created_by,
        "target_platform": target_platform,
    })
    return rows[0] if (rows and isinstance(rows, list)) else rows

def fail_claimed_build(req_id, claim_token, error):
    """A delayed failure report cannot overwrite a completed/reclaimed build."""
    import db as _db
    return bool(_db._patch(
        f"build_requests?id=eq.{_db._q(req_id)}&claim_token=eq.{_db._q(claim_token)}&status=eq.building",
        {"status": "failed", "build_log": error[:4000], "updated_at": _db._now_iso(), "lease_expires_at": None},
    ))

def get_build_request(req_id):
    import db as _db
    rows = _db._get(f"build_requests?id=eq.{_db._q(req_id)}&limit=1")
    return rows[0] if rows else None

def get_pending_build_requests():
    import db as _db
    return _db._get("build_requests?status=eq.pending&order=created_at.asc&limit=5")

def get_build_requests(company_id, limit=20):
    import db as _db
    return _db._get(
        f"build_requests?company_id=eq.{_db._q(company_id)}"
        f"&order=created_at.desc&limit={limit}"
    )

def update_build_request(req_id, status, artifact_url=None, error=None, sha256=None, agent_version=None):
    import db as _db
    data = {"status": status}
    if artifact_url:
        data["download_path"] = artifact_url
    if error:
        data["build_log"] = str(error)[:4000]
    if sha256:
        data["sha256"] = sha256
    if agent_version:
        data["agent_version"] = agent_version
    if status == "completed":
        data["completed_at"] = _db._now_iso()
    _db._patch(f"build_requests?id=eq.{_db._q(req_id)}", data)

def complete_claimed_build(req_id, claim_token, artifact_url, sha256=None, agent_version=None):
    import db as _db
    data = {
        "status": "completed", "download_path": artifact_url,
        "completed_at": _db._now_iso(), "lease_expires_at": None,
    }
    if sha256:
        data["sha256"] = sha256
    if agent_version:
        data["agent_version"] = agent_version
    rows = _db._patch(
        f"build_requests?id=eq.{_db._q(req_id)}&status=eq.building"
        f"&claim_token=eq.{_db._q(claim_token)}",
        data,
    )
    return bool(rows)

def mark_build_msi_ready(req_id):
    import db as _db
    _db._patch(f"build_requests?id=eq.{_db._q(req_id)}", {"msi_ready": True})

def mark_claimed_build_msi_ready(req_id, claim_token):
    import db as _db
    rows = _db._patch(
        f"build_requests?id=eq.{_db._q(req_id)}&status=eq.completed"
        f"&claim_token=eq.{_db._q(claim_token)}",
        {"msi_ready": True},
    )
    return bool(rows)

def get_latest_completed_build(target_platform="windows-amd64", *, summary_only=False):
    """The most recent successfully completed agent build, across ALL
    tenants — the compiled exe is byte-identical regardless of which
    tenant's config.json a given build bundled alongside it (only
    config.json is per-tenant; the binary itself isn't), so any completed
    build can serve as the canonical "latest agent" for UPDATE_AGENT jobs.
    """
    import db as _db
    projection = "&select=agent_version" if summary_only else ""
    rows = _db._get(
        "build_requests?status=eq.completed&sha256=not.is.null"
        f"&target_platform=eq.{_db._q(target_platform)}&order=completed_at.desc&limit=1"
        + projection
    )
    return rows[0] if rows else None

def endpoint_target_platform(endpoint):
    import db as _db
    platform = str(endpoint.get("platform") or "windows").lower()
    arch = str(endpoint.get("arch") or "amd64").lower()
    if arch in {"x86_64", "x64", "amd64"}:
        arch = "amd64"
    elif arch in {"aarch64", "arm64"}:
        arch = "arm64"
    else:
        arch = "amd64"
    if platform == "windows":
        arch = "amd64"
    return f"{platform}-{arch}"
