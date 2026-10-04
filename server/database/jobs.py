"""Jobs database operations."""


def _decrypt_job(job, company=None):
    """Job payload/log_output/error_msg are stored encrypted per-tenant
    (see services/tenant_crypto.py) — decrypt in place before handing a
    job row back to any caller. Raises tenant_crypto.VaultLocked if the
    job's company is BYOK-mode and currently locked; callers that can't
    tolerate that (e.g. dispatching to an agent) must catch it."""
    import db as _db
    if job is None:
        return None
    company = company or _db.get_company_by_id(job["company_id"])
    if job.get("payload") is not None:
        job["payload"] = _db.decrypt_field(company, job["payload"], "job.payload")
    if job.get("log_output") is not None:
        job["log_output"] = _db.decrypt_field(company, job["log_output"], "job.log-output")
    if job.get("error_msg") is not None:
        job["error_msg"] = _db.decrypt_field(company, job["error_msg"], "job.error-message")
    if (job.get("type") == "APPLY_DEVICE_EXPERIENCE" and job.get("status") == "failed"
            and job.get("exit_code") == 408 and not job.get("error_msg")):
        job["error_msg"] = "Deployment expired after the 3-day delivery window. Redeploy it for this endpoint."
    return job

def get_jobs(company_id, endpoint_id=None, status=None, branch_id=None, limit=50, offset=0, created_since=None):
    import db as _db
    path = (
        f"jobs?company_id=eq.{_db._q(company_id)}"
        f"&order=created_at.desc&limit={limit}&offset={offset}"
    )
    if endpoint_id:
        path += f"&endpoint_id=eq.{_db._q(endpoint_id)}"
    if created_since:
        path += f"&created_at=gte.{_db._q(created_since)}"
    if status:
        path += f"&status=eq.{_db._q(status)}"
    if branch_id:
        path += f"&branch_id=eq.{_db._q(branch_id)}"
    rows = _db._get(path)
    company = _db.get_company_by_id(company_id)
    return [_db._decrypt_job(j, company) for j in rows]

def get_home_sync_jobs(company_id, status=None, branch_id=None, limit=20):
    """Read tenant-scoped Home results without exposing expiring job grants."""
    import db as _db
    path = (
        f"jobs?company_id=eq.{_db._q(company_id)}&type=eq.SYNC_WARDEN_HOME"
        "&select=id,endpoint_id,company_id,branch_id,status,created_at,started_at,"
        "completed_at,exit_code,log_output,error_msg"
        f"&order=created_at.desc&limit={min(100, max(1, int(limit)))}"
    )
    if status:
        path += f"&status=eq.{_db._q(status)}"
    if branch_id:
        path += f"&branch_id=eq.{_db._q(branch_id)}"
    company = _db.get_company_by_id(company_id)
    return [_db._decrypt_job(row, company) for row in _db._get(path)]

def get_job(job_id, decrypt=True):
    import db as _db
    rows = _db._get(f"jobs?id=eq.{_db._q(job_id)}&limit=1")
    if not rows:
        return None
    return _db._decrypt_job(rows[0]) if decrypt else rows[0]

def has_inflight_job(endpoint_id, job_type):
    """True if endpoint_id already has a not-yet-finished job of job_type
    (pending/approved/running) — used by the auto-update scheduler so a slow
    UPDATE_AGENT job (or one still waiting on the endpoint's next poll) isn't
    re-dispatched again on every 60s scheduler tick before it's had a chance
    to complete."""
    import db as _db
    rows = _db._get(
        f"jobs?endpoint_id=eq.{_db._q(endpoint_id)}&type=eq.{_db._q(job_type)}"
        f"&status=in.(pending,approved,running)&limit=1"
    )
    return bool(rows)

def get_endpoint_home_sync_jobs(company_id, endpoint_id):
    """Read sync timing without decrypting payloads or retaining Home grants."""
    import db as _db
    path = (
        f"jobs?company_id=eq.{_db._q(company_id)}&endpoint_id=eq.{_db._q(endpoint_id)}"
        "&type=eq.SYNC_WARDEN_HOME&select=id,status,created_at,completed_at"
    )
    active = _db._get(path + "&status=in.(pending,approved,running)&limit=1")
    if active:
        return active
    return _db._get(
        path + "&status=in.(completed,failed,cancelled)"
        "&order=completed_at.desc.nullslast,created_at.desc&limit=4"
    )

def has_recent_job(endpoint_id, job_type, minutes=15):
    """Return whether an operation was recently queued for this endpoint."""
    import db as _db
    cutoff = (
        _db.datetime.now(_db.timezone.utc) - _db.timedelta(minutes=max(1, int(minutes)))
    ).isoformat()
    rows = _db._get(
        f"jobs?endpoint_id=eq.{_db._q(endpoint_id)}&type=eq.{_db._q(job_type)}"
        f"&created_at=gte.{_db._q(cutoff)}&select=id&limit=1"
    )
    return bool(rows)

def has_job(endpoint_id, job_type):
    """True when this endpoint has ever received this one-shot operation."""
    import db as _db
    rows = _db._get(
        f"jobs?endpoint_id=eq.{_db._q(endpoint_id)}&type=eq.{_db._q(job_type)}"
        "&select=id&limit=1"
    )
    return bool(rows)

def create_job(company_id, branch_id, endpoint_id, job_type, payload, created_by,
               requires_dual_approval=False, escalation_id=None, expires_at=None):
    import db as _db
    if job_type == "COMPLIANCE_SCAN":
        from services.compliance_state import prepare_scan
        payload = prepare_scan(company_id, endpoint_id, payload)
    company = _db.get_company_by_id(company_id)
    data = {
        "company_id": company_id,
        "branch_id": branch_id,
        "endpoint_id": endpoint_id,
        "type": job_type,
        "payload": _db.encrypt_field(company, payload, "job.payload") if payload is not None else None,
        "status": "pending",
        "created_by": created_by,
        "requires_dual_approval": requires_dual_approval,
    }
    if expires_at:
        data["expires_at"] = expires_at
    if escalation_id:
        data["escalation_id"] = escalation_id
    if job_type == "INSTALL_APP":
        from services.package_storage import installation
        with installation(company_id, payload):
            rows = _db._post("jobs", data)
    elif job_type == "FILE_PUSH":
        from services.tenant_storage import admission
        with admission(company_id, len((data.get("payload") or "").encode("utf-8")) + 4096):
            rows = _db._post("jobs", data)
    else:
        rows = _db._post("jobs", data)
    job = rows[0] if (rows and isinstance(rows, list)) else rows
    if job:
        job["payload"] = payload  # return the plaintext the caller just gave us
    return job

def create_system_job_once(company_id, branch_id, endpoint_id, job_type, payload):
    """Atomically create scheduler work unless the same operation is active."""
    import db as _db
    if job_type == "COMPLIANCE_SCAN":
        from services.compliance_state import prepare_scan
        payload = prepare_scan(company_id, endpoint_id, payload)
    company = _db.get_company_by_id(company_id)
    params = {
        "p_company_id": str(company_id),
        "p_branch_id": str(branch_id) if branch_id else None,
        "p_endpoint_id": str(endpoint_id),
        "p_type": job_type,
        "p_encrypted_payload": _db.encrypt_field(company, payload, "job.payload") if payload is not None else None,
    }
    if job_type == "INSTALL_APP":
        from services.package_storage import installation
        with installation(company_id, payload):
            rows = _db._rpc("create_system_job_once", params) or []
    elif job_type == "FILE_PUSH":
        from services.tenant_storage import admission
        with admission(company_id, len((params["p_encrypted_payload"] or "").encode("utf-8")) + 4096):
            rows = _db._rpc("create_system_job_once", params) or []
    else:
        rows = _db._rpc("create_system_job_once", params) or []
    job = rows[0] if rows else None
    if job:
        job["payload"] = payload
    return job

def _company_for_job(job_id):
    import db as _db
    rows = _db._get(f"jobs?id=eq.{_db._q(job_id)}&select=company_id&limit=1")
    if not rows:
        return None
    return _db.get_company_by_id(rows[0]["company_id"])

def update_job_status(job_id, status, log_output=None, exit_code=None, error_msg=None):
    import db as _db
    company = _db._company_for_job(job_id) if (log_output is not None or error_msg is not None) else None
    data = {"status": status}
    if log_output is not None:
        data["log_output"] = _db.encrypt_field(company, log_output, "job.log-output")
    if exit_code is not None:
        data["exit_code"] = exit_code
    if error_msg is not None:
        data["error_msg"] = _db.encrypt_field(company, error_msg, "job.error-message")
    if status == "running":
        data["started_at"] = _db._now_iso()
    elif status in ("completed", "failed", "cancelled"):
        data["completed_at"] = _db._now_iso()
    _db._patch(f"jobs?id=eq.{_db._q(job_id)}", data)

def finish_running_job(job_id, status, log_output=None, exit_code=None, error_msg=None):
    """Atomically finish a running job.

    Only the first result report wins.  Agent HTTP retries or stale reports
    for cancelled/completed jobs return False and must not repeat downstream
    side effects such as alerts, escalation completion, or audit events.
    """
    import db as _db
    company = _db._company_for_job(job_id) if (log_output is not None or error_msg is not None) else None
    data = {
        "status": status,
        "completed_at": _db._now_iso(),
        "lease_expires_at": None,
    }
    if log_output is not None:
        data["log_output"] = _db.encrypt_field(company, log_output, "job.log-output")
    if exit_code is not None:
        data["exit_code"] = exit_code
    if error_msg is not None:
        data["error_msg"] = _db.encrypt_field(company, error_msg, "job.error-message")
    rows = _db._patch(
        f"jobs?id=eq.{_db._q(job_id)}&status=eq.running",
        data,
    )
    return bool(rows)

def claim_job_result_processing(job_id):
    import db as _db
    return bool(_db._rpc("claim_job_result_processing", {"p_job_id": str(job_id)}))

def complete_job_result_processing(job_id):
    import db as _db
    return bool(_db._rpc("complete_job_result_processing", {"p_job_id": str(job_id)}))

def append_job_log(job_id, new_lines):
    import db as _db
    rows = _db._get(f"jobs?id=eq.{_db._q(job_id)}&select=company_id,log_output&limit=1")
    if not rows:
        return
    company = _db.get_company_by_id(rows[0]["company_id"])
    existing = _db.decrypt_field(company, rows[0].get("log_output"), "job.log-output") or ""
    _db._patch(f"jobs?id=eq.{_db._q(job_id)}", {
        "log_output": _db.encrypt_field(company, existing + new_lines, "job.log-output"),
    })

def get_pending_jobs_for_endpoint(endpoint_id, decrypt=False, limit=5):
    """Atomically lease runnable work to one endpoint.

    Expired running leases are reclaimed; live leases are never returned a
    second time. This makes heartbeat polling independent from execution
    without allowing the same command to run concurrently.
    """
    import db as _db
    rows = _db._rpc("claim_jobs_for_endpoint", {
        "p_endpoint_id": str(endpoint_id),
        "p_limit": max(1, min(int(limit), 20)),
        "p_lease_seconds": 900,
    }) or []
    if not decrypt:
        return rows
    company = None
    out = []
    for j in rows:
        company = company or _db.get_company_by_id(j["company_id"])
        out.append(_db._decrypt_job(j, company))
    return out

def create_policy_deployment(company_id, branch_id, template, payload, created_by,
                             reason=None, idempotency_key=None, endpoint_ids=None,
                             target_selector=None, rollout_percentage=100):
    """Atomically create a policy rollout and all of its endpoint jobs."""
    import db as _db
    company = _db.get_company_by_id(company_id)
    encrypted_payload = _db.encrypt_field(company, payload, "job.payload")
    params = {
        "p_company_id": str(company_id),
        "p_branch_id": str(branch_id),
        "p_template_id": str(template["id"]),
        "p_template_name": template["name"],
        "p_encrypted_payload": encrypted_payload,
        "p_created_by": str(created_by),
        "p_reason": reason or None,
        "p_idempotency_key": idempotency_key or None,
    }
    rpc_name = "create_policy_deployment"
    if endpoint_ids is not None:
        rpc_name = "create_targeted_policy_deployment"
        params.update({
            "p_endpoint_ids": [str(value) for value in endpoint_ids],
            "p_target_selector": target_selector or {},
            "p_rollout_percentage": int(rollout_percentage),
        })
    rows = _db._rpc(rpc_name, params) or []
    return rows[0] if rows else None

def cancel_policy_deployment(deployment_id, company_id):
    import db as _db
    return int(_db._rpc("cancel_policy_deployment", {
        "p_deployment_id": str(deployment_id),
        "p_company_id": str(company_id),
    }) or 0)

def retry_policy_deployment(deployment_id, company_id):
    import db as _db
    return int(_db._rpc("retry_policy_deployment", {
        "p_deployment_id": str(deployment_id),
        "p_company_id": str(company_id),
    }) or 0)

def maybe_pause_policy_deployment(job_id):
    import db as _db
    return _db._rpc("maybe_pause_policy_deployment", {"p_job_id": str(job_id)})

def refresh_policy_deployment_status(job_id):
    import db as _db
    return _db._rpc("refresh_policy_deployment_status", {"p_job_id": str(job_id)})

def get_policy_deployment(deployment_id):
    import db as _db
    rows = _db._get(f"policy_deployments?id=eq.{_db._q(deployment_id)}&limit=1")
    return rows[0] if rows else None

def get_policy_deployments(company_id, limit=20):
    import db as _db
    rows = _db._rpc("get_policy_deployment_summaries", {
        "p_company_id": str(company_id),
        "p_limit": max(1, min(int(limit), 100)),
    }) or []
    for row in rows:
        row["counts"] = {
            key: int(row.pop(key, 0) or 0)
            for key in ("pending", "running", "completed", "failed", "cancelled")
        }
    return rows

def cancel_job(job_id, admin_id):
    import db as _db
    company = _db._company_for_job(job_id)
    rows = _db._patch(f"jobs?id=eq.{_db._q(job_id)}&status=in.(pending,approved)", {
        "status": "cancelled",
        "completed_at": _db._now_iso(),
        "error_msg": _db.encrypt_field(company, f"Cancelled by admin {admin_id}", "job.error-message"),
    })
    return bool(rows)
