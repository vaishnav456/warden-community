"""Schedules database operations."""


def create_scheduled_job(company_id, branch_id, endpoint_id, name, job_type, payload, interval_seconds, created_by):
    import db as _db
    from datetime import datetime, timezone, timedelta
    next_run = (datetime.now(timezone.utc) + timedelta(seconds=interval_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
    data = {
        "company_id": str(company_id),
        "name": name,
        "job_type": job_type,
        "payload": payload or {},
        "enabled": True,
        "interval_seconds": interval_seconds,
        "next_run_at": next_run,
        "created_at": _db._now_iso(),
    }
    if branch_id:
        data["branch_id"] = str(branch_id)
    if endpoint_id:
        data["endpoint_id"] = str(endpoint_id)
    if created_by:
        data["created_by"] = str(created_by)
    if job_type == 'INSTALL_APP':
        from services.package_storage import installation
        with installation(company_id,payload):
            rows = _db._post('scheduled_jobs',data)
    else:
        rows = _db._post("scheduled_jobs", data)
    return rows[0] if (rows and isinstance(rows, list)) else rows

def get_scheduled_jobs(company_id):
    import db as _db
    return _db._get(
        f"scheduled_jobs?company_id=eq.{_db._q(str(company_id))}&order=created_at.desc"
    ) or []

def get_scheduled_job(job_id):
    import db as _db
    rows = _db._get(f"scheduled_jobs?id=eq.{_db._q(str(job_id))}&limit=1")
    return rows[0] if rows else None

def update_scheduled_job(job_id, enabled):
    import db as _db
    _db._patch(f"scheduled_jobs?id=eq.{_db._q(str(job_id))}", {"enabled": enabled})

def delete_scheduled_job(job_id):
    import db as _db
    _db._delete(f"scheduled_jobs?id=eq.{_db._q(str(job_id))}")

def get_due_scheduled_jobs():
    """Atomically claim due schedules and advance their next run.

    Advancing in the same transaction as selection prevents two scheduler
    processes from dispatching the same occurrence. A process crash can skip
    one occurrence, but cannot duplicate privileged endpoint commands.
    """
    import db as _db
    return _db._rpc("claim_due_scheduled_jobs", {"p_limit": 100}) or []

def mark_scheduled_job_ran(job_id, interval_seconds):
    import db as _db
    from datetime import datetime, timezone, timedelta
    now = _db._now_iso()
    interval_seconds = interval_seconds or 86400
    next_run = (datetime.now(timezone.utc) + timedelta(seconds=interval_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
    _db._patch(f"scheduled_jobs?id=eq.{_db._q(str(job_id))}", {
        "last_run_at": now,
        "next_run_at": next_run,
    })
