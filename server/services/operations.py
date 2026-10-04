"""Payload-free operational snapshots with explicit tenant/branch predicates."""
import db
from services.device_health import age_seconds


def queue_snapshot(company_id, branch_id=None):
    base = f"jobs?company_id=eq.{db._q(company_id)}"
    if branch_id:
        base += f"&branch_id=eq.{db._q(branch_id)}"
    counts = {status: db._count(base + f"&status=eq.{status}") for status in ('pending', 'running', 'failed')}
    rows = db._get(base + "&status=eq.pending&select=created_at&order=created_at.asc,id.asc&limit=1")
    age = age_seconds(rows[0].get('created_at')) if rows else None
    counts['oldest_pending_seconds'] = max(0, int(age)) if age is not None else None
    return counts
