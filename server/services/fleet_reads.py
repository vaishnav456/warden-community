"""Scoped metadata batching; never caches authorization or decrypted data."""
from datetime import datetime, timedelta, timezone
import db


def update_blockers(company_id, now=None):
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError('Aware timestamp required')
    recent = db._get_all(
        f"jobs?company_id=eq.{db._q(company_id)}&type=eq.UPDATE_AGENT"
        f"&created_at=gte.{db._q((now-timedelta(minutes=15)).isoformat())}"
        "&select=endpoint_id&order=id.asc")
    remote = db._get_all(
        f"remote_sessions?company_id=eq.{db._q(company_id)}&status=eq.active"
        f"&started_at=gte.{db._q((now-timedelta(seconds=3700)).isoformat())}"
        "&select=endpoint_id&order=id.asc")
    return {str(row['endpoint_id']) for row in recent + remote}
