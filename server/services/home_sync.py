"""Authorize and schedule recurring Home sync without storing access grants."""

import re
import uuid
from datetime import datetime, timezone

import db
from services.home_grants import assignment_matches


SYNC_INTERVAL_SECONDS = 5 * 60
MAX_RETRY_SECONDS = 30 * 60
_USERNAME = re.compile(r"[A-Za-z0-9._-]{1,20}")


def short_windows_username(value):
    value = str(value or "").strip().replace("/", "\\")
    return value.rsplit("\\", 1)[-1] if value else ""


def endpoint_storage_principal(endpoint, username, assignments):
    """Allow direct shares only for the endpoint's current console account."""
    if not _USERNAME.fullmatch(str(username or "")):
        return None, []
    interactive = short_windows_username(endpoint.get("interactive_user"))
    if not interactive or interactive.casefold() != username.casefold():
        return None, []
    endpoint_id = str(endpoint.get("id") or "")
    direct = [
        item for item in assignments
        if item.get("enabled", True)
        and item.get("scope_type") == "endpoint"
        and str(item.get("scope_value") or "") == endpoint_id
        and str(item.get("company_id", endpoint.get("company_id")))
        == str(endpoint.get("company_id"))
    ]
    if not direct:
        return None, []
    try:
        principal_id = str(uuid.uuid5(uuid.UUID(endpoint_id), username.casefold()))
    except (ValueError, AttributeError):
        return None, []
    return {"id": principal_id, "username": username}, direct


def resolve_home_access_context(endpoint, username):
    """Use current Directory state, or an explicitly assigned device share."""
    company_id = endpoint["company_id"]
    identity = db.get_warden_identity_for_login(company_id, endpoint["id"], username)
    if identity:
        active = any(
            item.get("status") == "active"
            and str(item.get("endpoint_id", endpoint["id"])) == str(endpoint["id"])
            for item in identity.get("warden_identity_assignments") or []
        )
        if (identity.get("is_enabled", True) and active
                and str(identity.get("company_id", company_id)) == str(company_id)):
            assignments = db.get_home_assignments(company_id)
            return identity, [
                item for item in assignments
                if str(item.get("company_id", company_id)) == str(company_id)
            ], True
        # Disabled/pending managed accounts cannot fall through to direct shares.
        return None, [], True
    principal, direct = endpoint_storage_principal(
        endpoint, username, db.get_home_assignments(company_id),
    )
    return principal, direct, False


def _timestamp(value):
    if not value:
        return None
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result
    except (TypeError, ValueError):
        return None


def home_sync_due(jobs, now=None, force=False):
    """Wait after completion; back off repeated failures to at most 30 minutes."""
    if any(job.get("status") in {"pending", "approved", "running"} for job in jobs):
        return False
    if force or not jobs:
        return True
    latest = jobs[0]
    finished = _timestamp(latest.get("completed_at")) or _timestamp(latest.get("created_at"))
    if finished is None:
        return False
    failures = 0
    for job in jobs:
        if job.get("status") not in {"failed", "cancelled"}:
            break
        failures += 1
    delay = min(MAX_RETRY_SECONDS, SYNC_INTERVAL_SECONDS * (2 ** min(max(failures - 1, 0), 3)))
    return ((now or datetime.now(timezone.utc)) - finished).total_seconds() >= delay


def queue_periodic_home_sync(endpoint, current_user, *, capabilities=None, platform=None, now=None):
    """Queue a refresh for the authenticated heartbeat's signed-in user.

    Only job timing comes from history. Every due job resolves current tenant,
    endpoint, identity and Home assignments again. The agent obtains new,
    short-lived grants when it runs the refresh job.
    """
    username = short_windows_username(current_user)
    if not endpoint.get("is_active", True) or not _USERNAME.fullmatch(username):
        return None
    if capabilities is not None:
        if not isinstance(capabilities, list) or "SYNC_WARDEN_HOME" not in capabilities:
            return None
    elif str(platform or endpoint.get("platform") or "").lower() != "windows":
        return None

    jobs = db.get_endpoint_home_sync_jobs(endpoint["company_id"], endpoint["id"])
    changed_user = username.casefold() != short_windows_username(endpoint.get("interactive_user")).casefold()
    if not home_sync_due(jobs, now=now, force=changed_user):
        return None

    current_endpoint = {**endpoint, "interactive_user": current_user}
    principal, assignments, _ = resolve_home_access_context(current_endpoint, username)
    if not principal:
        return None
    assigned_spaces = {
        str(item.get("space_id")) for item in assignments
        if assignment_matches(item, current_endpoint, principal)
    }
    if not assigned_spaces:
        return None
    company_id = str(endpoint["company_id"])
    usable = any(
        str(space.get("id")) in assigned_spaces
        and str(space.get("company_id", company_id)) == company_id
        and space.get("enabled", True)
        and any(
            (item.get("home_storage_nodes") or {}).get("id")
            and (item.get("home_storage_nodes") or {}).get("status") != "disabled"
            and str((item.get("home_storage_nodes") or {}).get("company_id", company_id)) == company_id
            for item in space.get("home_space_nodes") or []
        )
        for space in db.get_home_spaces(endpoint["company_id"])
    )
    if not usable:
        return None
    # The database operation serializes competing heartbeats/workers and checks
    # all pending/approved/running jobs for this endpoint and operation.
    return db.create_system_job_once(
        endpoint["company_id"], endpoint.get("branch_id"), endpoint["id"],
        "SYNC_WARDEN_HOME", {"username": principal["username"], "refresh": True},
    )
