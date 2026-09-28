"""
Warden — Background job scheduler
Polls for due recurring scheduled jobs every 60 seconds and dispatches
them to their target endpoints. Run in a background thread.
"""
import time
import threading
import logging
import re

import config
import db
import services.health_tracker as health_tracker
from services.agent_updates import AgentBuildUnavailable, update_payload

log = logging.getLogger("warden.scheduler")

_INTERVAL = 60  # seconds

_AGENT_VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


def compare_agent_versions(left, right):
    """Compare strict numeric agent versions; reject ambiguous labels."""
    lm = _AGENT_VERSION_RE.fullmatch(str(left or "").strip())
    rm = _AGENT_VERSION_RE.fullmatch(str(right or "").strip())
    if not lm or not rm:
        raise ValueError("agent versions must be MAJOR.MINOR.PATCH")
    lv = tuple(int(part) for part in lm.groups())
    rv = tuple(int(part) for part in rm.groups())
    return (lv > rv) - (lv < rv)


def _dispatch_once():
    try:
        due_jobs = db.get_due_scheduled_jobs()
    except Exception as e:
        log.warning("scheduler: get_due_scheduled_jobs failed: %s", e)
        return

    if not due_jobs:
        return

    for job in due_jobs:
        try:
            _dispatch_job(job)
        except Exception as e:
            log.warning("scheduler: error dispatching job %s ('%s'): %s", job.get("id"), job.get("name"), e)


def _dispatch_job(job):
    company_id = job["company_id"]
    branch_id = job.get("branch_id")
    job_type = job["job_type"]
    payload = job.get("payload") or {}
    from services.entitlements import check_job
    decision = check_job(company_id, job_type)
    if not decision.allowed:
        log.warning("Scheduler: blocked '%s': %s", job.get("name"), decision.message)
        return
    # Resolve target endpoints
    if job.get("endpoint_id"):
        ep = db.get_endpoint(job["endpoint_id"])
        targets = [ep] if ep else []
    elif branch_id:
        targets = [
            e for e in db.get_endpoints(company_id, branch_id=branch_id)
            if e.get("status") == "online"
        ]
    else:
        targets = [
            e for e in db.get_endpoints(company_id)
            if e.get("status") == "online"
        ]

    dispatched = 0
    skipped = 0
    for ep in targets:
        capabilities = set(ep.get("capabilities") or [])
        if capabilities and job_type not in capabilities:
            skipped += 1
            continue
        created = db.create_system_job_once(
            company_id, ep.get("branch_id"), ep["id"], job_type, payload,
        )
        if not created:
            log.info("Scheduler: skipped duplicate in-flight %s for endpoint %s",
                     job_type, ep["id"])
        else:
            dispatched += 1

    log.info("Scheduler: dispatched '%s' to %d endpoint(s), skipped %d",
             job.get("name"), dispatched, skipped)


def _check_auto_updates():
    """Opt-in (see companies.auto_update_agents / settings/security.html):
    dispatch UPDATE_AGENT to any online endpoint of an opted-in tenant whose
    reported agent_version lags the latest completed build, so a fleet
    doesn't sit on stale agent code waiting for someone to click Update
    Agent per-endpoint. Payload is derived server-side exactly like the
    manual Update Agent button (routes/endpoints.py) — never trust a
    client-supplied download_url/sha256 for something that runs as a
    privileged Windows service."""
    try:
        companies = db.get_companies_with_auto_update()
    except Exception as e:
        log.warning("scheduler: get_companies_with_auto_update failed: %s", e)
        return
    if not companies:
        return

    builds = {}

    for company in companies:
        company_id = company["id"]
        try:
            endpoints = db.get_endpoints(company_id)
        except Exception as e:
            log.warning("scheduler: get_endpoints failed for company %s: %s", company_id, e)
            continue

        for ep in endpoints:
            if ep.get("status") != "online":
                continue
            target = db.endpoint_target_platform(ep)
            if target not in builds:
                try:
                    builds[target] = db.get_latest_completed_build(target)
                except Exception as e:
                    log.warning("scheduler: latest build lookup for %s failed: %s", target, e)
                    builds[target] = None
            build = builds[target]
            if not build or not build.get("sha256") or not build.get("agent_version"):
                continue
            try:
                compare_agent_versions(build["agent_version"], build["agent_version"])
            except ValueError:
                log.error("scheduler: refusing auto-update from invalid build version %r", build["agent_version"])
                continue
            try:
                payload = update_payload(ep)
            except AgentBuildUnavailable as e:
                log.warning("scheduler: update artifacts unavailable for endpoint %s: %s", ep["id"], e)
                continue
            current_version = ep.get("agent_version")
            if current_version:
                try:
                    # Never dispatch an equal version or a downgrade. The
                    # agent independently enforces the same rule.
                    if compare_agent_versions(build["agent_version"], current_version) <= 0:
                        continue
                except ValueError:
                    log.warning(
                        "scheduler: endpoint %s reported invalid version %r; update allowed for recovery",
                        ep["id"], current_version,
                    )
            try:
                created = db.create_system_job_once(
                    company_id, ep.get("branch_id"), ep["id"], "UPDATE_AGENT", payload,
                )
                if not created:
                    continue
                log.info(
                    "Scheduler: auto-update dispatched to endpoint %s (%s -> %s)",
                    ep["id"], ep.get("agent_version"), build["agent_version"],
                )
            except Exception as e:
                log.warning("scheduler: auto-update dispatch failed for endpoint %s: %s", ep["id"], e)


def _promote_patch_rollouts():
    try:
        deployments = db.get_due_patch_deployments()
    except Exception as e:
        log.warning("scheduler: due patch rollout lookup failed: %s", e)
        return
    for deployment in deployments:
        try:
            queued = db.promote_patch_deployment(deployment["id"])
            if queued < 0:
                log.warning("Scheduler: paused patch deployment %s after %d pilot failures",
                            deployment["id"], -queued)
            elif queued:
                log.info("Scheduler: promoted patch deployment %s; queued %d broad-ring endpoints",
                         deployment["id"], queued)
        except Exception as e:
            log.warning("scheduler: patch rollout promotion failed for %s: %s", deployment["id"], e)


def _loop():
    while True:
        time.sleep(_INTERVAL)
        health_tracker.ping("scheduler")
        _dispatch_once()
        _check_auto_updates()
        _promote_patch_rollouts()


def start():
    t = threading.Thread(target=_loop, daemon=True, name="scheduler")
    t.start()
    log.info("Scheduler started")
