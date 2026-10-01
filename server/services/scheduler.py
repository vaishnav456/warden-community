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


def scheduled_targets(job):
    """Resolve current ownership, not just the scope at schedule creation."""
    company_id = job["company_id"]
    branch_id = job.get("branch_id")
    if job.get("endpoint_id"):
        endpoint = db.get_endpoint(job["endpoint_id"])
        candidates = [endpoint] if endpoint else []
    else:
        candidates = db.get_endpoints(company_id, branch_id=branch_id)
        candidates = [endpoint for endpoint in candidates if endpoint.get("status") == "online"]
    return [
        endpoint for endpoint in candidates
        if str(endpoint.get("company_id")) == str(company_id)
        and (not branch_id or str(endpoint.get("branch_id")) == str(branch_id))
    ]


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
    targets = scheduled_targets(job)
    from services.fleet_tools import defer_updates

    dispatched = 0
    skipped = 0
    for ep in targets:
        if job_type in {'INSTALL_APP','UPDATE_AGENT','REINSTALL_AGENT'} and defer_updates(ep):
            skipped += 1
            continue
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
        company = db.get_auto_update_company()
        companies = [company] if company else []
    except Exception as e:
        log.warning("scheduler: get_companies_with_auto_update failed: %s", e)
        return
    if not companies:
        return

    builds = {}

    from services.agent_rollouts import campaigns, ACTIVE
    # A paused campaign must also block ordinary auto-updates: otherwise its
    # failure stop/canary boundary could be bypassed by this scheduler.
    try:
        protected = {key for row in campaigns(active_only=True) if row['status'] in ACTIVE for key in row['targets']}
    except Exception as exc:
        log.warning('Cannot verify rollout boundaries; auto-updates deferred: %s', exc)
        return

    for company in companies:
        company_id = company["id"]
        try:
            endpoints = db.get_endpoints(company_id)
        except Exception as e:
            log.warning("scheduler: get_endpoints failed for company %s: %s", company_id, e)
            continue

        for ep in endpoints:
            if str(ep['id']) in protected or db.get_active_remote_session(ep['id']):
                continue
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
            # The update job finishes before the restarted service reports its
            # new version. Avoid dispatching another updater during that gap.
            try:
                if db.has_recent_job(ep["id"], "UPDATE_AGENT", minutes=15):
                    continue
            except Exception as e:
                log.warning(
                    "scheduler: recent update lookup failed for endpoint %s: %s",
                    ep["id"], e,
                )
                continue
            try:
                from services.fleet_tools import defer_updates
                if defer_updates(dict(ep,company_id=company_id)):
                    continue
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


def _purge_expired_trials():
    try:
        purged = db.purge_expired_hosted_trials()
    except Exception as e:
        log.warning("scheduler: expired hosted-trial cleanup failed: %s", e)
        return
    for item in purged:
        from services.tenant_crypto import lock_company
        lock_company(item.get("company_id"))
        log.info("Hosted trial deleted: lead=%s tenant=%s endpoints=%s",
                 item.get("lead_id"), item.get("company_id"),
                 item.get("deleted_endpoint_count", 0))


def _loop():
    while True:
        time.sleep(_INTERVAL)
        health_tracker.ping("scheduler")
        _dispatch_once()
        try:
            from services.agent_rollouts import tick
            tick()
        except Exception:
            log.exception('Staged agent update check failed')
        _check_auto_updates()
        try:
            from services.fleet_tools import tick as patch_applications
            patch_applications()
        except Exception:
            log.exception('Application patch check deferred')
        _promote_patch_rollouts()
        _purge_expired_trials()


def start():
    t = threading.Thread(target=_loop, daemon=True, name="scheduler")
    t.start()
    log.info("Scheduler started")
