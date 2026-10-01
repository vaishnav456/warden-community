"""Durable canary/batch update campaigns, verified by post-update heartbeat."""
from datetime import datetime, timezone
import hashlib
import uuid
import logging
import db
import config
from services.agent_updates import read_build_artifact, AgentBuildUnavailable
from services.device_health import age_seconds

ACTIVE = {'canary', 'expanding', 'paused', 'rolling_back'}


def campaigns(company_id=None, active_only=False):
    path = 'agent_rollouts?order=created_at.desc,id.asc&limit=1000'
    if active_only:
        path += '&status=in.(canary,expanding,paused,rolling_back)'
    if company_id:
        path += f'&company_id=eq.{db._q(company_id)}'
    result = []
    while True:
        page = db._get(path + f'&offset={len(result)}')
        result.extend(page)
        if len(page) < 1000:
            return result


def in_window(start, end, now=None):
    hour = (now or datetime.now(timezone.utc)).hour
    return start == end or (start <= hour < end if start < end else hour >= start or hour < end)


def pinned_payload(build):
    if not build or build.get('status') != 'completed' or build.get('deletion_requested_at'):
        raise AgentBuildUnavailable('Build is unavailable')
    blob = read_build_artifact(build, 'agent')
    if hashlib.sha256(blob).hexdigest() != build.get('sha256'):
        raise AgentBuildUnavailable('Build digest does not match the artifact')
    base = config.SERVER_URL.rstrip('/')
    payload = dict(download_url=f"{base}/api/agent/builds/{build['id']}/agent",
                   sha256=build['sha256'], version=build['agent_version'])
    if (build.get('target_platform') or 'windows-amd64').startswith('windows-'):
        provider = read_build_artifact(build, 'credential_provider')
        payload.update(credential_provider_url=f"{base}/api/agent/builds/{build['id']}/credential-provider",
                       credential_provider_sha256=hashlib.sha256(provider).hexdigest())
    return payload


def create(company_id, build_id, endpoint_ids, actor_id, canary, batch, start, end, canary_ids=None):
    if not 1 <= canary <= 1000 or not 1 <= batch <= 1000 or not 0 <= start <= 23 or not 0 <= end <= 23:
        raise ValueError('Invalid batch size or UTC maintenance hours')
    endpoints = {str(ep['id']): ep for ep in db.get_endpoints(company_id)}
    ids = sorted(set(endpoint_ids))
    if not ids or len(ids) > 1000 or not set(ids) <= set(endpoints):
        raise ValueError('Select 1–1000 devices owned by this organization')
    named_canaries=set(canary_ids or [])
    if not named_canaries<=set(ids):
        raise ValueError('Named canary devices must also be selected as rollout targets')
    if named_canaries:
        canary=len(named_canaries)
    build = db.get_build_request(build_id)
    pinned_payload(build)
    occupied = {key for row in campaigns(company_id) if row['status'] in ACTIVE for key in row['targets']}
    if set(ids) & occupied:
        raise ValueError('A selected device already belongs to an active or paused rollout')
    targets = {}
    for key in ids:
        ep = endpoints[key]
        if db.endpoint_target_platform(ep) != (build.get('target_platform') or 'windows-amd64'):
            raise ValueError('All selected devices must match the build platform')
        from services.scheduler import compare_agent_versions
        if compare_agent_versions(build['agent_version'], ep.get('agent_version')) <= 0:
            raise ValueError('The release must be newer than every selected device')
        old = db._get(f"build_requests?status=eq.completed&agent_version=eq.{db._q(ep['agent_version'])}&target_platform=eq.{db._q(db.endpoint_target_platform(ep))}&order=completed_at.desc&limit=1")
        targets[key] = dict(state='waiting',canary=key in named_canaries if named_canaries else None,
                           previous_version=ep['agent_version'], previous_build_id=old[0]['id'] if old else None)
    return db._rpc('create_agent_rollout', dict(p_company=company_id,p_build=build_id,p_actor=actor_id,
                     p_canary=min(canary,len(ids)),p_batch=batch,p_start=start,p_end=end,p_targets=targets))[0]


def advance(row, now=None):
    if row['status'] not in ACTIVE or row['status'] == 'paused':
        return row
    now = now or datetime.now(timezone.utc)
    from services.entitlements import check_job
    if not check_job(row['company_id'],'UPDATE_AGENT').allowed:
        row.update(status='paused',pause_reason='Organization is not currently authorized to update agents')
        return row
    endpoints = {str(ep['id']): ep for ep in db.get_endpoints(row['company_id'])}
    build = db.get_build_request(row['build_id'])
    payload = pinned_payload(build)
    rollback = row['status'] == 'rolling_back'
    for key, target in row['targets'].items():
        ep = endpoints.get(key)
        if not ep:
            row.update(status='paused', pause_reason='A target device was removed or moved to another tenant')
            return row
        if target.get('state') not in {'queued', 'verifying', 'rollback_queued'}:
            continue
        job = db.get_job(target.get('job_id'), decrypt=False)
        if not job:
            row.update(status='paused', pause_reason='Update job no longer exists; inspect before retrying')
            return row
        expected = target['previous_version'] if target['state'] == 'rollback_queued' else payload['version']
        if job.get('status') in {'failed','cancelled'}:
            target['state'] = 'failed'
            row.update(status='paused', pause_reason='An update failed; remaining devices were not dispatched')
            return row
        if job.get('status') == 'completed':
            seen_age = age_seconds(ep.get('last_seen'),now)
            completed_age = age_seconds(job.get('completed_at'),now)
            healthy = ep.get('status') == 'online' and ep.get('agent_version') == expected and seen_age is not None and completed_age is not None and 0 <= seen_age < 180 and 0 <= completed_age and seen_age < completed_age
            if healthy:
                target['state'] = 'rolled_back' if expected == target['previous_version'] else 'verified'
            elif (age_seconds(job.get('completed_at'),now) or 0) > 600:
                target['state'] = 'failed'
                row.update(status='paused',pause_reason='Device did not report a healthy expected-version heartbeat within 10 minutes')
                return row
            elif not rollback:
                target['state'] = 'verifying'
    states = [value['state'] for value in row['targets'].values()]
    if not rollback and all(state == 'verified' for state in states):
        row['status'] = 'completed'
        return row
    if rollback and all(state in {'rolled_back','waiting'} for state in states):
        row.update(status='paused',pause_reason='Rollback complete. Cancel this campaign to release its devices to normal auto-updates.')
        return row
    if any(state in {'queued','verifying','rollback_queued'} for state in states) or not in_window(row['window_start'],row['window_end'],now):
        return row
    if row['status'] == 'canary' and sum(state == 'verified' for state in states) >= row['canary_count']:
        row['status'] = 'expanding'
    limit = row['canary_count'] - sum(state=='verified' for state in states) if row['status'] == 'canary' else row['batch_size']
    count = 0
    for key, target in row['targets'].items():
        ep = endpoints[key]
        from services.fleet_tools import defer_updates
        if defer_updates(ep,now):
            continue
        if row['status']=='canary' and any(t.get('canary') for t in row['targets'].values()) and not target.get('canary'):
            continue
        eligible = target['state'] in ({'verified','failed'} if rollback else {'waiting'})
        if not eligible or ep.get('status') != 'online' or db.get_active_remote_session(key):
            continue
        job_payload = payload
        job_type = 'UPDATE_AGENT'
        if rollback:
            if ep.get('agent_version') == target['previous_version']:
                target['state'] = 'rolled_back'
                continue
            if not db.endpoint_target_platform(ep).startswith('windows-'):
                row.update(status='paused',pause_reason='Automatic downgrade is supported on Windows only; use a reviewed recovery job for this platform')
                return row
            from services.scheduler import compare_agent_versions
            if compare_agent_versions(ep.get('agent_version'),'2.6.48')<0:
                row.update(status='paused',pause_reason='This agent predates signed rollback support (2.6.48); use a reviewed recovery installation')
                return row
            if not target.get('previous_build_id') or ep.get('agent_version') != payload['version']:
                row.update(status='paused',pause_reason='Rollback requires an available previous build and the expected current version')
                return row
            job_payload = pinned_payload(db.get_build_request(target['previous_build_id']))
            job_payload['rollback_from'] = payload['version']
            job_type = 'REINSTALL_AGENT'
        if db.has_inflight_job(key,'UPDATE_AGENT') or db.has_inflight_job(key,'REINSTALL_AGENT'):
            continue
        # Persist verification changes before transactional dispatch so its
        # SQL target-state guard sees the same campaign state as this worker.
        db._patch(f"agent_rollouts?id=eq.{db._q(row['id'])}&lease_token=eq.{row['lease_token']}",
                  {field:row.get(field) for field in ('status','targets','pause_reason')})
        company = db.get_company_by_id(row['company_id'])
        jobs = db._rpc('dispatch_agent_rollout',dict(p_id=row['id'],p_token=row['lease_token'],p_endpoint=key,
                       p_type=job_type,p_payload=db.encrypt_field(company,job_payload,'job.payload'))) or []
        job = jobs[0] if jobs else None
        if job:
            target.update(state='rollback_queued' if rollback else 'queued',job_id=str(job['id']))
            count += 1
        if count >= limit:
            break
    return row


def tick():
    for candidate in campaigns(active_only=True):
        if candidate['status'] not in ACTIVE or candidate['status'] == 'paused':
            continue
        token = str(uuid.uuid4())
        if not db._rpc('claim_agent_rollout',dict(p_id=candidate['id'],p_token=token)):
            continue
        try:
            fresh = db._get(f"agent_rollouts?id=eq.{db._q(candidate['id'])}")[0]
            row = advance(fresh)
            db._patch(f"agent_rollouts?id=eq.{db._q(row['id'])}&lease_token=eq.{token}",
                      {key:row.get(key) for key in ('status','targets','pause_reason')})
        except Exception:
            logging.getLogger(__name__).exception('Rollout worker failed for %s; pausing for review',candidate['id'])
            # Preserve SQL's durable targets if the error followed dispatch.
            db._patch(f"agent_rollouts?id=eq.{db._q(candidate['id'])}&lease_token=eq.{token}",
                      dict(status='paused',pause_reason='Worker encountered an error. Inspect device jobs and server logs before resuming.'))
        finally:
            db._patch(f"agent_rollouts?id=eq.{db._q(candidate['id'])}&lease_token=eq.{token}",dict(lease_token=None,lease_until=None))
