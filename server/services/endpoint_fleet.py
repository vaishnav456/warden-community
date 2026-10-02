"""Read-only fleet presentation. Search encrypted names after tenant decryption."""
from datetime import datetime, timedelta, timezone
from math import ceil
import db
from services.endpoint_drives import local_drives
from services.dashboard_view import prepare_endpoints, timestamp

HEALTH = {'agent-update', 'encryption', 'patches', 'low-disk', 'failed-jobs', 'drift'}
SORTS = {'attention', 'name', 'last-contact', 'disk'}


def pages(path):
    """Explicit small pages avoid the PostgREST default maximum-row truncation."""
    result = []
    while True:
        page = db._get(path + f'&limit=500&offset={len(result)}') or []
        result.extend(page)
        if len(page) < 500:
            return result


def recent_jobs(company_id, endpoint_id=None, branch=None):
    scope = '&company_id=eq.' + db._q(str(company_id))
    if endpoint_id:
        scope += '&endpoint_id=eq.' + db._q(str(endpoint_id))
    if branch:
        scope += '&branch_id=eq.' + db._q(str(branch))
    since = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    return pages('jobs?select=id,endpoint_id,type,status,created_at,completed_at' + scope
                 + '&created_at=gte.' + db._q(since) + '&order=created_at.desc,id.asc')


def load(company, branch=None):
    scope = '&company_id=eq.' + db._q(str(company['id']))
    branch_scope = '&branch_id=eq.' + db._q(str(branch)) if branch else ''
    raw = pages('endpoints?is_active=eq.true' + scope + branch_scope + '&order=id.asc')
    endpoints = [db._decrypt_endpoint(row, company) for row in raw]
    checks = pages('compliance_results?select=endpoint_id,scanned_at,results' + scope + '&order=scanned_at.desc,id.asc')
    patches = pages('patch_inventory?select=endpoint_id' + scope + '&order=id.asc')
    jobs = recent_jobs(company['id'], branch=branch)
    return prepare(endpoints, checks, patches, jobs)


def prepare(endpoints, checks=(), patches=(), jobs=(), now=None):
    now = now or datetime.now(timezone.utc)
    # Keep newest check rather than letting an older scan overwrite it.
    latest = {}
    for check in checks:
        key = str(check.get('endpoint_id'))
        if key not in latest or (timestamp(check.get('scanned_at')) or datetime.min.replace(tzinfo=timezone.utc)) > (timestamp(latest[key].get('scanned_at')) or datetime.min.replace(tzinfo=timezone.utc)):
            latest[key] = check
    result = prepare_endpoints(endpoints, latest.values(), patches, now)
    by_endpoint = {}
    for job in jobs:
        by_endpoint.setdefault(str(job.get('endpoint_id')), []).append(job)
    for ep in result:
        ep['_local_drives'] = local_drives(ep)
        related = by_endpoint.get(str(ep['id']), [])
        related.sort(key=lambda j: timestamp(j.get('created_at')) or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
        ep['_failed_job'] = next((j for j in related if j.get('status') == 'failed'), None)
        ep['_update_job'] = next((j for j in related if j.get('type') in {'UPDATE_AGENT', 'REINSTALL_AGENT'}), None)
        ep['_drift'] = sum(isinstance(v, dict) and v.get('drift') is True for v in (ep.get('policy_state') or {}).values())
        ep['_low_disk'] = (any(drive['free_gb'] < 10 for drive in ep['_local_drives'])
                           if ep['_local_drives'] else
                           isinstance(ep.get('disk_free_gb'), (int, float)) and ep['disk_free_gb'] < 10)
        ep['_signals'] = []
        for condition, label in [(not ep['_online'], 'Offline'), (ep['_low_disk'], 'Low disk (last report)'),
                                 (ep['_encryption'] == 'attention', 'Encryption check failed'),
                                 (ep['_patch_attention'], 'Reported pending patches'), (ep['_agent_update'], 'Agent update available'),
                                 (ep['_drift'], 'Policy drift'), (ep['_failed_job'], 'Failed job in last 24h')]:
            if condition:
                ep['_signals'].append(label)
        ep['_attention'] = bool(ep['_signals'])
    return result


def listing(endpoints, args):
    query = str(args.get('q', '')).strip()[:200]
    state = args.get('state') if args.get('state') in {'online', 'offline', 'attention'} else ''
    health = args.get('health') if args.get('health') in HEALTH else ''
    platform = args.get('platform') if args.get('platform') in {'windows', 'linux', 'darwin'} else ''
    sort = args.get('sort') if args.get('sort') in SORTS else 'attention'
    rows = list(endpoints)
    if query:
        rows = [ep for ep in rows if query.casefold() in ' '.join(str(ep.get(k) or '') for k in ('display_name', 'hostname', 'os_name', 'agent_version', 'last_seen_ip')).casefold()]
    if platform:
        rows = [ep for ep in rows if (ep.get('platform') or 'windows') == platform]
    if health:
        rows = [ep for ep in rows if {'agent-update': ep['_agent_update'], 'encryption': ep['_encryption'] == 'attention',
                                    'patches': ep['_patch_attention'], 'low-disk': ep['_low_disk'],
                                    'failed-jobs': bool(ep['_failed_job']), 'drift': bool(ep['_drift'])}[health]]
    summary = dict(total=len(rows), online=sum(ep['_online'] for ep in rows), attention=sum(ep['_attention'] for ep in rows))
    if state:
        rows = [ep for ep in rows if {'online': ep['_online'], 'offline': not ep['_online'], 'attention': ep['_attention']}[state]]
    name = lambda ep: str(ep.get('display_name') or ep.get('hostname') or '').casefold()
    if sort == 'last-contact':
        rows.sort(key=lambda ep: (-(timestamp(ep.get('last_seen')).timestamp() if timestamp(ep.get('last_seen')) else 0), name(ep), str(ep['id'])))
    elif sort == 'disk':
        rows.sort(key=lambda ep: (ep.get('disk_free_gb') if isinstance(ep.get('disk_free_gb'), (int, float)) else float('inf'), name(ep), str(ep['id'])))
    else:
        rows.sort(key=lambda ep: ((-len(ep['_signals']) if sort == 'attention' else 0), name(ep), str(ep['id'])))
    def integer(key, default):
        try:
            return int(args.get(key, default))
        except (ValueError, TypeError):
            return default
    size = integer('page_size', 25)
    size = size if size in {25, 50, 100} else 25
    count = len(rows)
    page_count = max(1, ceil(count / size))
    page = max(1, min(integer('page', 1), page_count))
    return dict(endpoints=rows[(page-1)*size:page*size], fleet_summary=summary, query=query,
                selected_state=state, selected_health=health, selected_platform=platform,
                selected_sort=sort, page=page, page_size=size, page_count=page_count, total_matches=count)
