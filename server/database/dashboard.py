"""One aggregate read for dashboard counters; no cross-request data cache."""
from datetime import datetime, timedelta, timezone
import json
import urllib.error

COUNTERS = ('pending_escalations', 'open_alerts', 'critical_alerts',
            'failed_jobs', 'pending_jobs', 'running_jobs')


def dashboard_counts(company_id, branch_id=None, now=None):
    import db
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError('Dashboard timestamp must have a timezone')
    try:
        result = db._rpc('dashboard_counts', {
            'p_company_id': str(company_id),
            'p_branch_id': str(branch_id) if branch_id else None,
            'p_now': now.isoformat(),
        })
    except urllib.error.HTTPError as error:
        # Rolling deployments can precede schema-cache refresh. Only the
        # exact missing-function error may use the legacy query path.
        if error.code != 404:
            raise
        try:
            missing = json.loads(error.read(4096)).get('code') == 'PGRST202'
        finally:
            error.close()
        if not missing:
            raise
        return _legacy_counts(company_id, branch_id, now)
    if not isinstance(result, dict) or any(type(result.get(key)) is not int or result[key] < 0 for key in COUNTERS):
        raise RuntimeError('Invalid dashboard count response')
    return {key: result[key] for key in COUNTERS}


def _legacy_counts(company_id, branch_id, now):
    import db
    scope = dict(company_id=company_id, branch_id=branch_id)
    active = {'is_resolved': 'eq.false', 'or': f'(snoozed_until.is.null,snoozed_until.lte.{now.isoformat()})'}
    return dict(
        pending_escalations=db.dashboard_count(table='escalation_requests', status='in.(pending,pending_secondary)', expires_at='gt.' + now.isoformat(), **scope),
        open_alerts=db.dashboard_count(table='alerts', **active, **scope),
        critical_alerts=db.dashboard_count(table='alerts', severity='eq.critical', **active, **scope),
        failed_jobs=db.dashboard_count(table='jobs', status='eq.failed', created_at='gte.' + (now - timedelta(days=1)).isoformat(), **scope),
        pending_jobs=db.dashboard_count(table='jobs', status='eq.pending', **scope),
        running_jobs=db.dashboard_count(table='jobs', status='eq.running', **scope),
    )
