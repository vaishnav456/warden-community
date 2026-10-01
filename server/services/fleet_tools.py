"""Opt-in application patching and per-device branch traffic controls."""
import hashlib
import json
import logging
import pathlib
import re
from datetime import datetime, timezone
import config
import db
from services.agent_rollouts import in_window
from services.entitlements import check_job
from services.package_storage import installation
from services.device_health import age_seconds


def numeric_version(value):
    text = str(value or '').strip()
    if not re.fullmatch(r'\d{1,9}(?:\.\d{1,9}){0,7}', text):
        return None
    parts = tuple(int(part) for part in text.split('.'))
    while len(parts) > 1 and parts[-1] == 0:
        parts = parts[:-1]
    return parts


def rules(company_id):
    return db._get(f'software_patch_rules?company_id=eq.{db._q(company_id)}&order=created_at.desc&limit=1000')


def traffic_for(endpoint):
    if not endpoint.get('branch_id'):
        return None
    rows = db._get(f"branch_traffic_rules?company_id=eq.{db._q(endpoint['company_id'])}&branch_id=eq.{db._q(endpoint['branch_id'])}&limit=1")
    return rows[0] if rows else None


def defer_updates(endpoint, now=None):
    rule = traffic_for(endpoint)
    return bool(rule and rule.get('defer_updates') and in_window(rule['business_start'],rule['business_end'],now))


def inventory(endpoint_id):
    result = []
    while True:
        page = db.get_software(endpoint_id,limit=1000,offset=len(result))
        result.extend(page)
        if len(page) < 1000:
            return result


def match_patch(rule, endpoint, installed):
    if str(endpoint.get('company_id')) != str(rule['company_id']) or (rule.get('branch_id') and str(endpoint.get('branch_id')) != str(rule['branch_id'])):
        return None
    matches = [row for row in installed if str(row.get('name') or '').casefold() == rule['inventory_name'].casefold()
               and str(row.get('publisher') or '').casefold() == rule['publisher'].casefold()]
    if len(matches) != 1:
        return None  # Missing/ambiguous software is not an invitation to install.
    current, target = numeric_version(matches[0].get('version')), numeric_version(rule['target_version'])
    if current is None or target is None:
        return dict(status='unknown',installed=matches[0],detail='Version needs manual review')
    width = max(len(current),len(target))
    older = current+(0,)*(width-len(current)) < target+(0,)*(width-len(target))
    digest = hashlib.sha256(json.dumps([rule['inventory_name'],rule['publisher'],matches[0].get('version')],separators=(',',':')).encode()).hexdigest()
    return dict(status='outdated' if older else 'current',installed=matches[0],digest=digest)


def dispatch(rule, endpoint, found, now=None):
    if not rule.get('enabled') or not found or found['status'] != 'outdated' or endpoint.get('status') != 'online':
        return None
    age = age_seconds(endpoint.get('software_inventory_at'),now)
    if age is None or age > 86400 or age < -300:
        return None
    if not in_window(rule['window_start'],rule['window_end'],now) or defer_updates(endpoint,now) or db.get_active_remote_session(endpoint['id']):
        return None
    if not check_job(rule['company_id'],'INSTALL_APP').allowed:
        return None
    actor = db.get_admin_by_id(rule.get('approved_by'))
    if not actor or not actor.get('is_active',True) or actor.get('role') not in {'superadmin','company_admin'} or (actor.get('role') != 'superadmin' and str(actor.get('company_id')) != str(rule['company_id'])):
        return None
    app = db.get_app(rule['app_id'])
    if not app or app.get('sha256') != rule['package_sha256'] or (app.get('install_args') or '') != rule['install_args']:
        return None  # Package changes require a new explicit approval.
    ext = pathlib.Path(app.get('file_path') or '').suffix.lower()
    platform = str(endpoint.get('platform') or 'windows').lower()
    if ext not in {'windows':{'.msi','.exe'},'linux':{'.deb','.rpm'},'darwin':{'.pkg'}}.get(platform,set()):
        return None
    caps = endpoint.get('capabilities') or []
    if caps and 'INSTALL_APP' not in caps:
        return None
    payload = dict(app_id=app['id'],app_url=f"{config.SERVER_URL.rstrip('/')}/api/agent/apps/{app['id']}/download",
                   sha256=app['sha256'],ext=ext,install_args=app.get('install_args') or '',
                   require_authenticode=bool(config.REQUIRE_SIGNED_WINDOWS_APPS and platform=='windows'))
    company = db.get_company_by_id(rule['company_id'])
    with installation(rule['company_id'],payload):
        jobs = db._rpc('dispatch_software_patch',dict(p_rule=rule['id'],p_endpoint=endpoint['id'],
                      p_digest=found['digest'],p_payload=db.encrypt_field(company,payload,'job.payload'))) or []
    if jobs:
        db.audit(rule['company_id'],rule['approved_by'],'software_patch_dispatched',
                 dict(rule_id=rule['id'],job_id=jobs[0]['id'],app_id=app['id']),branch_id=endpoint.get('branch_id'),endpoint_id=endpoint['id'])
        return jobs[0]
    return None


def tick():
    offset=0
    while True:
        page=db._get(f'software_patch_rules?enabled=eq.true&order=id.asc&limit=1000&offset={offset}')
        for rule in page:
            try:
                endpoints=db.get_endpoints(rule['company_id'],branch_id=rule.get('branch_id'))
            except Exception:
                logging.getLogger(__name__).exception('Application patch rule %s deferred',rule['id'])
                continue
            for endpoint in endpoints:
                try:
                    if endpoint.get('status') == 'online':
                        dispatch(rule,endpoint,match_patch(rule,endpoint,inventory(endpoint['id'])))
                except Exception:
                    logging.getLogger(__name__).exception('Application patch endpoint %s deferred',endpoint['id'])
        if len(page)<1000:return
        offset+=len(page)
