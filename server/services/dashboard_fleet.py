"""Aggregate fleet facts without transferring/decrypting the entire fleet."""
import json
import urllib.error
import db

# The dashboard cards need labels, last metrics and precomputed fleet flags.
# Keep bulk/private device material out of the per-field custody calls.
ENDPOINT_CARD_FIELDS = frozenset({
    'id', 'company_id', 'branch_id', 'platform', 'hostname', 'display_name',
    'os_name', 'status', 'last_seen', 'heartbeat_encrypted',
    'cpu_pct', 'ram_used_pct', 'disk_free_gb', 'agent_memory_mb',
    'agent_uptime_sec', 'net_sent_mbps', 'net_recv_mbps',
    '_online', '_fresh', '_agent_update', '_agent_unknown', '_encryption',
    '_patch_attention', '_offline_age',
})


def missing_function(error):
    if not isinstance(error, urllib.error.HTTPError) or error.code != 404:
        return False
    try:
        value = json.loads(error.read(4096))
        return isinstance(value, dict) and value.get('code') == 'PGRST202'
    except (ValueError, TypeError):
        return False
    finally:
        error.close()


def snapshot(company_id, branch_id, now):
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError('Aware timestamp required')
    try:
        result = db._rpc('dashboard_fleet', dict(p_company_id=str(company_id),
                         p_branch_id=str(branch_id) if branch_id else None, p_now=now.isoformat()))
    except urllib.error.HTTPError as error:
        if missing_function(error):
            return None  # Compatibility only until the migration is installed.
        raise
    if not isinstance(result, dict) or not isinstance(result.get('endpoints'), list) or len(result['endpoints']) > 10:
        raise RuntimeError('Invalid fleet aggregate')
    for key in ('total_count','online_count','offline_count','stale_count'):
        if type(result.get(key)) is not int or result[key] < 0:
            raise RuntimeError('Invalid fleet totals')
    if result['online_count'] + result['offline_count'] != result['total_count']:
        raise RuntimeError('Inconsistent fleet totals')
    if result['stale_count'] > result['offline_count'] or len(result['endpoints']) > result['total_count']:
        raise RuntimeError('Inconsistent fleet sample')
    health = result.get('health')
    if not isinstance(health, dict) or any(type(health.get(k)) is not int or health[k] < 0 for k in (
            'agent_updates','agent_unknown','encryption_attention','encryption_unknown','patch_attention')) or any(
                value > result['total_count'] for value in health.values() if type(value) is int):
        raise RuntimeError('Invalid fleet health totals')
    company = db.get_company_by_id(company_id)
    decrypted = []
    for row in result['endpoints']:
        if not isinstance(row, dict) or str(row.get('company_id')) != str(company_id) or (branch_id and str(row.get('branch_id')) != str(branch_id)):
            raise RuntimeError('Invalid fleet sample ownership')
        card = {field: value for field, value in row.items() if field in ENDPOINT_CARD_FIELDS}
        decrypted.append(db._decrypt_endpoint(card, company))
    result['endpoints'] = decrypted
    return result
