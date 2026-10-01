"""Evidence-based health findings; never infer SMART/security state from silence."""
from datetime import datetime, timezone


def age_seconds(value, now=None):
    try:
        seen = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        if seen.tzinfo is None:
            seen = seen.replace(tzinfo=timezone.utc)
        return ((now or datetime.now(timezone.utc)) - seen).total_seconds()
    except (ValueError, TypeError):
        return None


def findings(endpoint, latest_version=None, now=None):
    result = []
    def add(code, severity, title, detail, action=None):
        result.append(dict(code=code, severity=severity, title=title, detail=detail, action=action))
    age = age_seconds(endpoint.get('last_seen'), now)
    if endpoint.get('status') != 'online' or age is None or age > 180 or age < -300:
        add('offline', 'warning', 'Device not reporting', 'Check power and connectivity; actions wait until reconnect.')
    for field, threshold, code, title, unit in (
            ('disk_free_gb', 5, 'storage', 'Low free disk space', 'GB'),
            ('cpu_pct', 90, 'cpu', 'High CPU usage', '%'),
            ('ram_used_pct', 90, 'memory', 'High memory usage', '%')):
        value = endpoint.get(field)
        if isinstance(value, (int, float)) and ((value < threshold) if code == 'storage' else (value >= threshold)):
            add(code, 'critical' if code == 'storage' and value < 1 else 'warning', title,
                f'Last reported value: {value:g} {unit}. Inspect before taking action.', 'inventory')
    if latest_version and endpoint.get('agent_version'):
        from services.scheduler import compare_agent_versions
        try:
            if compare_agent_versions(endpoint['agent_version'], latest_version) < 0:
                add('update', 'warning', 'Agent update available',
                    f"Installed {endpoint['agent_version']}; available {latest_version}.", 'update')
        except ValueError:
            add('version', 'warning', 'Agent version unrecognized', 'Collect inventory to verify the installed agent.', 'inventory')
    capabilities = endpoint.get('capability_details')
    inventory = capabilities.get('device_health') if isinstance(capabilities,dict) else {}
    inventory = inventory if isinstance(inventory,dict) else {}
    inventory_age = age_seconds(inventory.get('collected_at'),now)
    if inventory_age is not None and -300 <= inventory_age < 900:
        for disk in inventory.get('disks') or []:
            if isinstance(disk,dict) and str(disk.get('HealthStatus','')).lower() in {'unhealthy','warning'}:
                add('disk_health','critical','Windows reports a disk health problem',
                    f"{disk.get('FriendlyName') or 'Disk'}: {disk.get('HealthStatus')}. Back up data and inspect the drive; do not automatically repair or format.", 'inventory')
        if str(inventory.get('defender_status','')).lower() == 'stopped':
            add('security_service','warning','Microsoft Defender service is stopped',
                'Verify whether another antivirus intentionally disabled Defender before changing security services.', 'inventory')
    return result


def remote_diagnostic(endpoint, session):
    reason = str(session.get('fail_reason') or '')
    lower = reason.lower()
    if endpoint.get('status') != 'online':
        return dict(code='device_offline', title='Device is offline', detail='Check power, internet and the Warden Agent service.', action='Wait for the device to reconnect.')
    if session.get('consent_required') and session.get('consent_status') == 'pending':
        return dict(code='awaiting_approval', title='Waiting for user approval', detail='The endpoint user must approve the remote-access notification.', action='Ask the user to check their notification. Approval is not bypassed.')
    if session.get('consent_status') in {'denied', 'rejected'}:
        return dict(code='approval_denied', title='Remote access was declined', detail=reason or 'The user declined consent.', action='Discuss the request with the user before requesting a new session.')
    if reason:
        if any(word in lower for word in ('firewall', 'tls', 'certificate', 'websocket', 'relay', 'timeout', 'timed out')):
            return dict(code='connection_failed', title='Remote connection failed', detail=reason, action='Check outbound HTTPS/443, proxy and certificate settings, then reconnect. A timeout alone does not prove a firewall block.')
        return dict(code='agent_failed', title='Endpoint reported a failure', detail=reason, action='Review endpoint events and the remote-access job before retrying.')
    return dict(code='connecting', title='Connecting to the device', detail='The browser is waiting for the endpoint relay and first screen frame.', action='If this continues, check the remote-access job and endpoint events.')
