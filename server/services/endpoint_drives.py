"""Bounded, defensive view of agent-reported encrypted local drive telemetry."""
import math
import re


def local_drives(endpoint):
    details = endpoint.get('capability_details')
    snapshot = details.get('local_drives') if isinstance(details, dict) else None
    values = snapshot.get('volumes') if isinstance(snapshot, dict) else None
    if not isinstance(values, list):
        return []
    result, seen = [], set()
    for row in values[:26]:
        if not isinstance(row, dict):
            continue
        mount = row.get('mount_point')
        if not isinstance(mount, str) or not re.fullmatch(r'[A-Za-z]:', mount):
            continue
        mount = mount.upper()
        total, free = row.get('total_gb'), row.get('free_gb')
        if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v)
               for v in (total, free)):
            continue
        if mount in seen or not 0 <= free <= total or total <= 0:
            continue
        seen.add(mount)
        result.append(dict(mount_point=mount, total_gb=total, used_gb=round(total-free, 2),
                           free_gb=free, used_pct=round(100*(total-free)/total, 1)))
    return sorted(result, key=lambda row: row['mount_point'])
