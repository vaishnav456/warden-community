"""Explicit cleanup of obsolete MSI installers; agent update archives stay intact."""
from pathlib import Path
import uuid
import db
import config


def msi_path(build_id):
    clean = str(uuid.UUID(str(build_id)))
    root = Path(config.AGENT_DIST_DIR).resolve()
    path = root / clean / 'agent-installer.msi'
    if path.resolve() != path.absolute() or not path.resolve().is_relative_to(root):
        raise ValueError('Installer storage path is unsafe')
    return path


def inventory(company_id):
    builds = db.get_build_requests(company_id,1000)
    latest = {}
    result = []
    for build in builds:
        platform = build.get('target_platform') or 'windows-amd64'
        if platform not in latest:
            latest[platform] = (db.get_latest_completed_build(platform) or {}).get('id')
        path = msi_path(build['id'])
        if not path.is_file():
            continue
        result.append(dict(id=build['id'],version=build.get('agent_version'),created_at=build.get('created_at'),
                           bytes=path.stat().st_size,removable=build.get('status') in {'completed','failed','cancelled'} and str(build['id']) != str(latest[platform])))
    return result


def remove_msi(company_id,build_id):
    from services.tenant_storage import admission
    with admission(company_id,0):
        build = db.get_build_request(build_id)
        if not build or str(build.get('company_id')) != str(company_id):
            raise ValueError('Installer not found')
        platform = build.get('target_platform') or 'windows-amd64'
        latest = db.get_latest_completed_build(platform) or {}
        if str(latest.get('id')) == str(build_id) or build.get('status') not in {'completed','failed','cancelled'}:
            raise ValueError('Current or active installer cannot be removed')
        path = msi_path(build_id)
        size = path.stat().st_size if path.is_file() else 0
        # Stop new installer downloads first. Agent updates use the ZIP, not MSI.
        db._patch(f"build_requests?id=eq.{db._q(build_id)}&company_id=eq.{db._q(company_id)}",{'msi_ready':False})
        path.unlink(missing_ok=True)
        return size


def pressure(used,limit):
    if limit <= 0:
        return 0
    ratio = used / limit
    return 100 if ratio >= 1 else 95 if ratio >= .95 else 80 if ratio >= .8 else 0


def check_pressure():
    return  # Community does not impose a hosted storage allowance.
