"""Read-only, tenant-scoped package audit; never automatically delete files."""
import hashlib
import os
import uuid
from pathlib import Path
import config
import db
from services.tenant_storage import admission, StorageError
from services.package_storage import _package_path


def reconcile(company_id, max_files=10000):
    company_id = str(uuid.UUID(str(company_id)))
    if not 1 <= max_files <= 10000:
        raise ValueError('Invalid reconciliation bound')
    with admission(company_id, 0):
        root = Path(config.UPLOAD_DIR).resolve()
        tenant = root / 'apps' / company_id
        if tenant.resolve() != tenant.absolute():
            raise StorageError('invalid_storage_path', 'Symbolic tenant storage path')
        rows = db._get_all(f"app_library?company_id=eq.{db._q(company_id)}&select=id,company_id,file_path,sha256&order=id.asc")
        references = set()
        missing = []
        for row in rows:
            if str(row.get('company_id')) != company_id:
                raise StorageError('invalid_storage_path', 'Invalid package ownership')
            path = _package_path(row)
            references.add(path.absolute())
            if not path.is_file():
                missing.append(str(row['id']))
        orphan_count = orphan_bytes = scanned = 0
        fingerprints = []
        complete = True
        if tenant.is_dir():
            def scan_error(error):
                raise StorageError('storage_scan_failed', 'Package scan could not be completed')
            for directory, dirs, files in os.walk(tenant, followlinks=False, onerror=scan_error):
                if any((Path(directory) / name).is_symlink() for name in dirs + files):
                    raise StorageError('invalid_storage_path', 'Symbolic package storage path')
                for name in files:
                    if scanned >= max_files:
                        complete = False
                        break
                    path = Path(directory) / name
                    scanned += 1
                    if path.absolute() not in references:
                        orphan_count += 1
                        orphan_bytes += path.stat().st_size
                        if len(fingerprints) < 100:
                            fingerprints.append(hashlib.sha256(str(path.relative_to(root)).encode()).hexdigest())
                if not complete:
                    break
        return dict(read_only=True, complete=complete, scanned_files=scanned,
                    missing_package_ids=missing[:100], missing_package_count=len(missing),
                    unreferenced_file_count=orphan_count, unreferenced_bytes=orphan_bytes,
                    path_fingerprints=fingerprints,
                    scope='tenant package files only; branding, build artifacts and Home excluded',
                    warning='Unreferenced does not mean safe to delete. Review active work first.')
