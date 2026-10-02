"""Community storage coordination. No subscriptions or hosted capacity limits."""
from contextlib import contextmanager
from pathlib import Path
import uuid
import logging
import db
import config


class StorageError(OSError):
    def __init__(self,code,message,status=503):
        super().__init__(message)
        self.code,self.status=code,status


@contextmanager
def admission(company_id,additional_bytes,replacing=None,operational=False):
    if company_id is None:
        yield
        return
    token=str(uuid.uuid4())
    if not db._rpc('claim_tenant_storage',dict(p_company_id=str(company_id),p_token=token)):
        raise StorageError('storage_busy','Storage cleanup or package publication is in progress. Retry shortly.',409)
    try:
        yield
    finally:
        try:
            db._rpc('release_tenant_storage',dict(p_company_id=str(company_id),p_token=token))
        except Exception:
            logging.getLogger(__name__).exception('Storage lease release failed')


def usage(company_id):
    paths=set()
    root=Path(config.UPLOAD_DIR).resolve()
    for app in db.get_app_library(company_id,include_global=False,include_deleting=True):
        path=(root/str(app.get('file_path') or '')).resolve()
        if not path.is_relative_to(root):
            raise StorageError('invalid_storage_path','Invalid package storage reference')
        paths.add(path)
    root=Path(config.AGENT_DIST_DIR).resolve()
    for build in db.get_build_requests(company_id,1000):
        path=root/str(uuid.UUID(str(build['id'])))
        if path.is_dir():
            for file in path.rglob('*'):
                if not file.resolve().is_relative_to(root):
                    raise StorageError('invalid_storage_path','Invalid build storage reference')
                if file.is_file():
                    paths.add(file.resolve())
    total=sum(path.stat().st_size for path in paths if path.is_file())
    database_bytes=int(db._rpc('tenant_database_bytes', {'p_company_id':str(company_id)}))
    return dict(used_bytes=total+database_bytes,file_bytes=total,database_bytes=database_bytes)
