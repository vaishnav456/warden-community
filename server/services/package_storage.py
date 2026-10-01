"""Explicit package deletion, quota reclamation and install/delete coordination."""
from contextlib import contextmanager
from pathlib import Path
import re
from urllib.parse import urlsplit

import config
import db
from services.tenant_storage import admission, StorageError


def package_id(payload):
    if not isinstance(payload, dict):
        return None
    match = re.fullmatch(r"/api/agent/apps/([^/]+)/download", urlsplit(str(payload.get("app_url") or "")).path)
    # app_url is what agents download; a conflicting app_id must not hide it.
    return match.group(1) if match else (str(payload["app_id"]) if payload.get("app_id") else None)


@contextmanager
def installation(company_id, payload):
    """All library install producers share the tenant deletion lease."""
    app_id = package_id(payload)
    if not app_id:  # External installers do not depend on App Library storage.
        yield
        return
    with admission(company_id, 0):
        app = db.get_app(app_id)
        if not app or app.get("deletion_requested_at"):
            raise StorageError("package_unavailable", "This package was deleted or is being deleted.", 409)
        if app.get("company_id") and str(app["company_id"]) != str(company_id):
            raise StorageError("package_unavailable", "Package is unavailable to this organization.", 404)
        yield


def _package_path(app):
    """Only canonical installer paths may be physically removed."""
    sha = str(app.get("sha256") or "")
    if not re.fullmatch(r"[0-9a-f]{64}", sha):
        raise StorageError("invalid_package_path", "Package storage reference is invalid.")
    relative = Path(app.get("file_path") or "")
    ext = relative.suffix.lower()
    if ext not in {".exe", ".msi", ".deb", ".rpm", ".pkg"}:
        raise StorageError("invalid_package_path", "Package storage reference is invalid.")
    expected = {Path("apps") / str(app["company_id"]) / sha[:2] / (sha + ext),
                Path("apps") / sha[:2] / (sha + ext)}  # Legacy shared layout.
    if relative not in expected:
        raise StorageError("invalid_package_path", "Package is outside this organization's storage.")
    root = Path(config.UPLOAD_DIR).resolve()
    path = root / relative
    if path.resolve() != path.absolute() or not path.resolve().is_relative_to(root / "apps"):
        raise StorageError("invalid_package_path", "Symbolic package paths cannot be deleted.")
    return path


def delete_package(company_id, app_id):
    # Zero growth allows cleanup even when already over quota.
    with admission(company_id, 0):
        app = db.get_app(app_id, include_deleting=True)
        if not app or str(app.get("company_id")) != str(company_id):
            raise StorageError("package_not_found", "Tenant package not found.", 404)
        path = _package_path(app)
        if db.package_in_use(company_id, app_id):
            raise StorageError("package_in_use",
                               "This package has queued/running installs, pending approvals or an enabled schedule. Finish or cancel them before deleting it.", 409)
        references = db.get_app_file_references(app["file_path"])
        shared = any(str(row["id"]) != str(app_id) for row in references)
        # Keep a durable retryable library entry until filesystem cleanup and
        # metadata deletion both finish. It cannot be downloaded or deployed.
        db.request_app_deletion(app_id, company_id)
        freed = 0
        if not shared and path.exists():
            size = path.stat().st_size
            try:
                path.unlink()
            except OSError as exc:
                raise StorageError("package_cleanup_failed",
                                   "Could not remove the package file. It remains counted in storage. Retry deletion from App Library.") from exc
            freed = size
        db.delete_app(app_id)
        return {"ok": True, "freed_bytes": freed, "shared_file_retained": shared,
                "message": ("Package removed. The installer is retained because another library entry uses it."
                            if shared else f"Package deleted; {freed} bytes of file storage freed.")}
