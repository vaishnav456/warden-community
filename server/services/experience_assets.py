"""Lifecycle rules for tenant device-experience images."""
from datetime import datetime, timedelta, timezone


RETENTION = timedelta(days=3)


def is_available(path, now=None):
    """Images may be downloaded for at most 72 hours after last deployment."""
    now = now or datetime.now(timezone.utc)
    modified = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
    return modified >= now - RETENTION


def cleanup_expired(upload_dir, now=None):
    """Remove only expired, content-addressed branding images."""
    root = (upload_dir / "branding").resolve()
    if not root.is_dir():
        return 0
    removed = 0
    for path in root.glob("*/*"):
        if (not path.is_file() or path.suffix.lower() not in {".png", ".jpg"}
                or len(path.stem) != 64):
            continue
        try:
            int(path.stem, 16)
            if not is_available(path, now=now):
                path.unlink()
                removed += 1
        except (OSError, ValueError):
            continue
    return removed
