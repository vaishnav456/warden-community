"""Notifications database operations."""


def invalidate_request_cache():
    from flask import g, has_request_context
    if has_request_context():
        # Any mutation may trigger a notification. The transport calls this
        # before attempting it because a failed response can hide a commit.
        g.pop('_db_unread_count_cache', None)


def create_notification(admin_id, company_id, title, message, notif_type="info", link=None):
    import db as _db
    _db._post("notifications", {
        "admin_id": admin_id,
        "company_id": company_id,
        "title": title,
        "message": message,
        "type": notif_type,
        "link": link,
    }, prefer="return=minimal")

def get_notifications(admin_id, unread_only=False, limit=30):
    import db as _db
    path = f"notifications?admin_id=eq.{_db._q(admin_id)}&order=created_at.desc&limit={limit}"
    if unread_only:
        path += "&is_read=eq.false"
    return _db._get(path)

def count_unread_notifications(admin_id):
    import db as _db
    from flask import g, has_request_context
    # The route and template often need the same badge count. Share only this
    # integer for one request; authentication and vault state are never cached.
    cache = None
    key = str(admin_id)
    if has_request_context():
        cache = g.setdefault('_db_unread_count_cache', {})
        if key in cache:
            return cache[key]
    count = _db._count(f"notifications?admin_id=eq.{_db._q(admin_id)}&is_read=eq.false&select=id")
    if cache is not None:
        cache[key] = count
    return count

def mark_notifications_read(admin_id):
    import db as _db
    _db._patch(f"notifications?admin_id=eq.{_db._q(admin_id)}&is_read=eq.false", {
        "is_read": True,
        "read_at": _db._now_iso(),
    })

def cleanup_expired_tokens():
    """Delete expired, revoked refresh tokens older than 7 days."""
    import db as _db
    cutoff = (_db.datetime.now(_db.timezone.utc) - _db.timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        _db._delete(f"refresh_tokens?revoked=eq.true&created_at=lt.{_db._q(cutoff)}")
    except Exception:
        pass
