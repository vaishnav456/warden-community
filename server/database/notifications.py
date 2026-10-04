"""Notifications database operations."""


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
    return _db._count(f"notifications?admin_id=eq.{_db._q(admin_id)}&is_read=eq.false&select=id")

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
        url = (
            f"{_db.config.SUPABASE_URL}/refresh_tokens"
            f"?revoked=eq.true&created_at=lt.{_db._q(cutoff)}"
        )
        headers = dict(_db._HEADERS)
        headers["Content-Profile"] = "endpt"
        req = _db.urllib.request.Request(url, method="DELETE", headers=headers)
        from contextlib import closing
        with closing(_db.urllib.request.urlopen(req, timeout=10, context=_db._SSL_CTX)):
            pass
    except Exception:
        pass
