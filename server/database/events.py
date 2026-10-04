"""Events database operations."""


def log_endpoint_event(endpoint_id, event_type, detail=None):
    import db as _db
    company = _db._endpoint_company(endpoint_id)
    _db._post("endpoint_events", {
        "endpoint_id": endpoint_id,
        "event_type": event_type,
        "detail": {},
        "detail_encrypted": _db._endpoint_encrypt(
            company, "event.detail", detail or {},
        ),
    }, prefer="return=minimal")

def get_endpoint_events(endpoint_id, limit=50):
    import db as _db
    rows = _db._get(
        f"endpoint_events?endpoint_id=eq.{_db._q(endpoint_id)}"
        f"&order=created_at.desc&limit={limit}"
    )
    company = _db._endpoint_company(endpoint_id)
    for row in rows:
        encrypted = row.pop("detail_encrypted", None)
        if encrypted:
            row["detail"] = _db._endpoint_decrypt(company, "event.detail", encrypted)
    return rows

def get_recent_endpoint_events(endpoint_id, event_type, since_iso, limit=50):
    """Events of a given type for this endpoint since a given ISO timestamp —
    used by alert_engine.py's anomaly checks (e.g. counting how many
    tls_cert_rotation_detected or ip_changed events happened in a recent
    window, rather than reacting to any single occurrence of either, which
    can be entirely legitimate on its own)."""
    import db as _db
    rows = _db._get(
        f"endpoint_events?endpoint_id=eq.{_db._q(endpoint_id)}"
        f"&event_type=eq.{_db._q(event_type)}"
        f"&created_at=gte.{_db._q(since_iso)}"
        f"&order=created_at.desc&limit={limit}"
    )
    company = _db._endpoint_company(endpoint_id)
    for row in rows:
        encrypted = row.pop("detail_encrypted", None)
        if encrypted:
            row["detail"] = _db._endpoint_decrypt(company, "event.detail", encrypted)
    return rows
