"""Apps database operations."""


def get_app_library(company_id=None, include_global=True, include_deleting=False):
    import db as _db
    suffix = "" if include_deleting else "&deletion_requested_at=is.null"
    if include_global and company_id:
        rows = _db._get(f"app_library?or=(company_id.is.null,company_id.eq.{_db._q(company_id)})&order=name.asc" + suffix)
    elif company_id:
        rows = _db._get(f"app_library?company_id=eq.{_db._q(company_id)}&order=name.asc" + suffix)
    else:
        rows = _db._get("app_library?company_id=is.null&order=name.asc" + suffix)
    return rows

def get_app(app_id, include_deleting=False):
    import db as _db
    suffix = "" if include_deleting else "&deletion_requested_at=is.null"
    rows = _db._get(f"app_library?id=eq.{_db._q(app_id)}&limit=1" + suffix)
    return rows[0] if rows else None

def get_app_file_references(file_path):
    import db as _db
    return _db._get(f"app_library?file_path=eq.{_db._q(file_path)}&select=id&limit=2")

def request_app_deletion(app_id, company_id):
    import db as _db
    rows = _db._patch(f"app_library?id=eq.{_db._q(app_id)}&company_id=eq.{_db._q(company_id)}",
                  {"deletion_requested_at": _db._now_iso()})
    if not rows:
        raise RuntimeError("Could not mark package for deletion")

def package_in_use(company_id, app_id):
    import db as _db
    from services.package_storage import package_id
    company = None
    sources = (
        ("jobs", "type=eq.INSTALL_APP&status=in.(pending,approved,running)", "job.payload"),
        ("escalation_requests", "operation=eq.INSTALL_APP&status=in.(pending,pending_secondary,approved)", "escalation.payload"),
        ("scheduled_jobs", "job_type=eq.INSTALL_APP&enabled=eq.true", None),
    )
    for table, filters, domain in sources:
        offset = 0
        while True:
            rows = _db._get(f"{table}?company_id=eq.{_db._q(company_id)}&{filters}"
                        f"&select=id,payload&order=id.asc&limit=500&offset={offset}")
            for row in rows:
                payload = row.get("payload")
                if domain and payload is not None:
                    company = company or _db.get_company_by_id(company_id)
                    payload = _db.decrypt_field(company, payload, domain)
                if not isinstance(payload, dict) or str(package_id(payload)) == str(app_id):
                    return True  # Unreadable active references fail closed.
            if len(rows) < 500:
                break
            offset += len(rows)
    return bool(_db._get(f"software_patch_rules?company_id=eq.{_db._q(company_id)}&app_id=eq.{_db._q(app_id)}&enabled=eq.true&select=id&limit=1"))

def create_app(name, version, sha256, file_path, size_bytes, company_id=None,
               description=None, install_args="", self_service=False):
    import db as _db
    rows = _db._post("app_library", {
        "name": name,
        "version": version,
        "sha256": sha256,
        "file_path": file_path,
        "size_bytes": size_bytes,
        "company_id": company_id,
        "description": description,
        "install_args": install_args,
        "self_service": bool(self_service),
    })
    return rows[0] if (rows and isinstance(rows, list)) else rows

def update_app(app_id, values):
    import db as _db
    allowed = {"name", "version", "description", "install_args", "self_service"}
    payload = {key: value for key, value in values.items() if key in allowed}
    if not payload:
        return _db.get_app(app_id)
    rows = _db._patch(f"app_library?id=eq.{_db._q(app_id)}", payload)
    return rows[0] if rows else None

def delete_app(app_id):
    import db as _db
    _db._delete(f"app_library?id=eq.{_db._q(app_id)}")
