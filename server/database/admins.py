"""Admins database operations."""


def get_admin_by_email(email):
    import db as _db
    rows = _db._get(f"admin_users?email=eq.{_db._q(email)}&limit=1")
    row = rows[0] if rows else None
    if row and row.get("mfa_secret"):
        from services.platform_secrets import decrypt_mfa_secret
        row["mfa_secret"] = decrypt_mfa_secret(row["id"], row["mfa_secret"])
    return row

def get_admin_by_id(admin_id):
    import db as _db
    rows = _db._get(f"admin_users?id=eq.{_db._q(admin_id)}&limit=1")
    row = rows[0] if rows else None
    if row and row.get("mfa_secret"):
        from services.platform_secrets import decrypt_mfa_secret
        row["mfa_secret"] = decrypt_mfa_secret(row["id"], row["mfa_secret"])
    return row

def get_admins_for_company(company_id):
    import db as _db
    return _db._get(f"admin_users?company_id=eq.{_db._q(company_id)}&order=full_name.asc")

def get_all_admins():
    import db as _db
    return _db._get("admin_users?order=email.asc")

def create_admin_user(email, password_hash, full_name, role, company_id=None, branch_id=None, created_by=None):
    import db as _db
    payload = {
        "email": email,
        "password_hash": password_hash,
        "full_name": full_name,
        "role": role,
    }
    if company_id:
        payload["company_id"] = company_id
    if branch_id:
        payload["branch_id"] = branch_id
    if created_by:
        payload["created_by"] = created_by
    rows = _db._post("admin_users", payload)
    return rows[0] if (rows and isinstance(rows, list)) else rows

def update_admin(admin_id, data):
    import db as _db
    rows = _db._patch(f"admin_users?id=eq.{_db._q(admin_id)}", data)
    return rows[0] if (rows and isinstance(rows, list)) else rows

def update_admin_failed_attempts(admin_id, count, locked_until=None):
    import db as _db
    data = {"failed_attempts": count}
    if locked_until:
        data["locked_until"] = locked_until
    _db._patch(f"admin_users?id=eq.{_db._q(admin_id)}", data)

def update_admin_last_login(admin_id, ip):
    import db as _db
    _db._patch(f"admin_users?id=eq.{_db._q(admin_id)}", {
        "last_login_at": _db._now_iso(),
        "last_login_ip": ip,
        "failed_attempts": 0,
        "locked_until": None,
    })

def update_admin_mfa(admin_id, secret, backup_codes):
    import db as _db
    from services.platform_secrets import encrypt_mfa_secret, hash_backup_code
    _db._patch(f"admin_users?id=eq.{_db._q(admin_id)}", {
        "mfa_secret": encrypt_mfa_secret(admin_id, secret),
        "mfa_enabled": True,
        "mfa_backup_codes": [hash_backup_code(code) for code in backup_codes],
    })

def disable_admin_mfa(admin_id):
    import db as _db
    _db._patch(f"admin_users?id=eq.{_db._q(admin_id)}", {
        "mfa_secret": None,
        "mfa_enabled": False,
        "mfa_backup_codes": None,
    })

def update_admin_password(admin_id, new_hash):
    import db as _db
    _db._patch(f"admin_users?id=eq.{_db._q(admin_id)}", {"password_hash": new_hash})
