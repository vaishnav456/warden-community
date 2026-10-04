"""Branches database operations."""


def get_branches(company_id):
    import db as _db
    return _db._get_all(f"branches?company_id=eq.{_db._q(company_id)}&order=name.asc,id.asc")

def get_branch(branch_id):
    import db as _db
    rows = _db._get(f"branches?id=eq.{_db._q(branch_id)}&limit=1")
    return rows[0] if rows else None

def create_branch(company_id, name, city=None, timezone="UTC"):
    import db as _db
    data = {"company_id": company_id, "name": name, "timezone": timezone}
    if city:
        data["city"] = city
    rows = _db._post("branches", data)
    return rows[0] if (rows and isinstance(rows, list)) else rows

def update_branch(branch_id, company_id, fields):
    import db as _db
    rows = _db._patch(
        f"branches?id=eq.{_db._q(branch_id)}&company_id=eq.{_db._q(company_id)}",
        fields,
    )
    return rows[0] if rows else None

def delete_branch(branch_id):
    import db as _db
    _db._delete(f"branches?id=eq.{_db._q(branch_id)}")
