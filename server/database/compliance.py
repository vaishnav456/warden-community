"""Compliance database operations."""


def create_compliance_policy(company_id, branch_id, name, description, checks, created_by):
    import db as _db
    data = {
        "company_id": str(company_id),
        "name": name,
        "description": description or "",
        "checks": checks,
        "enabled": True,
        "created_by": str(created_by) if created_by else None,
        "created_at": _db._now_iso(),
        "updated_at": _db._now_iso(),
    }
    if branch_id:
        data["branch_id"] = str(branch_id)
    rows = _db._post("compliance_policies", data)
    return rows[0] if (rows and isinstance(rows, list)) else rows

def get_compliance_policies(company_id, branch_id=None):
    import db as _db
    q = f"compliance_policies?company_id=eq.{_db._q(str(company_id))}&order=created_at.asc"
    if branch_id:
        q += f"&branch_id=eq.{_db._q(str(branch_id))}"
    return _db._get(q) or []

def get_compliance_policy(policy_id):
    import db as _db
    rows = _db._get(f"compliance_policies?id=eq.{_db._q(str(policy_id))}&limit=1")
    return rows[0] if rows else None

def update_compliance_policy(policy_id, name, description, checks, enabled):
    import db as _db
    _db._patch(f"compliance_policies?id=eq.{_db._q(str(policy_id))}", {
        "name": name,
        "description": description or "",
        "checks": checks,
        "enabled": enabled,
        "updated_at": _db._now_iso(),
    })

def delete_compliance_policy(policy_id):
    import db as _db
    _db._delete(f"compliance_policies?id=eq.{_db._q(str(policy_id))}")

def upsert_compliance_result(endpoint_id, company_id, policy_id, overall_status, score, results, policy_fingerprint=None):
    # Use POST with upsert (on_conflict=endpoint_id)
    import db as _db
    data = {
        "endpoint_id": str(endpoint_id),
        "company_id": str(company_id),
        "overall_status": overall_status,
        "score": score,
        "results": results,
        "scanned_at": _db._now_iso(),
        "policy_fingerprint": policy_fingerprint if isinstance(policy_fingerprint, str) and len(policy_fingerprint) == 64 else None,
        "policy_id": str(policy_id) if policy_id else None,
    }
    _db._post("compliance_results", data,
          prefer="resolution=merge-duplicates,return=representation")

def get_compliance_result(endpoint_id):
    import db as _db
    rows = _db._get(f"compliance_results?endpoint_id=eq.{_db._q(str(endpoint_id))}&limit=1")
    return rows[0] if rows else None

def get_compliance_results_for_company(company_id, branch_id=None, *, summary_only=False):
    import db as _db
    path = f"compliance_results?company_id=eq.{_db._q(str(company_id))}"
    fields = "endpoint_id,scanned_at,results" if summary_only else "*"
    if branch_id:
        fields += ",endpoints!inner(branch_id)"
        path += f"&endpoints.branch_id=eq.{_db._q(branch_id)}"
    if summary_only or branch_id:
        path += f"&select={fields}"
    return _db._get_all(path + "&order=scanned_at.desc,endpoint_id.asc") or []
