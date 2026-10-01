"""Fresh, policy-bound evidence for conditional sign-in."""
import hashlib
import json
from services.device_health import age_seconds


def active_policy(endpoint, policies):
    applicable = [p for p in policies if p.get("enabled", True)
                  and str(p.get("company_id")) == str(endpoint["company_id"])]
    return next((p for p in applicable if p.get("branch_id")
                 and str(p["branch_id"]) == str(endpoint.get("branch_id"))),
                next((p for p in applicable if not p.get("branch_id")), None))


def fingerprint(endpoint, policy):
    from routes.compliance import _checks_for_endpoint
    content = [str(policy["id"]) if policy else None,
               sorted(_checks_for_endpoint(endpoint, policy)),
               str(policy.get("updated_at") or "") if policy else ""]
    return hashlib.sha256(json.dumps(content, separators=(",", ":")).encode()).hexdigest()


def permits_sign_in(endpoint, result, policies, now=None):
    if not result or result.get("overall_status") != "compliant":
        return False
    if str(result.get("company_id")) != str(endpoint["company_id"]) or str(result.get("endpoint_id")) != str(endpoint["id"]):
        return False
    age = age_seconds(result.get("scanned_at"), now)
    if age is None or not 0 <= age <= 86400:
        return False
    return result.get("policy_fingerprint") == fingerprint(endpoint, active_policy(endpoint, policies))


def prepare_scan(company_id, endpoint_id, payload):
    import db
    from routes.compliance import _checks_for_endpoint
    endpoint = db.get_endpoint(endpoint_id)
    if not endpoint or str(endpoint["company_id"]) != str(company_id):
        raise ValueError("Compliance target ownership changed")
    policy = active_policy(endpoint, db.get_compliance_policies(company_id))
    return {**(payload or {}), "policy_id": str(policy["id"]) if policy else None,
            "checks": _checks_for_endpoint(endpoint, policy),
            "policy_fingerprint": fingerprint(endpoint, policy)}


def scan_receipt(endpoint, job_id):
    """Bind old and new agent results to the scan actually issued by this server."""
    import db
    job = db.get_job(job_id) if job_id else None
    if not job or job.get("type") != "COMPLIANCE_SCAN" or job.get("status") != "running":
        raise ValueError("Compliance scan is not running")
    if str(job.get("company_id")) != str(endpoint["company_id"]) or str(job.get("endpoint_id")) != str(endpoint["id"]):
        raise ValueError("Compliance scan target does not match")
    age = age_seconds(job.get("started_at"))
    if age is None or not 0 <= age <= 86400:
        raise ValueError("Compliance scan has expired")
    payload = job.get("payload") or {}
    return payload.get("policy_id"), payload.get("policy_fingerprint")
