"""Centralized tenant lifecycle, feature and capacity enforcement."""
from dataclasses import dataclass
import hashlib
from datetime import datetime, timezone

import db


@dataclass
class Decision:
    allowed: bool
    code: str = "ok"
    message: str = ""
    limit: int | None = None
    used: int | None = None


MUTATING_STATES = {"active", "grace"}
INTERACTIVE_STATES = {"active", "grace"}


def access(company_id):
    record = db.get_company_subscription(company_id)
    if not record:
        return {
            "status": "active", "lifecycle_state": "active", "plan_code": "legacy",
            "plan_name": "Legacy", "features": {}, "limits": {"endpoints": 2},
        }
    plan = record.get("plans") or {}
    features = dict(plan.get("features") or {})
    limits = {
        "endpoints": plan.get("endpoint_limit"),
        "admins": plan.get("admin_limit"),
        "branches": plan.get("branch_limit"),
    }
    for override in db.get_active_entitlement_overrides(company_id):
        key, value = override.get("entitlement_key"), override.get("value")
        if key in limits:
            limits[key] = value
        elif key:
            features[key] = value
    return {
        **record,
        "plan_code": plan.get("code", "legacy"),
        "plan_name": plan.get("name", "Legacy"),
        "features": features,
        "limits": limits,
    }


def check_mutation(company_id):
    state = access(company_id).get("lifecycle_state", "active")
    if state not in MUTATING_STATES:
        return Decision(False, "tenant_read_only",
                        f"Tenant lifecycle is {state}; changes are disabled.")
    return Decision(True)


def check_feature(company_id, feature):
    info = access(company_id)
    if info.get("lifecycle_state") not in INTERACTIVE_STATES:
        return Decision(False, "tenant_unavailable",
                        f"Tenant lifecycle is {info.get('lifecycle_state')}.")
    # Missing feature keys preserve compatibility for pre-migration deployments.
    if feature in info["features"] and not bool(info["features"][feature]):
        return Decision(False, "feature_not_entitled",
                        f"{feature.replace('_', ' ').title()} is not included in {info['plan_name']}.")
    return Decision(True)


def platform_feature_enabled(company_id, feature_key):
    """Resolve a platform rollout deterministically for one tenant.

    Explicit tenant overrides win. Otherwise the global kill switch and a
    stable tenant/key bucket enforce the rollout percentage without cookies
    or a tenant changing cohorts between requests.
    """
    flag = next((f for f in db.get_feature_flags() if f.get("key") == feature_key), None)
    if not flag or not flag.get("is_enabled") or flag.get("stage") == "retired":
        return False
    now = datetime.now(timezone.utc)
    for override in db.get_feature_overrides(company_id):
        if str(override.get("flag_id")) != str(flag["id"]):
            continue
        expires = override.get("expires_at")
        if expires:
            try:
                if datetime.fromisoformat(expires.replace("Z", "+00:00")) <= now:
                    continue
            except ValueError:
                continue
        return bool(override.get("enabled"))
    rollout = int(flag.get("rollout_percent") or 0)
    bucket = int(hashlib.sha256(f"{feature_key}:{company_id}".encode()).hexdigest()[:8], 16) % 100
    return bucket < rollout


def effective_platform_features(company_id):
    return {flag["key"]: platform_feature_enabled(company_id, flag["key"])
            for flag in db.get_feature_flags()}


def check_capacity(company_id, resource):
    mutation = check_mutation(company_id)
    if not mutation.allowed:
        return mutation
    info = access(company_id)
    limit = info["limits"].get(resource)
    if limit is None:
        return Decision(True)
    used = db.get_company_usage(company_id).get(resource, 0)
    if used >= int(limit):
        return Decision(False, "capacity_reached",
                        f"{resource.title()} capacity reached ({used}/{limit}).",
                        int(limit), used)
    return Decision(True, limit=int(limit), used=used)


JOB_FEATURES = {
    "SETUP_REMOTE_ACCESS": "remote_control",
    "REMOVE_REMOTE_ACCESS": "remote_control",
    "FILE_PUSH": "file_transfer",
    "FILE_PULL": "file_transfer",
    "LIST_DIRECTORY": "file_transfer",
    "PUSH_LOCAL_POLICY": "policy_management",
    "CHECK_POLICY_DRIFT": "policy_management",
}


def check_job(company_id, job_type):
    mutation = check_mutation(company_id)
    if not mutation.allowed:
        return mutation
    return check_feature(company_id, JOB_FEATURES.get(job_type, "jobs"))
