"""Community-edition feature checks.

The community server is single-organization and has no subscription,
organization lifecycle, rollout cohort, or commercial capacity gate.
"""
from dataclasses import dataclass


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
    return {
        "status": "active", "lifecycle_state": "active",
        "plan_code": "community", "plan_name": "Community",
        "features": {}, "limits": {"endpoints": None, "admins": None, "branches": None},
    }


def check_mutation(company_id):
    return Decision(True)


def check_feature(company_id, feature):
    return Decision(True)


def platform_feature_enabled(company_id, feature_key):
    """Community features are locally available without a SaaS rollout gate."""
    return True


def effective_platform_features(company_id):
    return {}


def check_capacity(company_id, resource):
    return Decision(True)


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
