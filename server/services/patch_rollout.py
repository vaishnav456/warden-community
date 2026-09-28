"""Pure helpers for deterministic patch rollout rings and target scopes."""

import hashlib


def endpoint_in_scope(endpoint, policy):
    scope = policy.get("scope_type")
    value = policy.get("scope_value")
    if scope == "tenant":
        return True
    if scope == "branch":
        return str(endpoint.get("branch_id") or "") == str(value or "")
    if scope == "tag":
        return str(value or "").casefold() in {str(tag).casefold() for tag in endpoint.get("tags") or []}
    if scope == "endpoints":
        values = value if isinstance(value, list) else []
        return str(endpoint.get("id")) in {str(item) for item in values}
    return False


def assign_rings(endpoints, deployment_id, pilot_percentage):
    """Stable cohorts: the same deployment always yields the same ring."""
    eligible = sorted(endpoints, key=lambda endpoint: hashlib.sha256(
        f"{deployment_id}:{endpoint['id']}".encode()).hexdigest())
    if not eligible:
        return {"pilot": [], "broad": []}
    pilot_count = max(1, (len(eligible) * int(pilot_percentage) + 99) // 100)
    return {"pilot": eligible[:pilot_count], "broad": eligible[pilot_count:]}

