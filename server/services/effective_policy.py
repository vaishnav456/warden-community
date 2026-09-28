"""Resolve persistent policy assignments into one explainable endpoint policy."""

import json


SCOPE_RANK = {"tenant": 100, "branch": 200, "tag": 300, "endpoint": 400}


def assignment_matches(assignment, endpoint):
    scope = assignment.get("scope_type")
    value = assignment.get("scope_value")
    if not assignment.get("enabled", True):
        return False
    if scope == "tenant":
        return True
    if scope == "branch":
        return str(value) == str(endpoint.get("branch_id") or "")
    if scope == "endpoint":
        return str(value) == str(endpoint.get("id") or "")
    if scope == "tag":
        wanted = str(value or "").casefold()
        return any(str(tag).casefold() == wanted for tag in (endpoint.get("tags") or []))
    return False


def resolve_effective_policy(endpoint, assignments):
    """Return settings plus a complete source chain.

    Assignments must contain a ``template`` object (or ``settings`` directly).
    Higher scope wins: endpoint > tag > branch > tenant. Within one scope,
    priority wins; updated_at/id provide deterministic ordering. Equal-ranked,
    equal-priority assignments that disagree are reported as conflicts even
    though the deterministic last assignment is selected.
    """
    applicable = [item for item in assignments if assignment_matches(item, endpoint)]
    applicable.sort(key=lambda item: (
        SCOPE_RANK.get(item.get("scope_type"), 0),
        int(item.get("priority") or 0),
        str(item.get("updated_at") or item.get("created_at") or ""),
        str(item.get("id") or ""),
    ))

    effective = {}
    provenance = {}
    conflicts = []
    same_level = {}
    for assignment in applicable:
        template = assignment.get("template") or {}
        settings = assignment.get("settings") or template.get("settings") or {}
        source = {
            "assignment_id": str(assignment.get("id") or ""),
            "template_id": str(assignment.get("template_id") or template.get("id") or ""),
            "template_name": template.get("name") or assignment.get("template_name") or "Policy",
            "scope_type": assignment.get("scope_type"),
            "scope_value": assignment.get("scope_value"),
            "priority": int(assignment.get("priority") or 0),
        }
        level = (SCOPE_RANK.get(source["scope_type"], 0), source["priority"])
        for key, value in settings.items():
            previous_at_level = same_level.get((key, level))
            if previous_at_level and previous_at_level["value"] != value:
                conflicts.append({
                    "setting": key,
                    "level": {"scope": source["scope_type"], "priority": source["priority"]},
                    "sources": [previous_at_level["source"], source],
                    "values": [previous_at_level["value"], value],
                    "selected": source,
                })
            same_level[(key, level)] = {"value": value, "source": source}
            provenance.setdefault(key, []).append({**source, "value": value})
            effective[key] = value

    return {
        "endpoint_id": str(endpoint.get("id") or ""),
        "settings": effective,
        "provenance": provenance,
        "conflicts": conflicts,
        "assignments": applicable,
        "fingerprint": _fingerprint(effective),
    }


def _fingerprint(settings):
    import hashlib
    encoded = json.dumps(settings, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()

