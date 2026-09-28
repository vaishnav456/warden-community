"""Deterministic custom-rule analysis for observed endpoint connections."""

import fnmatch
import ipaddress


def _port_matches(filters, value):
    if not filters:
        return True
    for entry in filters:
        text = str(entry)
        if "-" in text:
            start, end = text.split("-", 1)
            if int(start) <= int(value or 0) <= int(end):
                return True
        elif int(text) == int(value or 0):
            return True
    return False


def _address_matches(filters, value):
    if not filters:
        return True
    try:
        address = ipaddress.ip_address(value)
        return any(address in ipaddress.ip_network(item, strict=False) for item in filters)
    except (ValueError, TypeError):
        return False


def _specificity(rule):
    explicit = rule.get("priority")
    if explicit is not None:
        return int(explicit)
    return (100 if rule.get("program") else 0) + (30 if rule.get("remote_addresses") else 0) + \
        (20 if rule.get("remote_ports") else 0) + (10 if rule.get("protocol", "any") != "any" else 0)


def evaluate_flow(flow, rules):
    candidates = []
    flow_direction = {"outbound": "out", "inbound": "in"}.get(
        flow.get("direction"), flow.get("direction", "out")
    )
    for index, rule in enumerate(rules or []):
        if not rule.get("enabled", True):
            continue
        if rule.get("direction", "out") not in {"both", flow_direction}:
            continue
        protocol = str(rule.get("protocol") or "any").lower()
        if protocol != "any" and protocol != str(flow.get("protocol") or "").lower():
            continue
        program = str(rule.get("program") or "")
        if program and not fnmatch.fnmatch(str(flow.get("process_path") or "").casefold(), program.casefold()):
            continue
        if not _port_matches(rule.get("remote_ports") or [], flow.get("remote_port")):
            continue
        if not _address_matches(rule.get("remote_addresses") or [], flow.get("remote_address")):
            continue
        candidates.append((_specificity(rule), rule.get("action") == "block", -index, rule))
    if not candidates:
        return {"action": "unmatched", "rule": None, "weight": 0}
    weight, _, _, winner = max(candidates, key=lambda item: item[:3])
    return {"action": winner.get("action", "allow"), "rule": winner.get("name"), "weight": weight}
