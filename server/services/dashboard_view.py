"""Read-only dashboard presentation and tenant/branch scope."""
from datetime import datetime, timedelta, timezone
import re
import uuid
from urllib.parse import urlencode

from flask import abort, g, request
import db


def selected_branch():
    if g.admin.get("role") == "branch_admin":
        branch = g.admin.get("branch_id")
        if not branch:
            abort(403)
        return str(branch)
    branch = request.args.get("branch_id") or None
    if branch:
        try:
            uuid.UUID(branch)
        except ValueError:
            abort(404)
        row = db.get_branch(branch)
        if not row or str(row.get("company_id")) != str(g.company["id"]):
            abort(404)
    return branch


def scoped_url(path, branch_id=None, **filters):
    params = {key: value for key, value in filters.items() if value not in (None, "")}
    if branch_id:
        params["branch_id"] = branch_id
    return path + ("?" + urlencode(params) if params else "")


def timestamp(value):
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result
    except (TypeError, ValueError):
        return None


def version(value):
    if not re.fullmatch(r"\d+\.\d+\.\d+", str(value or "")):
        return None
    return tuple(int(part) for part in str(value).split("."))


def report_online(endpoint, now=None):
    now = now or datetime.now(timezone.utc)
    seen = timestamp(endpoint.get("last_seen"))
    return bool(endpoint.get("status") == "online" and seen and timedelta(0) <= now - seen <= timedelta(minutes=3))


def prepare_endpoints(endpoints, compliance=(), patches=(), now=None):
    now = now or datetime.now(timezone.utc)
    checks = {str(row["endpoint_id"]): row for row in compliance}
    patch_ids = {str(row["endpoint_id"]) for row in patches}
    builds = {}
    result = []
    for original in endpoints:
        ep = dict(original)
        seen = timestamp(ep.get("last_seen"))
        fresh = bool(seen and timedelta(0) <= now - seen <= timedelta(minutes=3))
        ep["_fresh"] = fresh
        ep["_online"] = ep.get("status") == "online" and fresh
        ep["_offline_age"] = ("never" if not seen else "days" if now - seen >= timedelta(days=1) else "recent")
        target = db.endpoint_target_platform(ep)
        if target not in builds:
            builds[target] = db.get_latest_completed_build(target, summary_only=True)
        latest = builds[target] or {}
        current, available = version(ep.get("agent_version")), version(latest.get("agent_version"))
        ep["_agent_update"] = bool(current and available and current < available)
        ep["_agent_unknown"] = not bool(current and available)
        scan = checks.get(str(ep["id"]))
        scanned = timestamp(scan.get("scanned_at")) if scan else None
        scan_fresh = bool(scanned and timedelta(0) <= now - scanned <= timedelta(days=1))
        encryption = [item for item in (scan or {}).get("results", [])
                      if isinstance(item, dict) and item.get("check") in ("bitlocker_enabled", "disk_encryption_enabled")]
        ep["_encryption"] = ("unknown" if not scan_fresh or not encryption
                             else "attention" if any(item.get("status") == "fail" for item in encryption)
                             else "pass" if all(item.get("status") == "pass" for item in encryption) else "unknown")
        ep["_patch_attention"] = str(ep["id"]) in patch_ids
        result.append(ep)
    return sorted(result, key=lambda ep: (ep["_online"], not ep["_agent_update"], str(ep.get("display_name") or ep.get("hostname") or "").casefold()))


def group_alerts(alerts):
    groups = {}
    priority = {"critical": 0, "warning": 1, "info": 2}
    for alert in alerts:
        key = (alert.get("endpoint_id") or alert.get("id"), alert.get("type") or alert.get("title"))
        if key not in groups:
            groups[key] = dict(alert, repeats=0)
        groups[key]["repeats"] += 1
        if priority.get(alert.get("severity"), 3) < priority.get(groups[key].get("severity"), 3):
            groups[key]["severity"] = alert["severity"]
    return sorted(groups.values(), key=lambda a: priority.get(a.get("severity"), 3))
