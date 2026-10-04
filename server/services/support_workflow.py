"""Support triage uses reported evidence, never guesses a diagnosis or grants access."""
from datetime import datetime, timezone
import hashlib
from services.device_health import findings, age_seconds


def text(value):
    if not isinstance(value, str):
        raise ValueError("Enter a message.")
    value = value.replace("\r\n", "\n").strip()
    if not 1 <= len(value) <= 2000 or any(ord(c) < 32 and c not in "\n\t" for c in value):
        raise ValueError("Enter a message of at most 2000 characters.")
    return value


def requester_key(username):
    return hashlib.sha256(username.strip().casefold().encode("utf-8")).hexdigest()


def visit_time(value):
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if stamp.tzinfo is None or stamp <= datetime.now(timezone.utc):
            raise ValueError()
        return stamp.astimezone(timezone.utc).isoformat()
    except (ValueError, TypeError, AttributeError):
        raise ValueError("Use a future date with a timezone, for example 2026-10-05T10:00:00+05:30.")


def triage(endpoint):
    age = age_seconds(endpoint.get("last_seen"))
    online = endpoint.get("status") == "online" and age is not None and -300 <= age <= 180
    return {
        "reachable": online,
        "connection": "Reporting recently" if online else "Offline or stale; remote access cannot start yet",
        "observations": findings(endpoint),
        "note": "Last-reported evidence, not a confirmed diagnosis. An on-site visit may be needed for power, hardware or network faults.",
    }
