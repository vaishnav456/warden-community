"""Read-only BitLocker telemetry. Never read, decrypt or re-escrow a key."""
import math
import re
from datetime import datetime, timedelta, timezone
import db

_VOLUME_STATES = {"FullyDecrypted", "FullyEncrypted", "EncryptionInProgress",
                  "DecryptionInProgress", "EncryptionPaused", "DecryptionPaused"}
_PROTECTION_STATES = {"On", "Off", "Unknown"}
_PROTECTOR = re.compile(r"^[{]?[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}[}]?$")


def _time(value):
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return result.astimezone(timezone.utc) if result.tzinfo else None
    except ValueError:
        return None


def record_status(endpoint, body, now=None):
    if not isinstance(body, dict):
        return
    now = now or datetime.now(timezone.utc)
    captured = _time(body.get("collected_at"))
    if captured is None or not now - timedelta(minutes=2) <= captured <= now + timedelta(seconds=30):
        return
    volumes = body.get("volumes")
    if not isinstance(volumes, list) or len(volumes) > 32:
        return
    validated = []
    for volume in volumes:
        if not isinstance(volume, dict):
            continue
        mount = volume.get("mount_point")
        if not isinstance(mount, str) or not re.fullmatch(r"[A-Za-z]:", mount):
            continue
        state, protection = volume.get("volume_status"), volume.get("protection_status")
        if (not isinstance(state, str) or not isinstance(protection, str)
                or state not in _VOLUME_STATES or protection not in _PROTECTION_STATES):
            continue
        percentage = volume.get("encryption_percentage")
        if isinstance(percentage, bool) or not isinstance(percentage, (float, int)):
            continue
        if not math.isfinite(percentage) or not 0 <= percentage <= 100:
            continue
        ids = volume.get("protector_ids")
        if not isinstance(ids, list) or len(ids) > 32:
            continue
        ids = {value.strip("{}").lower() for value in ids
               if isinstance(value, str) and _PROTECTOR.fullmatch(value)}
        if ids:
            validated.append((mount.upper(), ids, state, protection, percentage))
    if not validated:
        return
    keys = db.get_endpoint_recovery_keys(endpoint["id"], current_only=True)
    # Only update previously escrowed, current protectors belonging to this
    # authenticated device and tenant. Unknown IDs must never create keys.
    for key in keys:
        if str(key.get("company_id")) != str(endpoint["company_id"]):
            continue
        if str(key.get("endpoint_id")) != str(endpoint["id"]) or not key.get("is_current"):
            continue
        for mount, ids, state, protection, percentage in validated:
            if (key.get("volume_mount") == mount and
                    str(key.get("protector_id") or "").strip("{}").lower() in ids):
                db.update_endpoint_recovery_status(endpoint["company_id"], endpoint["id"],
                    key["id"], state, protection, percentage, captured.isoformat())
                break


def display_status(endpoint):
    now = datetime.now(timezone.utc)
    rows = [row for row in db.get_endpoint_recovery_keys(endpoint["id"])
            if str(row.get("company_id")) == str(endpoint["company_id"])
            and str(row.get("endpoint_id")) == str(endpoint["id"])]
    for row in rows:
        reported = _time(row.get("last_reported_at"))
        row["status_fresh"] = bool(row.get("is_current") and endpoint.get("status") == "online"
            and reported and timedelta(seconds=-30) <= now - reported <= timedelta(minutes=2))
    return rows
