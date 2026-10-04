"""Endpoint-bound signed installation measurements, not hardware attestation."""
import base64
import hashlib
import json
import re
from services import signing
import db

_HASH = re.compile(r"^[0-9a-f]{64}$")
PURPOSE = "warden-agent-integrity-v2"
MEASUREMENT_FIELDS = ("purpose", "endpoint_id", "agent_version", "sha256",
                      "installation_id", "device_cert_sha256", "api_key_sha256")


def measurement(fields):
    core = {key: fields[key] for key in MEASUREMENT_FIELDS}
    return hashlib.sha256(json.dumps(core, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _baseline(endpoint, company):
    encrypted = endpoint.get("agent_integrity_baseline_encrypted")
    return db._endpoint_decrypt(company, "integrity-baseline", encrypted) if encrypted else None


def manifest(endpoint, challenge, version, observed):
    from services.heartbeat_crypto import _decode
    _decode(challenge, 32)
    if not isinstance(version, str) or len(version) > 32:
        raise ValueError("invalid version")
    if not isinstance(observed, str) or not _HASH.fullmatch(observed):
        raise ValueError("invalid hash")
    target = db.endpoint_target_platform(endpoint)
    rows = db._get(
        "build_requests?status=eq.completed"
        f"&target_platform=eq.{db._q(target)}"
        f"&agent_version=eq.{db._q(version)}"
        f"&sha256=eq.{db._q(observed)}&order=completed_at.desc&limit=1"
    )
    if not rows:
        return None
    company = db.get_company_by_id(endpoint["company_id"])
    baseline = _baseline(endpoint, company)
    if baseline and baseline.get("sha256") != observed:
        # An approved file elsewhere is not sufficient to change this endpoint's
        # baseline: require its most recent server-authorized update/rollback.
        jobs = db._get(
            f"jobs?endpoint_id=eq.{db._q(endpoint['id'])}"
            "&type=in.(UPDATE_AGENT,REINSTALL_AGENT)&status=in.(pending,running,completed)"
            "&order=created_at.desc&limit=1"
        )
        payload = db.decrypt_field(company, jobs[0].get("payload"), "job.payload") if jobs else {}
        if not isinstance(payload, dict) or payload.get("sha256") != observed or payload.get("version") != version:
            return None
    core = dict(purpose=PURPOSE, endpoint_id=str(endpoint["id"]), agent_version=version,
                sha256=observed, installation_id=str(endpoint.get("installation_id") or ""),
                device_cert_sha256=str(endpoint.get("client_cert_fingerprint") or "").lower().replace(":", ""),
                api_key_sha256=str(endpoint.get("api_key_hash") or ""))
    if not core["installation_id"] or not _HASH.fullmatch(core["device_cert_sha256"]) or not _HASH.fullmatch(core["api_key_sha256"]):
        raise ValueError("device identity unavailable")
    core["measurement_sha256"] = measurement(core)
    if baseline != core:
        old = endpoint.get("agent_integrity_baseline_encrypted")
        query = f"endpoints?id=eq.{db._q(endpoint['id'])}&agent_integrity_baseline_encrypted="
        query += "eq." + db._q(old) if old else "is.null"
        db._patch(query, {"agent_integrity_baseline_encrypted":
                         db._endpoint_encrypt(company, "integrity-baseline", core)})
        fresh = db.get_endpoint(endpoint["id"])
        persisted = _baseline(fresh, company)
        if persisted != core:
            return None
    proof = dict(**core, challenge=challenge)
    return dict(**proof, signature=base64.b64encode(signing.sign_canonical_payload(proof)).decode())


def record_report(endpoint, body):
    report = body.get("agent_integrity")
    if not isinstance(report, dict):
        return
    observed = report.get("sha256")
    status = report.get("status")
    reported_measurement = report.get("measurement_sha256")
    if not isinstance(observed, str) or not _HASH.fullmatch(observed):
        return
    if status not in {"verified", "mismatch", "unverified", "unavailable"}:
        return
    company = db.get_company_by_id(endpoint["company_id"])
    baseline = _baseline(endpoint, company)
    trusted = bool(baseline and baseline.get("sha256") == observed
                   and baseline.get("agent_version") == body.get("agent_version")
                   and baseline.get("measurement_sha256") == reported_measurement)
    saved = dict(sha256=observed, status="mismatch" if status=="mismatch" else "verified" if trusted else "unverified",
                 local_status=status, measurement_sha256=reported_measurement,checked_at=db._now_iso())
    db._patch(f"endpoints?id=eq.{db._q(endpoint['id'])}", {
        "agent_integrity_encrypted": db._endpoint_encrypt(company, "agent_integrity", saved),
    })
    if status == "mismatch" or not trusted:
        if not db.get_open_alert(endpoint["id"], "agent_integrity"):
            db.create_alert(endpoint["company_id"], endpoint.get("branch_id"), endpoint["id"],
                            "agent_integrity", "critical", "Warden agent integrity warning",
                            "Installed Warden agent does not match its approved installation measurement", saved)
    elif trusted:
        alert=db.get_open_alert(endpoint["id"],"agent_integrity")
        if alert:
            db.resolve_alert(alert["id"],None,"Agent again matches its server-approved installation measurement.")
