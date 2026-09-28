"""
Warden — Enrollment route
Public HTTPS endpoint. Agents POST here with a one-time token to get their API key.
No VPN/WireGuard involved — agent communicates directly over HTTPS.
"""
import hashlib
import logging
import secrets
import re
import pathlib
from datetime import datetime, timedelta, timezone
from flask import Blueprint, request, jsonify

import config
import db
from middleware.security import check_rate_limit

log = logging.getLogger("enroll")

bp = Blueprint("enroll", __name__)


_INVALID_HARDWARE_IDS = {
    "", "none", "unknown", "default string", "to be filled by o.e.m.",
    "00000000-0000-0000-0000-000000000000",
    "ffffffff-ffff-ffff-ffff-ffffffffffff",
}


def _normalise_hardware_id(value):
    value = str(value or "").strip().lower()
    return "" if value in _INVALID_HARDWARE_IDS else value


def _profile_rejection(profile, hostname, hardware_id, identity, claim):
    """Return a stable API error code when a device may not use a profile.

    Hostname and managed DNS suffix are desired state, not enrollment
    prerequisites. A fresh workgroup PC necessarily reports its old name and
    no organization suffix; the authenticated agent applies both later.
    """
    if not profile or not profile.get("is_active"):
        return "enrollment_profile_inactive"
    if profile.get("require_pre_registration"):
        if not claim or str(claim.get("profile_id")) != str(profile["id"]):
            return "device_not_pre_registered"
        if claim.get("status") == "released":
            return "device_claim_released"
    return None


def desired_managed_hostname(profile, claim, hardware_id, installation_id):
    """Resolve profile intent to a deterministic Windows computer name."""
    raw = str((claim or {}).get("expected_hostname") or profile.get("hostname_pattern") or "").strip()
    if not raw:
        return None
    seed = str(hardware_id or installation_id or raw).strip().lower()
    suffix = hashlib.sha256(seed.encode()).hexdigest()[:4].upper()
    candidate = raw.upper()
    if "*" in candidate or "?" in candidate:
        candidate = re.sub(r"[?*]+", suffix, candidate)
    candidate = re.sub(r"[^A-Z0-9-]", "-", candidate).strip("-")
    if len(candidate) > 15:
        prefix = candidate[:-len(suffix)] if candidate.endswith(suffix) else candidate
        if prefix.endswith("-"):
            prefix = prefix[:10].rstrip("-") + "-"
        else:
            prefix = prefix[:11].rstrip("-")
        candidate = prefix + suffix
    return candidate[:15] or None


def recovery_admin_payload(profile):
    """Return the safe, non-locking recovery-account job for a profile.

    Creating the break-glass administrator is a prerequisite for lockdown,
    not the lockdown itself. Existing interactive users remain enabled until
    a Warden identity has been provisioned and acknowledged by the endpoint.
    """
    if not profile or not profile.get("warden_only_mode"):
        return None
    lockdown = profile.get("lockdown_config") or {}
    username = str(lockdown.get("recovery_admin_username") or "").strip()
    password = str(lockdown.get("recovery_admin_password") or "")
    if not username or not password:
        return None
    return {
        "username": username,
        "password": password,
        "full_name": "Warden Recovery Administrator",
        "is_admin": True,
        "must_change_password": False,
        "purpose": "warden_recovery",
    }


def queue_managed_identity_recovery(company_id, branch_id, endpoint_id):
    """Restore device-only identity secrets after format/re-enrollment.

    The endpoint record and organization assignments survive a hardware-based
    reclaim, while the DPAPI file does not. Only existing active assignments
    are replayed, and the signed recovery flag never contains the reusable
    Warden password.
    """
    queued = 0
    for summary in db.get_warden_identities(company_id):
        assignment = next((item for item in summary.get("warden_identity_assignments", [])
                           if str(item.get("endpoint_id")) == str(endpoint_id)
                           and item.get("status") == "active"), None)
        if not assignment or not summary.get("is_enabled", True):
            continue
        identity = db.get_warden_identity(summary["id"], company_id)
        if not identity:
            continue
        payload = {
            "username": identity["username"], "credential_mode": "managed_shadow_v1",
            "full_name": identity.get("display_name") or "", "is_admin": bool(identity["is_admin"]),
            "must_change_password": False, "password_version": identity["password_version"],
            "profile_photo": identity.get("profile_photo") or "", "recover_existing": True,
        }
        job = db.create_job(company_id, branch_id, endpoint_id,
                            "PROVISION_WARDEN_IDENTITY", payload, None)
        if not job:
            continue
        db.upsert_warden_identity_assignment(
            identity["id"], endpoint_id, "pending", identity["password_version"], job["id"],
        )
        queued += 1
    return queued

ALLOWED_OPERATIONS = {
    "INSTALL_APP",
    "UNINSTALL_APP",
    "CREATE_USER",
    "PROVISION_WARDEN_IDENTITY",
    "WARDEN_ONLY_LOCKDOWN",
    "DELETE_USER",
    "RESET_PASSWORD",
    "DISABLE_USER",
    "ENABLE_USER",
    "GRANT_ELEVATION",
    "REVOKE_ELEVATION",
    "RUN_CMD",
    "REBOOT",
    "SHUTDOWN",
    "COLLECT_SYSINFO",
    "COLLECT_SOFTWARE",
    "UPDATE_AGENT",
    "REINSTALL_AGENT",
    "SET_PERIPHERAL_POLICY",
    "SETUP_REMOTE_ACCESS",
    "REMOVE_REMOTE_ACCESS",
    "COMPLIANCE_SCAN",
    "FILE_PUSH",
    "FILE_PULL",
    "LIST_DIRECTORY",
    "GET_EVENT_LOGS",
    "WINDOWS_UPDATE",
    "UNINSTALL_AGENT",
    "PUSH_LOCAL_POLICY",
    "CHECK_POLICY_DRIFT",
    "COLLECT_USERS",
    "ROTATE_TLS_PINS",
    "CONFIGURE_DEVICE_IDENTITY",
    "CAPTURE_PACKETS",
    "COLLECT_NETWORK_FLOWS",
    "SYNC_WARDEN_HOME",
    "APPLY_DEVICE_EXPERIENCE",
    "ENABLE_BITLOCKER",
    "ROTATE_BITLOCKER_RECOVERY",
}


@bp.route("/enroll", methods=["POST"])
def enroll():
    """
    Agent enrollment endpoint.
    Body: {
        "token":      "<one-time enrollment token>",
        "hostname":   "PC-NAME",
        "hardware_id": "...",
        "os_info":    {...}
    }
    Response: {
        "api_key":               "<per-endpoint API key>",
        "endpoint_id":           "<uuid>",
        "server_ed25519_pubkey": "<base64>",
        "company_id":            "<uuid>",
        "branch_id":             "<uuid|null>",
        "allowed_operations":    [...]
    }
    """
    if not check_rate_limit("enroll", 5, fail_closed=True):
        return jsonify({"error": "rate_limited"}), 429

    body = request.get_json(silent=True) or {}
    token = body.get("token", "").strip()
    hostname = body.get("hostname", "").strip()
    hardware_id = _normalise_hardware_id(body.get("hardware_id"))
    device_identity = body.get("device_identity") or {}
    if not isinstance(device_identity, dict):
        return jsonify({"error": "invalid_device_identity"}), 400
    # The top-level field is retained for compatibility with old agents.
    # The canonical value is duplicated into the structured identity record.
    device_identity["hardware_id"] = hardware_id
    agent_version = body.get("agent_version", "").strip()
    os_info = body.get("os_info") or {}
    csr_pem = body.get("csr_pem", "").strip()
    installation_id = body.get("installation_id", "").strip().lower()

    if not all([token, hostname, installation_id]):
        return jsonify({"error": "missing_fields"}), 400

    if not re.fullmatch(r"[0-9a-f]{32}", installation_id):
        return jsonify({"error": "invalid_installation_id"}), 400

    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]?$', hostname):
        return jsonify({"error": "invalid_hostname"}), 400

    # Validate requirements that don't consume shared state before claiming
    # a token use. Previously a missing CSR burned a one-time token even
    # though no endpoint could be created.
    if config.DEVICE_CERTIFICATES_ENABLED and not csr_pem:
        return jsonify({"error": "client_cert_required"}), 400

    # Verify token
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    token_rec = db.get_enrollment_token_by_hash(token_hash, include_inactive=True)
    if not token_rec:
        return jsonify({"error": "invalid_token"}), 401

    profile = None
    claim = None
    if token_rec.get("profile_id"):
        profile = db.get_enrollment_profile(token_rec["profile_id"])
        claim = db.get_enrollment_device_claim_for_identity(
            token_rec["company_id"],
            hardware_id=hardware_id,
            serial_number=device_identity.get("serial_number"),
            entra_device_id=device_identity.get("entra_device_id"),
        )
        rejection = _profile_rejection(profile, hostname, hardware_id, device_identity, claim)
        if rejection:
            try:
                if not db.get_open_enrollment_alert(
                    token_rec["company_id"], token_rec.get("profile_id"), hostname,
                ):
                    db.create_alert(
                        company_id=token_rec["company_id"],
                        branch_id=token_rec.get("branch_id"), endpoint_id=None,
                        alert_type="enrollment_rejected", severity="warning",
                        title="Device enrollment was rejected",
                        message=(
                            f"{hostname or 'Unknown device'} could not enroll with "
                            f"profile {(profile or {}).get('name') or 'Unknown profile'}: "
                            f"{rejection.replace('_', ' ')}."
                        ),
                        detail={
                            "hostname": hostname,
                            "profile_id": token_rec.get("profile_id"),
                            "profile_name": (profile or {}).get("name"),
                            "reason": rejection,
                            "hardware_id": hardware_id,
                        },
                    )
            except Exception:
                log.exception("Could not create enrollment rejection alert")
            return jsonify({"error": rejection}), 403

    recovery_endpoint = db.get_endpoint_by_installation_id(
        token_rec["company_id"], installation_id,
    )
    recovered_by_hardware = False
    if (
        not recovery_endpoint and hardware_id and profile
        and profile.get("reclaim_existing", True)
    ):
        recovery_endpoint = db.get_endpoint_by_hardware_id(
            token_rec["company_id"], hardware_id,
        )
        recovered_by_hardware = bool(recovery_endpoint)

    enrolled_recently = False
    if recovery_endpoint and recovery_endpoint.get("enrolled_at"):
        try:
            enrolled_at = datetime.fromisoformat(
                str(recovery_endpoint["enrolled_at"]).replace("Z", "+00:00")
            )
            enrolled_recently = datetime.now(timezone.utc) - enrolled_at <= timedelta(hours=1)
        except (TypeError, ValueError):
            enrolled_recently = False
    recovering = bool(
        recovery_endpoint
        and not recovered_by_hardware
        and enrolled_recently
        and str(recovery_endpoint.get("enrollment_token_id") or "") == str(token_rec["id"])
        and (
            token_rec.get("is_active")
            or str(token_rec.get("used_by_endpoint_id") or "") == str(recovery_endpoint["id"])
        )
    )
    reactivating = bool(recovery_endpoint and not recovery_endpoint.get("is_active", True))
    reenrolling = bool(recovery_endpoint and not recovering)

    if not token_rec.get("is_active") and not recovering:
        return jsonify({"error": "invalid_token"}), 401

    # Capacity is checked before claiming the one-time token, so a rejected
    # enrollment does not consume it. Existing agents are never disabled by
    # a later downgrade; this gate applies only to new enrollment.
    from services.entitlements import check_capacity
    capacity = check_capacity(token_rec["company_id"], "endpoints")
    consumes_new_seat = not recovery_endpoint or reactivating
    if not recovering and consumes_new_seat and not capacity.allowed:
        return jsonify({
            "error": capacity.code, "message": capacity.message,
            "used": capacity.used, "limit": capacity.limit,
        }), 403

    # Atomically claim the token before doing anything else — two
    # concurrent requests with the same token could otherwise both pass
    # the read-only lookup above and each create a distinct endpoint from
    # what's meant to be a single-use token. Whichever request loses this
    # CAS gets treated exactly like an invalid/already-used token.
    if not recovering and not db.claim_enrollment_token(token_rec["id"]):
        return jsonify({"error": "invalid_token"}), 401

    company_id = token_rec["company_id"]
    branch_id = token_rec["branch_id"]

    # The agent generated its device key locally and submitted only a CSR;
    # the private key is never transmitted. Issuance happens after endpoint
    # creation so the certificate can contain the canonical endpoint UUID,
    # but before the enrollment token is burned so a failed issuance remains
    # recoverable on the next enrollment attempt.
    client_cert_pem = fingerprint = cf_cert_id = None

    # Generate per-endpoint API key
    api_key = secrets.token_urlsafe(48)
    api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()

    # Create endpoint record
    try:
        if recovering:
            endpoint = db.recover_endpoint_enrollment(
                recovery_endpoint["id"], hostname, api_key_hash,
            )
        elif reenrolling:
            endpoint = db.reenroll_endpoint(
                recovery_endpoint["id"], branch_id, hostname, api_key_hash,
                hardware_id, token_rec["id"],
                enrollment_profile_id=profile["id"] if profile else None,
                device_identity=device_identity,
                installation_id=installation_id if recovered_by_hardware else None,
            )
        else:
            endpoint = db.create_endpoint(
                company_id=company_id,
                branch_id=branch_id,
                hostname=hostname,
                api_key_hash=api_key_hash,
                hardware_id=hardware_id,
                installation_id=installation_id,
                enrollment_token_id=token_rec["id"],
                enrollment_profile_id=profile["id"] if profile else None,
                device_identity=device_identity,
            )
    except Exception:
        if not recovering:
            try:
                db.release_enrollment_token(token_rec["id"])
            except Exception:
                log.exception("Could not release enrollment-token claim after endpoint failure")
        raise
    if not endpoint:
        if not recovering:
            try:
                db.release_enrollment_token(token_rec["id"])
            except Exception:
                log.exception("Could not release enrollment-token claim after endpoint failure")
        return jsonify({"error": "enrollment_failed"}), 500

    # Bind the certificate to the canonical endpoint UUID, which is only
    # known after creation/recovery. If issuance fails, release the token so
    # the same installation can safely retry its recoverable enrollment.
    if config.DEVICE_CERTIFICATES_ENABLED:
        try:
            from services.agent_ca import sign_agent_csr
            client_cert_pem, fingerprint, cf_cert_id = sign_agent_csr(
                csr_pem, str(endpoint["id"]), company_id=company_id,
            )
        except Exception as exc:
            log.error("Client-certificate issuance failed for %s during enrollment: %s", hostname, exc)
            if not recovering:
                try:
                    db.release_enrollment_token(token_rec["id"])
                except Exception:
                    log.exception("Could not release enrollment-token claim after certificate failure")
            return jsonify({"error": "client_cert_issuance_failed"}), 502

    # Burn the enrollment token
    if not recovering:
        db.burn_enrollment_token(token_rec["id"], endpoint["id"])
    if claim:
        db.mark_enrollment_device_claim_enrolled(
            claim["id"], endpoint["id"], device_identity,
        )

    # Store initial OS info
    if os_info:
        db.update_endpoint_sysinfo(endpoint["id"], os_info)

    if fingerprint:
        old_cert_id = recovery_endpoint.get("cloudflare_cert_id") if recovery_endpoint else None
        db.set_endpoint_client_cert(endpoint["id"], fingerprint, cf_cert_id)
        if old_cert_id and old_cert_id != cf_cert_id:
            try:
                from services.agent_ca import revoke_agent_cert
                revoke_agent_cert(old_cert_id)
            except Exception:
                # The newly issued credential is already active and stored;
                # retain service availability while surfacing cleanup loudly.
                log.exception("Could not revoke superseded client certificate %s", old_cert_id)

    db.log_endpoint_event(endpoint["id"], "enrolled", {
        "hostname": hostname,
        "hardware_id": hardware_id,
        "agent_version": agent_version,
        "reactivated": reactivating,
        "reenrolled": reenrolling,
        "recovered_by_hardware": recovered_by_hardware,
        "enrollment_profile_id": profile["id"] if profile else None,
        "deployment_method": profile.get("deployment_method") if profile else "legacy",
    })
    db.audit(company_id, None, "endpoint_enrolled", {
        "endpoint_id": endpoint["id"],
        "hostname": hostname,
    }, branch_id=branch_id, endpoint_id=endpoint["id"])

    # Seed the endpoint detail page immediately. These non-privileged,
    # read-only inventory jobs are returned by the agent's first heartbeat
    # moments after enrollment, once authenticated communications are fully
    # initialized. Keeping them as ordinary signed jobs preserves the same
    # audit/signature/retry path as a later manual collection.
    initial_scans = () if recovering else (
        ("COLLECT_SYSINFO", {}),
        ("COLLECT_SOFTWARE", {}),
        ("COLLECT_USERS", {}),
    )
    for operation, payload in initial_scans:
        try:
            db.create_job(
                company_id=company_id,
                branch_id=branch_id,
                endpoint_id=endpoint["id"],
                job_type=operation,
                payload=payload,
                created_by=None,
            )
        except Exception:
            # Enrollment itself must remain successful if an optional
            # inventory job cannot be queued; the endpoint can be rescanned.
            log.exception(
                "Could not queue initial %s scan for endpoint %s",
                operation, endpoint["id"],
            )

    if reenrolling or reactivating:
        try:
            recovered_identities = queue_managed_identity_recovery(
                company_id, branch_id, endpoint["id"],
            )
            if recovered_identities:
                db.log_endpoint_event(endpoint["id"], "managed_identities_recovery_queued", {
                    "count": recovered_identities,
                })
        except Exception:
            # Enrollment remains usable with the recovery administrator. The
            # administrator can retry from Directory → Repair if this optional replay
            # is interrupted.
            log.exception("Could not queue managed identity recovery for endpoint %s", endpoint["id"])

    # Stage the encrypted break-glass administrator immediately for a
    # Warden-only profile. This does not disable or modify any existing user.
    # Full lockdown remains chained to a successfully provisioned Warden
    # identity, so a partial enrollment can never lock everybody out.
    recovery_payload = recovery_admin_payload(profile)
    if recovery_payload and not recovering:
        try:
            recovery_job = db.create_job(
                company_id, branch_id, endpoint["id"], "CREATE_USER",
                recovery_payload, created_by=None,
            )
            db.log_endpoint_event(endpoint["id"], "recovery_admin_queued", {
                "job_id": str((recovery_job or {}).get("id") or ""),
                "username": recovery_payload["username"],
            })
        except Exception:
            # Enrollment remains available and existing users are untouched;
            # the failed prerequisite is visible in server logs and can be
            # retried from the endpoint job UI.
            log.exception("Could not queue recovery administrator for endpoint %s", endpoint["id"])

    # A zero-touch profile is a complete desired-state assignment, not only
    # an enrollment gate. Queue its reviewed policy, required applications,
    # and optional update installation immediately after the endpoint has its
    # own credentials. Re-enrollment after a format replays desired state;
    # a transient recovery of the same installation does not duplicate it.
    preparation = (profile or {}).get("post_enrollment") or {}
    if profile and not recovering:
        policy_id = preparation.get("policy_template_id")
        if policy_id:
            template = db.get_policy_template(policy_id)
            if template and str(template.get("company_id")) == str(company_id):
                try:
                    db.create_job(company_id, branch_id, endpoint["id"], "PUSH_LOCAL_POLICY", {
                        "settings": template.get("settings") or {}, "policy_version": 1,
                    }, None)
                except Exception:
                    log.exception("Could not queue zero-touch policy for endpoint %s", endpoint["id"])
        for app_id in (preparation.get("required_app_ids") or [])[:50]:
            app = db.get_app(app_id)
            if not app or (app.get("company_id") and str(app.get("company_id")) != str(company_id)):
                continue
            ext = pathlib.Path(app.get("file_path") or "").suffix.lower()
            if ext not in {".exe", ".msi"}:
                continue
            try:
                db.create_job(company_id, branch_id, endpoint["id"], "INSTALL_APP", {
                    "app_url": f"{config.SERVER_URL}/api/agent/apps/{app_id}/download",
                    "sha256": app.get("sha256"), "ext": ext,
                    "install_args": app.get("install_args") or "",
                }, None)
            except Exception:
                log.exception("Could not queue zero-touch app %s for endpoint %s", app_id, endpoint["id"])
        if preparation.get("install_updates"):
            try:
                db.create_job(company_id, branch_id, endpoint["id"], "WINDOWS_UPDATE", {"action": "install"}, None)
            except Exception:
                log.exception("Could not queue zero-touch updates for endpoint %s", endpoint["id"])

    from services.signing import get_server_pubkey_b64
    return jsonify({
        "api_key":               api_key,
        "endpoint_id":           str(endpoint["id"]),
        "server_ed25519_pubkey": get_server_pubkey_b64(),
        "company_id":            str(company_id),
        "branch_id":             str(branch_id) if branch_id else None,
        "allowed_operations":    sorted(ALLOWED_OPERATIONS),
        "client_cert_pem":       client_cert_pem,
    })
