"""
Warden — Agent API routes
No VPN — agents connect directly over pinned HTTPS (see agent/comms.py).
Authentication: X-Agent-Key header per endpoint, plus Ed25519-signed job
envelopes (server/services/signing.py).
"""
import base64
import io
import ipaddress
import json
import math
import re
import zipfile
from datetime import datetime, timedelta, timezone
from flask import Blueprint, request, jsonify, g, send_file, abort, current_app

import config
import db
from middleware.auth import agent_auth_required
from middleware.security import check_rate_limit, get_client_ip
from services.signing import sign_job
from services.agent_updates import AgentBuildUnavailable, as_download, build_for_endpoint
from services.experience_assets import is_available
from services.home_sync import (
    endpoint_storage_principal as _endpoint_storage_principal,
    queue_periodic_home_sync,
    resolve_home_access_context,
)

bp = Blueprint("agent_api", __name__)
_IDENTITY_LOGIN_RE = re.compile(
    r"^(?:[A-Za-z0-9._-]{1,20}|[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+)$"
)


@bp.post("/api/agent/certificate/renew")
@agent_auth_required
def renew_device_certificate():
    """Rotate a short-lived endpoint certificate without replacing its API key."""
    if not config.DEVICE_CERTIFICATES_ENABLED:
        return jsonify({"error": "device_certificates_disabled"}), 404
    if not check_rate_limit(f"device-cert:{g.endpoint['id']}", 4):
        return jsonify({"error": "rate_limited"}), 429
    body = request.get_json(silent=True) or {}
    csr_pem = str(body.get("csr_pem") or "").strip()
    if not csr_pem:
        return jsonify({"error": "client_cert_required"}), 400
    try:
        from services.agent_ca import ca_bundle_pem, sign_agent_csr
        cert_pem, fingerprint, reference = sign_agent_csr(
            csr_pem, str(g.endpoint["id"]), company_id=str(g.endpoint["company_id"]),
        )
    except (ValueError, RuntimeError) as exc:
        current_app.logger.warning("Endpoint certificate renewal rejected for %s: %s", g.endpoint["id"], exc)
        return jsonify({"error": "client_cert_issuance_failed"}), 400
    db.set_endpoint_client_cert(g.endpoint["id"], fingerprint, reference)
    db.log_endpoint_event(g.endpoint["id"], "device_certificate_renewed", {
        "fingerprint": fingerprint, "issuer": "warden-private-ca",
    })
    return jsonify({"client_cert_pem": cert_pem, "device_ca_pem": ca_bundle_pem()})


@bp.route("/api/agent/branding/<asset_id>")
@agent_auth_required
def download_branding_asset(asset_id):
    """Serve organization-owned visual assets only to enrolled Agents."""
    if not re.fullmatch(r"[0-9a-f]{64}", asset_id):
        abort(404)
    tenant_dir = config.UPLOAD_DIR / "branding" / str(g.endpoint["company_id"])
    for extension, mimetype in ((".png", "image/png"), (".jpg", "image/jpeg")):
        path = tenant_dir / f"{asset_id}{extension}"
        if path.is_file():
            if not is_available(path):
                abort(410)
            response = send_file(path, mimetype=mimetype, conditional=False)
            response.headers["Cache-Control"] = "private, no-store"
            response.headers["X-Content-Type-Options"] = "nosniff"
            return response
    abort(404)


def _identity_login_response(outcome, status, message="Sign-in failed", identity=None):
    db.log_warden_identity_login(
        g.endpoint["company_id"], g.endpoint["id"],
        str((request.get_json(silent=True) or {}).get("username") or "")[:254],
        outcome, identity_id=identity.get("id") if identity else None,
        reason=message, source_ip=get_client_ip(),
    )
    response = jsonify({"ok": False, "error": outcome, "message": message})
    response.headers["Cache-Control"] = "no-store"
    return response, status


@bp.route("/api/agent/identity/authenticate", methods=["POST"])
@agent_auth_required
def authenticate_warden_identity():
    """Verify a Warden password for this endpoint without exposing its hash.

    Used by the agent's local sign-in broker.  A successful response is not a
    Windows credential: the broker uses its device-only DPAPI secret when it
    asks LSA to log on the provisioned shadow account.
    """
    body = request.get_json(silent=True) or {}
    username = str(body.get("username") or "").strip()
    password = body.get("password")
    if len(username) > 254 or not _IDENTITY_LOGIN_RE.fullmatch(username) or not isinstance(password, str) or len(password) > 128:
        return _identity_login_response("invalid_credentials", 401)
    # Scope the limiter to the authenticated device and requested identity so
    # one noisy endpoint cannot prevent every endpoint behind the same NAT
    # from signing in.  The database lockout below remains the durable guard.
    if not check_rate_limit(f"identity:{g.endpoint['id']}:{username.casefold()}", 10):
        return _identity_login_response("locked", 429, "Too many sign-in attempts. Try again shortly.")
    identity = db.get_warden_identity_for_login(
        g.endpoint["company_id"], g.endpoint["id"], username,
    )
    if not identity:
        return _identity_login_response("not_assigned", 401)
    assignments = identity.get("warden_identity_assignments") or []
    if not assignments or assignments[0].get("status") != "active":
        return _identity_login_response("not_assigned", 403, "Identity is not active on this endpoint", identity)
    if not identity.get("is_enabled", True):
        return _identity_login_response("disabled", 403, "Identity is disabled", identity)
    if identity.get("password_setup_required"):
        return _identity_login_response(
            "password_setup_required", 403,
            "Complete the one-time Warden password setup before signing in", identity,
        )
    if identity.get("locked_until"):
        try:
            locked = datetime.fromisoformat(identity["locked_until"].replace("Z", "+00:00"))
            if locked > datetime.now(timezone.utc):
                return _identity_login_response("locked", 423, "Identity is temporarily locked", identity)
        except (TypeError, ValueError):
            return _identity_login_response("locked", 423, "Identity lock state is invalid", identity)

    policy = identity.get("conditional_access") or {}
    if not isinstance(policy, dict):
        return _identity_login_response("policy_denied", 403, "Conditional access policy is invalid", identity)
    start_hour = policy.get("utc_start_hour")
    end_hour = policy.get("utc_end_hour")
    if isinstance(start_hour, int) and isinstance(end_hour, int):
        hour = datetime.now(timezone.utc).hour
        allowed = (start_hour <= hour < end_hour) if start_hour < end_hour else (hour >= start_hour or hour < end_hour)
        if not allowed:
            return _identity_login_response("policy_denied", 403, "Sign-in is outside allowed hours", identity)
    if policy.get("require_compliant") is True:
        compliance = db.get_compliance_result(g.endpoint["id"])
        if not compliance or compliance.get("overall_status") != "compliant":
            return _identity_login_response("policy_denied", 403, "Endpoint is not compliant", identity)

    from routes.auth import _check_password
    if not _check_password(password, identity["password_hash"]):
        db.record_warden_login_failure(identity["id"])
        return _identity_login_response("invalid_credentials", 401, identity=identity)

    db.record_warden_login_success(identity["id"])
    offline_hours = int(identity.get("offline_access_hours") or 0)
    expires = datetime.now(timezone.utc) + timedelta(hours=offline_hours)
    db.log_warden_identity_login(
        g.endpoint["company_id"], g.endpoint["id"], identity["username"], "success",
        identity_id=identity["id"], source_ip=get_client_ip(),
        offline_grant_hours=offline_hours,
    )
    from services.home_grants import home_config_for
    try:
        home = home_config_for(
            g.endpoint, identity,
            db.get_home_spaces(g.endpoint["company_id"]),
            db.get_home_assignments(g.endpoint["company_id"]),
        )
    except Exception:
        # Home storage is an optional post-login service. A temporary storage
        # configuration outage must not prevent the identity from signing in.
        current_app.logger.exception("Could not issue Warden Home grants")
        home = []
    if home:
        db.log_home_access(
            g.endpoint["company_id"], g.endpoint["id"], identity["id"],
            None, None, "grants_issued", {"space_count": len(home)},
        )
    response = jsonify({
        "ok": True, "identity_id": identity["id"],
        "username": identity["username"], "display_name": identity.get("display_name") or "",
        "session_version": identity["session_version"],
        "password_version": identity["password_version"],
        "offline_valid_until": expires.isoformat().replace("+00:00", "Z") if offline_hours else None,
        "home": home,
    })
    response.headers["Cache-Control"] = "no-store"
    return response


@bp.post("/api/agent/home-config")
@agent_auth_required
def refreshed_home_config():
    """Issue fresh, endpoint-bound P2P grants for an assigned identity.

    Jobs carry only the username, never expiring grants. This makes failover
    safe for endpoints that reconnect after a topology change.
    """
    username = str((request.get_json(silent=True) or {}).get("username") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,20}", username):
        abort(400)
    identity, home_assignments, managed_identity = _home_access_context(username)
    if not identity:
        abort(404)
    from services.home_grants import home_config_for
    home = home_config_for(
        g.endpoint, identity,
        db.get_home_spaces(g.endpoint["company_id"]),
        home_assignments,
    )
    if home:
        db.log_home_access(
            g.endpoint["company_id"], g.endpoint["id"],
            identity["id"] if managed_identity else None,
            None, None, "grants_issued", {
                "space_count": len(home),
                "principal": "identity" if managed_identity else "endpoint",
            },
        )
    response = jsonify({"ok": True, "home": home})
    response.headers["Cache-Control"] = "no-store"
    return response


def _valid_webrtc_offer(value):
    return (isinstance(value, str) and 32 <= len(value) <= 131072
            and value.startswith("v=0") and "a=fingerprint:" in value
            and "a=ice-ufrag:" in value and "a=setup:actpass" in value)


def _home_access_context(username):
    """Resolve either a managed identity or a direct endpoint share grant."""
    return resolve_home_access_context(g.endpoint, username)


@bp.post("/api/agent/home-p2p/offer")
@agent_auth_required
def create_home_p2p_offer():
    body = request.get_json(silent=True) or {}
    username = str(body.get("username") or "").strip()
    node_id = str(body.get("node_id") or "")
    offer_sdp = body.get("offer_sdp")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,20}", username) or not _valid_webrtc_offer(offer_sdp):
        abort(400)
    if not check_rate_limit(f"home-p2p:{g.endpoint['id']}", 20):
        return jsonify({"error": "rate_limited"}), 429
    identity, home_assignments, managed_identity = _home_access_context(username)
    if not identity:
        abort(404)
    from services.home_grants import home_config_for
    home = home_config_for(
        g.endpoint, identity, db.get_home_spaces(g.endpoint["company_id"]),
        home_assignments,
    )
    allowed = any(
        str(node.get("id")) == node_id and node.get("connection_mode") == "p2p"
        for space in home for node in space.get("nodes", [])
    )
    if not allowed:
        abort(403)
    session = db.create_home_p2p_session(
        g.endpoint["company_id"], g.endpoint["id"], node_id, offer_sdp,
    )
    if not session:
        abort(503)
    db.log_home_access(g.endpoint["company_id"], g.endpoint["id"],
                       identity["id"] if managed_identity else None,
                       None, node_id, "p2p_offered", {"direct_only": True})
    response = jsonify({"ok": True, "session_id": session["id"]})
    response.headers["Cache-Control"] = "no-store"
    return response


@bp.post("/api/agent/home-p2p/answer")
@agent_auth_required
def get_home_p2p_answer():
    session_id = str((request.get_json(silent=True) or {}).get("session_id") or "")
    session = db.get_home_p2p_session(session_id, endpoint_id=g.endpoint["id"])
    if not session or str(session.get("company_id")) != str(g.endpoint["company_id"]):
        abort(404)
    response = jsonify({
        "status": session.get("status"), "answer_sdp": session.get("answer_sdp"),
        "error": session.get("error_message"),
    })
    response.headers["Cache-Control"] = "no-store"
    return response


@bp.before_request
def _require_agent_key_present():
    """Reject requests that have no X-Agent-Key header at all (fast pre-check)."""
    if not request.headers.get("X-Agent-Key"):
        from flask import abort
        abort(403)
    # The global 500 MiB ceiling is required for administrator app uploads,
    # not agent JSON. Bound authenticated agent POSTs before Flask allocates
    # or parses a pathological body.
    if request.method == "POST" and (request.content_length or 0) > 20 * 1024 * 1024:
        abort(413)


def _metric(value, minimum=0.0, maximum=None):
    if value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(number) or number < minimum:
        return None
    if maximum is not None:
        number = min(number, maximum)
    return number


def _integer_metric(value, minimum=0, maximum=None):
    """Validate a metric destined for an integer database column."""
    number = _metric(value, minimum=minimum, maximum=maximum)
    return int(number) if number is not None else None


def _record_policy_values(endpoint, values, source):
    """Store a bounded, catalog-only policy snapshot and raise drift once."""
    if not isinstance(values, dict):
        return
    import policy_settings
    known = {
        key: value for key, value in values.items()
        if isinstance(key, str) and key in policy_settings.POLICY_SETTINGS
    }
    drifted = db.record_policy_drift_check(endpoint["id"], known)
    db.log_endpoint_event(endpoint["id"], "policy_inventory_reported", {
        "source": source, "setting_count": len(known),
    })
    if drifted:
        db.create_alert(
            company_id=endpoint["company_id"],
            branch_id=endpoint["branch_id"],
            endpoint_id=endpoint["id"],
            alert_type="policy_drift",
            severity="warning",
            title=f"Policy drift detected: {len(drifted)} setting(s) changed outside Warden",
            message=", ".join(drifted),
            detail={"drifted_settings": drifted},
        )


def _record_hostname_change(endpoint, reported_hostname):
    """Reconcile a Windows rename for the already-authenticated endpoint.

    Endpoint identity remains the installation ID/API credential; hostname is
    only a mutable display attribute. Invalid or unchanged values are ignored.
    """
    if not isinstance(reported_hostname, str):
        return False
    hostname = reported_hostname.strip()
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]?", hostname):
        return False
    old_hostname = str(endpoint.get("hostname") or "")
    if hostname.casefold() == old_hostname.casefold():
        return False
    db.update_endpoint_hostname(endpoint["id"], hostname)
    db.log_endpoint_event(endpoint["id"], "hostname_changed", {
        "old_hostname": old_hostname,
        "new_hostname": hostname,
    })
    return True


def _queue_profile_device_identity(endpoint, body, capabilities, platform):
    """Queue zero-touch naming only after a capable agent is authenticated."""
    if (
        platform != "windows"
        or "CONFIGURE_DEVICE_IDENTITY" not in capabilities
        or not endpoint.get("enrollment_profile_id")
        or db.has_job(endpoint["id"], "CONFIGURE_DEVICE_IDENTITY")
    ):
        return None
    profile = db.get_enrollment_profile(endpoint["enrollment_profile_id"])
    if not profile or not profile.get("is_active"):
        return None
    from routes.enroll import desired_managed_hostname
    identity = endpoint.get("device_identity") or {}
    claim = db.get_enrollment_device_claim_for_identity(
        endpoint["company_id"],
        hardware_id=endpoint.get("hardware_id"),
        serial_number=identity.get("serial_number"),
        entra_device_id=identity.get("entra_device_id"),
    )
    desired_hostname = desired_managed_hostname(
        profile, claim, endpoint.get("hardware_id"), endpoint.get("installation_id"),
    )
    desired_domain = str(profile.get("domain_suffix") or "").strip().lower().lstrip(".")
    current_hostname = str(body.get("hostname") or endpoint.get("hostname") or "")
    current_domain = str(body.get("managed_domain_suffix") or "").strip().lower().lstrip(".")
    if (
        (not desired_hostname or current_hostname.casefold() == desired_hostname.casefold())
        and (not desired_domain or current_domain == desired_domain)
    ):
        return None
    job = db.create_system_job_once(
        endpoint["company_id"], endpoint.get("branch_id"), endpoint["id"],
        "CONFIGURE_DEVICE_IDENTITY", {
            "hostname": desired_hostname or "",
            "domain_suffix": desired_domain,
            "restart": True,
        },
    )
    if job:
        db.log_endpoint_event(endpoint["id"], "device_identity_configuration_queued", {
            "hostname": desired_hostname,
            "domain_suffix": desired_domain,
            "profile_id": profile["id"],
        })
    return job


@bp.route("/api/agent/heartbeat", methods=["POST"])
@agent_auth_required
def heartbeat():
    """
    Agent posts heartbeat every 30s with live metrics.
    Body: {
        "cpu_pct": 12.3,
        "ram_used_pct": 45.6,
        "disk_free_gb": 120.5,
        "agent_version": "1.0.0"
    }
    Response: {
        "pending_jobs": [...],  <- jobs ready for dispatch
        "commands": [...]       <- signed command envelopes
    }
    """
    body = request.get_json(silent=True) or {}
    endpoint = g.endpoint

    reported_platform = str(body.get("platform") or "").strip().lower()
    if reported_platform not in {"windows", "linux", "darwin"}:
        known_os = str(body.get("os_name") or endpoint.get("os_name") or "").lower()
        if "windows" in known_os:
            reported_platform = "windows"
        elif "mac" in known_os or "darwin" in known_os:
            reported_platform = "darwin"
        elif known_os:
            reported_platform = "linux"
        else:
            reported_platform = None

    _record_hostname_change(endpoint, body.get("hostname"))
    cpu_pct = _metric(body.get("cpu_pct"), maximum=100.0)
    ram_used_pct = _metric(body.get("ram_used_pct"), maximum=100.0)
    disk_free_gb = _metric(body.get("disk_free_gb"))

    client_ip = get_client_ip()
    previous_ip = endpoint.get("last_seen_ip")
    if previous_ip and client_ip and previous_ip != client_ip:
        # Always logged (cheap, useful history) — alert_engine.py decides
        # whether the recent *frequency* of these across a time window is
        # actually alert-worthy. A single change is normal (laptops move
        # networks, DHCP renews); several distinct IPs in a short window
        # is the actual anomaly signal.
        db.log_endpoint_event(endpoint["id"], "ip_changed", {
            "old_ip": previous_ip, "new_ip": client_ip,
        })

    has_interactive_user = "interactive_user" in body
    interactive_user = str(body.get("interactive_user") or "").strip() if has_interactive_user else None
    valid_interactive_user = (
        has_interactive_user and len(interactive_user) <= 512
        and not any(ord(char) < 32 for char in interactive_user)
    )

    local_ip = None
    try:
        reported_local_ip = ipaddress.ip_address(str(body.get("local_ip") or "").strip())
        if reported_local_ip.version == 4 and not (
            reported_local_ip.is_loopback or reported_local_ip.is_unspecified
            or reported_local_ip.is_link_local
        ):
            local_ip = str(reported_local_ip)
    except ValueError:
        pass

    topology_telemetry = body.get("topology_telemetry")
    if isinstance(topology_telemetry, dict):
        topology_telemetry = {
            key: topology_telemetry[key] for key in (
                "captured_at", "collector", "interfaces", "adapters", "neighbors",
                "gateways", "lldp_cdp", "discovery_protocols",
            ) if key in topology_telemetry
        }
        for key, limit in (("interfaces", 32), ("adapters", 32), ("neighbors", 256), ("gateways", 16)):
            if key in topology_telemetry and isinstance(topology_telemetry[key], list):
                topology_telemetry[key] = topology_telemetry[key][:limit]
        try:
            if len(json.dumps(topology_telemetry, separators=(",", ":"))) > 262144:
                topology_telemetry = None
        except (TypeError, ValueError):
            topology_telemetry = None
    else:
        topology_telemetry = None

    db.update_endpoint_heartbeat(
        endpoint_id=endpoint["id"],
        cpu_pct=cpu_pct,
        ram_used_pct=ram_used_pct,
        disk_free_gb=disk_free_gb,
        agent_version=body.get("agent_version"),
        agent_memory_mb=_metric(body.get("agent_memory_mb")),
        agent_uptime_sec=_integer_metric(body.get("agent_uptime_sec")),
        last_seen_ip=client_ip,
        local_ip=local_ip,
        device_type=str(body.get("device_type") or "").strip().lower() or None,
        platform=reported_platform,
        capabilities=body.get("capabilities"),
        capability_details=body.get("capability_details"),
        interactive_user_marker=valid_interactive_user,
        interactive_user=interactive_user if valid_interactive_user else None,
        net_sent_mbps=_metric(body.get("net_sent_mbps")),
        net_recv_mbps=_metric(body.get("net_recv_mbps")),
        topology_telemetry=topology_telemetry,
    )

    if valid_interactive_user and interactive_user:
        try:
            queue_periodic_home_sync(
                endpoint, interactive_user,
                capabilities=(body.get("capabilities") or []) if "capabilities" in body else None,
                platform=reported_platform,
            )
        except Exception:
            # Home scheduling must not prevent metrics and other commands from
            # being delivered when storage metadata or the tenant vault fails.
            current_app.logger.exception("Home sync scheduling failed for endpoint %s", endpoint["id"])

    # Agent 2.1.25+ collects configured machine policy at startup and keeps
    # attaching it until a heartbeat succeeds. Older agents omit this field
    # and continue to use the normal heartbeat protocol unchanged.
    if isinstance(body.get("policy_inventory"), dict):
        _record_policy_values(endpoint, body["policy_inventory"], "agent_startup")

    # Record metrics
    if cpu_pct is not None:
        db.insert_metric(
            endpoint["id"],
            cpu_pct,
            ram_used_pct,
            disk_free_gb,
        )

    # A successful authenticated heartbeat is authoritative proof that an
    # endpoint-offline condition has cleared.
    offline_alert = db.get_open_alert(endpoint["id"], "endpoint_offline")
    if offline_alert:
        db.resolve_alert(offline_alert["id"], None, "Endpoint heartbeat resumed")

    # Agent-side TLS trust-on-first-use re-pin (comms.py) reports every
    # fingerprint rotation here for an audit trail, even though it never
    # blocks the agent's own operation — see comms.py's _connect_with_pin.
    rotation = body.get("cert_rotation_detected")
    if isinstance(rotation, dict) and rotation.get("new_fingerprint"):
        db.log_endpoint_event(endpoint["id"], "tls_cert_rotation_detected", {
            "old_fingerprint": rotation.get("old_fingerprint"),
            "new_fingerprint": rotation.get("new_fingerprint"),
        })

    # Fetch pending jobs and sign each as an Ed25519 envelope. Payloads are
    running_id=body.get('running_job_id')
    if running_id:
        import uuid
        try:running_id=str(uuid.UUID(str(running_id)))
        except ValueError:return jsonify(error='invalid_running_job_id'),400
        db._rpc('renew_agent_job_lease',dict(p_endpoint=endpoint['id'],p_job=running_id))
    # stored encrypted per-tenant (see services/tenant_crypto.py) — a
    # BYOK-mode company whose vault is currently locked can't have its jobs
    # decrypted for dispatch; skip those (left pending, logged) rather than
    # failing the whole heartbeat for every other job.
    from services.tenant_crypto import VaultLocked
    try:
        job_capacity = int(body.get("job_capacity", 5))
    except (TypeError, ValueError):
        job_capacity = 0
    job_capacity = max(0, min(job_capacity, 5))
    pending = (
        db.get_pending_jobs_for_endpoint(endpoint["id"], limit=job_capacity)
        if job_capacity else []
    )
    capabilities_field = body.get("capabilities")
    capability_aware = "capabilities" in body
    reported_capabilities = {
        str(value) for value in capabilities_field
        if isinstance(capabilities_field, list) and isinstance(value, str)
    }
    _queue_profile_device_identity(
        endpoint, body, reported_capabilities, reported_platform,
    )
    company = db.get_company_by_id(endpoint["company_id"])
    commands = []
    for job in pending:
        # An explicit capability field is authoritative, including an empty
        # list. Legacy compatibility is restricted to old Windows agents;
        # treating an omitted list from Linux/macOS as "supports everything"
        # would dispatch Windows-only privileged operations.
        unsupported = (
            (capability_aware and job["type"] not in reported_capabilities)
            or (not capability_aware and reported_platform in {"linux", "darwin"})
        )
        if unsupported:
            finished = db.finish_running_job(
                job["id"], "failed", "", 1,
                f"Operation {job['type']} is not supported by this {reported_platform or 'endpoint'} agent",
            )
            if finished and db.claim_job_result_processing(job["id"]):
                db.complete_job_result_processing(job["id"])
            continue
        try:
            payload = db.decrypt_field(company, job.get("payload"), "job.payload") or {}
        except VaultLocked:
            db.log_endpoint_event(endpoint["id"], "job_dispatch_blocked_vault_locked", {
                "job_id": job["id"],
            })
            continue
        env = sign_job(
            str(job["id"]), job["type"], payload,
            str(endpoint["company_id"]), str(endpoint["id"]),
        )
        commands.append(env)

    branch_timezone = "UTC"
    if endpoint.get("branch_id"):
        branch = db.get_branch(endpoint["branch_id"])
        branch_timezone = str((branch or {}).get("timezone") or "UTC")

    return jsonify({
        "ok": True,
        "commands": commands,
        "server_time": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "branch_timezone": branch_timezone if reported_platform == "windows" else None,
    })


@bp.route("/api/agent/sysinfo", methods=["POST"])
@agent_auth_required
def sysinfo():
    """
    Agent reports full system information.
    Body: {
        "os_name": "Windows 11 Pro",
        "os_version": "10.0.22631",
        "os_build": "22631",
        "arch": "AMD64",
        "cpu_model": "Intel Core i5-12400",
        "ram_total_gb": 16.0,
        "disk_total_gb": 512.0
    }
    """
    body = request.get_json(silent=True) or {}
    _record_hostname_change(g.endpoint, body.get("hostname"))
    db.update_endpoint_sysinfo(g.endpoint["id"], body)
    return jsonify({"ok": True})


@bp.route("/api/agent/bitlocker-recovery", methods=["POST"])
@agent_auth_required
def bitlocker_recovery():
    """Escrow a BitLocker numerical recovery password before encryption starts.

    This endpoint never writes plaintext recovery material to jobs, endpoint
    events, request logs, or audit details. The database receives only
    organization-vault ciphertext.
    """
    body = request.get_json(silent=True) or {}
    job_id = str(body.get("job_id") or "").strip()
    mount = str(body.get("volume_mount") or "").strip().upper()
    protector_id = str(body.get("protector_id") or "").strip()
    password = str(body.get("recovery_password") or "").strip()
    groups = password.split("-")
    valid_password = (
        len(groups) == 8
        and all(re.fullmatch(r"\d{6}", group or "") for group in groups)
        and all(int(group) <= 720885 and int(group) % 11 == 0 for group in groups)
    )
    if (
        not job_id or not re.fullmatch(r"[A-Z]:", mount)
        or not re.fullmatch(r"\{?[0-9a-fA-F-]{36}\}?", protector_id)
        or not valid_password
    ):
        return jsonify({"error": "invalid_bitlocker_recovery_payload"}), 400
    job = db.get_job(job_id)
    if (
        not job or str(job.get("endpoint_id")) != str(g.endpoint["id"])
        or job.get("type") not in {"ENABLE_BITLOCKER", "ROTATE_BITLOCKER_RECOVERY"}
        or job.get("status") != "running"
    ):
        return jsonify({"error": "invalid_or_inactive_job"}), 409
    try:
        percentage = float(body.get("encryption_percentage", 0))
    except (TypeError, ValueError):
        return jsonify({"error": "invalid_encryption_percentage"}), 400
    if not 0 <= percentage <= 100:
        return jsonify({"error": "invalid_encryption_percentage"}), 400
    company = db.get_company_by_id(g.endpoint["company_id"])
    if not company:
        abort(404)
    try:
        record = db.escrow_endpoint_recovery_key(
            company, g.endpoint["id"], mount, protector_id, password,
            str(body.get("volume_status") or "")[:80],
            str(body.get("protection_status") or "")[:80], percentage,
        )
    except Exception as exc:
        from services.tenant_crypto import VaultLocked
        if isinstance(exc, VaultLocked):
            return jsonify({"error": "tenant_vault_locked"}), 423
        raise
    db.log_endpoint_event(g.endpoint["id"], "bitlocker_recovery_key_escrowed", {
        "recovery_key_id": str(record["id"]), "volume_mount": mount,
        "protector_id": protector_id,
    })
    return jsonify({"ok": True, "recovery_key_id": str(record["id"])})


@bp.post('/api/agent/home-progress')
@agent_auth_required
def home_progress():
    if not check_rate_limit(f"home-progress:{g.endpoint['id']}",30):
        return jsonify(error='rate_limited'),429
    body = request.get_json(silent=True)
    if not isinstance(body,dict) or not isinstance(body.get('report'),dict):
        return jsonify(error='invalid_payload'),400
    job_id = str(body.get('job_id') or '')
    report = body['report']
    job = db.get_job(job_id,decrypt=False)
    if not job or str(job.get('endpoint_id')) != str(g.endpoint['id']) or job.get('type') != 'SYNC_WARDEN_HOME':
        return jsonify(error='not_found'),404
    if report.get('kind') != 'warden_home_sync' or report.get('version') != 1 or report.get('status') != 'running':
        return jsonify(error='invalid_report'),400
    encoded = json.dumps(report,separators=(',',':'))
    if len(encoded.encode('utf-8')) > 256*1024:
        return jsonify(error='report_too_large'),413
    from routes.home import _home_transfer_view
    clean = _home_transfer_view(dict(log_output=encoded),{}).get('report')
    if clean is None:
        return jsonify(error='invalid_report'),400
    clean.update(kind='warden_home_sync',version=1,status='running')
    encoded=json.dumps(clean,separators=(',',':'))
    company = db.get_company_by_id(g.endpoint['company_id'])
    updated = db._patch(f"jobs?id=eq.{db._q(job_id)}&status=eq.running",{
        'log_output':db.encrypt_field(company,encoded,'job.log-output')})
    return jsonify(ok=True,accepted=bool(updated))


@bp.route("/api/agent/job-result", methods=["POST"])
@agent_auth_required
def job_result():
    """
    Agent reports the result of a completed job.
    Body: {
        "job_id": "uuid",
        "status": "completed" | "failed",
        "exit_code": 0,
        "log_output": "...",
        "error_msg": "..."
    }
    """
    body = request.get_json(silent=True) or {}
    job_id = str(body.get("job_id") or "").strip()
    status = str(body.get("status") or "")
    exit_code = body.get("exit_code")
    log_output = body.get("log_output", "")
    error_msg = body.get("error_msg", "")

    if (
        not job_id or status not in ("completed", "failed")
        or not isinstance(log_output, str) or not isinstance(error_msg, str)
        or len(log_output.encode("utf-8")) > 1024 * 1024
        or len(error_msg.encode("utf-8")) > 16 * 1024
    ):
        return jsonify({"error": "invalid_payload"}), 400
    if exit_code is not None:
        try:
            exit_code = int(exit_code)
        except (TypeError, ValueError):
            return jsonify({"error": "invalid_exit_code"}), 400

    job = db.get_job(job_id)
    if not job or str(job["endpoint_id"]) != str(g.endpoint["id"]):
        return jsonify({"error": "not_found"}), 404

    # Atomic lease claiming changes a dispatched job to running before this
    # endpoint receives it. Only that state may finish: duplicate outbox
    # retries and stale results for cancelled/completed jobs are harmless
    # no-ops and cannot repeat the side effects below.
    finished_now = db.finish_running_job(job_id, status, log_output, exit_code, error_msg)
    if not finished_now and job.get("status") != status:
        return jsonify({"ok": True, "duplicate": True})
    if not db.claim_job_result_processing(job_id):
        latest = db.get_job(job_id, decrypt=False)
        if latest and latest.get("result_processed_at"):
            return jsonify({"ok": True, "duplicate": True})
        return jsonify({"error": "result_processing_pending_retry"}), 503

    if status == "failed" and job["type"] == "PUSH_LOCAL_POLICY":
        paused_deployment_id = db.maybe_pause_policy_deployment(job_id)
        if paused_deployment_id:
            db.log_endpoint_event(g.endpoint["id"], "policy_deployment_auto_paused", {
                "deployment_id": str(paused_deployment_id),
                "reason": "failure threshold reached",
            })
    if job["type"] == "PUSH_LOCAL_POLICY":
        db.refresh_policy_deployment_status(job_id)
    if job["type"] == "WINDOWS_UPDATE":
        db.refresh_patch_deployment(job_id, status == "completed" and exit_code == 0)

    # If job was an escalation, complete the escalation request
    if job.get("escalation_id"):
        db.complete_escalation(job["escalation_id"], log_output, exit_code)

    # Record last-known-applied value of each individually-addressable
    # policy setting this job pushed, so the endpoint's Policy tab can show
    # what Warden last set without needing a live registry read-back. Only
    # on success, and only for the new {"settings": {...}} payload shape —
    # legacy fixed LGPO templates aren't individually addressable so there's
    # nothing per-key to record.
    if job["type"] == "PUSH_LOCAL_POLICY" and status == "completed" and exit_code == 0:
        settings = (job.get("payload") or {}).get("settings")
        if isinstance(settings, dict) and settings:
            db.update_endpoint_policy_state(
                g.endpoint["id"], settings,
                policy_version=str((job.get("payload") or {}).get("policy_version") or "1"),
            )

    # Optimistic windows_users update after Warden's own user-management
    # actions, so the Users tab reflects the change immediately rather than
    # waiting on a separate COLLECT_USERS scan (which is still what
    # establishes a row for a brand-new account and refreshes fields these
    # ops don't touch, like display_name).
    if status == "completed" and exit_code == 0:
        job_payload = job.get("payload") or {}
        username = job_payload.get("username")
        if job["type"] in {"CREATE_USER", "PROVISION_WARDEN_IDENTITY"} and username:
            db.upsert_windows_user(
                g.endpoint["id"], username,
                is_admin=bool(job_payload.get("is_admin")),
                is_enabled=True,
                display_name=job_payload.get("full_name"),
                profile_photo=job_payload.get("profile_photo"),
            )
        elif job["type"] == "DELETE_USER" and username:
            db.delete_windows_user(g.endpoint["id"], username)
        elif job["type"] == "DISABLE_USER" and username:
            db.set_windows_user_state(g.endpoint["id"], username, is_enabled=False)
        elif job["type"] == "ENABLE_USER" and username:
            db.set_windows_user_state(g.endpoint["id"], username, is_enabled=True)
        elif job["type"] == "GRANT_ELEVATION" and username:
            db.set_windows_user_state(g.endpoint["id"], username, is_admin=True)
        elif job["type"] == "REVOKE_ELEVATION" and username:
            db.set_windows_user_state(g.endpoint["id"], username, is_admin=False)

    # A Warden identity assignment follows the final agent job associated
    # with it.  This is deliberately keyed by job id (not username) so an
    # unrelated local-account action can never mutate centralized identity
    # state, even when the names happen to match.
    db.mark_warden_assignment_job_result(
        job_id, status == "completed" and exit_code == 0,
        error_msg or (log_output if status == "failed" else None),
        success_status="revoked" if job["type"] == "DELETE_USER" else "active",
    )

    # A Warden-only enrollment is deliberately a second, chained job.  The
    # endpoint is never locked down until the assigned Warden identity has
    # actually been created by the agent and acknowledged successfully.
    if (
        job["type"] == "PROVISION_WARDEN_IDENTITY"
        and status == "completed" and exit_code == 0
        and g.endpoint.get("enrollment_profile_id")
        and "WARDEN_ONLY_LOCKDOWN" in (g.endpoint.get("capabilities") or [])
    ):
        try:
            profile = db.get_enrollment_profile(g.endpoint["enrollment_profile_id"])
            lockdown = (profile or {}).get("lockdown_config") or {}
            if (
                profile and profile.get("warden_only_mode") and lockdown
                and not db.has_inflight_job(g.endpoint["id"], "WARDEN_ONLY_LOCKDOWN")
            ):
                allowed_users = db.get_active_warden_usernames_for_endpoint(g.endpoint["id"])
                if allowed_users:
                    db.create_job(
                        g.endpoint["company_id"], g.endpoint.get("branch_id"),
                        g.endpoint["id"], "WARDEN_ONLY_LOCKDOWN", {
                            "allowed_users": allowed_users,
                            "recovery_admin_username": lockdown["recovery_admin_username"],
                            "recovery_admin_password": lockdown["recovery_admin_password"],
                        }, created_by=None,
                    )
                    db.log_endpoint_event(g.endpoint["id"], "warden_only_lockdown_queued", {
                        "allowed_users": allowed_users,
                        "recovery_admin_username": lockdown["recovery_admin_username"],
                    })
        except Exception:
            # The identity remains active and the machine remains accessible;
            # surface lockdown orchestration failure without invalidating the
            # already-successful identity provisioning result.
            import logging
            logging.getLogger("warden.agent_api").exception(
                "Could not queue Warden-only lockdown for endpoint %s", g.endpoint["id"],
            )
            db.create_alert(
                company_id=g.endpoint["company_id"],
                branch_id=g.endpoint.get("branch_id"), endpoint_id=g.endpoint["id"],
                alert_type="warden_only_lockdown_failed", severity="critical",
                title="Warden-only enrollment was not completed",
                message="The Warden identity is usable, but existing Windows accounts were not disabled.",
            )

    # CHECK_POLICY_DRIFT reports current live values as a JSON object in
    # log_output (see agent-go/policy.go's checkPolicyDrift). Compare against
    # what Warden last pushed and alert once per scan if anything changed
    # outside Warden, instead of one alert per drifted setting.
    if job["type"] == "CHECK_POLICY_DRIFT" and status == "completed" and exit_code == 0:
        try:
            # log_output comes straight from the agent's JSON POST body with
            # no type check — if it's ever a non-string JSON value (object,
            # number, bool), json.loads raises TypeError, not ValueError,
            # which the original `except ValueError` didn't catch. That let
            # an uncaught 500 escape here — AFTER db.update_job_status()
            # above had already committed the job as "completed" — so a
            # malformed drift result silently lost its alert/record with no
            # useful error, the same "mutate then crash" shape as the fixed
            # escalations.py approve() bug.
            current_values = json.loads(log_output or "{}")
        except (ValueError, TypeError):
            current_values = {}
        if isinstance(current_values, dict):
            _record_policy_values(g.endpoint, current_values, "drift_job")

    db.log_endpoint_event(g.endpoint["id"], f"job_{status}", {
        "job_id": job_id,
        "type": job["type"],
        "exit_code": exit_code,
    })

    # Alert on failure
    if status == "failed":
        db.create_alert(
            company_id=g.endpoint["company_id"],
            branch_id=g.endpoint["branch_id"],
            endpoint_id=g.endpoint["id"],
            alert_type="job_failed",
            severity="warning",
            title=f"Job Failed: {job['type']}",
            message=error_msg or "Job failed with no error message",
            detail={"job_id": job_id, "exit_code": exit_code},
        )

    # A successful uninstall is the endpoint's final authenticated request.
    # Retire it only after recording the result/event so the active fleet no
    # longer shows a permanently-offline ghost, while retaining its history.
    # Marking it inactive also makes the old agent API key unusable if a
    # partially removed binary is ever started again.
    if job["type"] == "UNINSTALL_AGENT" and status == "completed" and exit_code == 0:
        cf_cert_id = g.endpoint.get("cloudflare_cert_id")
        cert_revocation_failed = False
        if cf_cert_id:
            try:
                from services.agent_ca import revoke_agent_cert
                revoke_agent_cert(cf_cert_id)
            except Exception as exc:
                cert_revocation_failed = True
                # Local retirement must still happen immediately. Record the
                # external revocation failure prominently for operator retry.
                import logging
                logging.getLogger("warden.agent_api").error(
                    "Cloudflare certificate revocation failed for endpoint %s: %s",
                    g.endpoint["id"], exc,
                )
                db.create_alert(
                    company_id=g.endpoint["company_id"],
                    branch_id=g.endpoint.get("branch_id"),
                    endpoint_id=g.endpoint["id"],
                    alert_type="client_cert_revocation_failed",
                    severity="critical",
                    title=f"Client certificate revocation failed: {g.endpoint.get('hostname')}",
                    message=f"Certificate {cf_cert_id}: {str(exc)[:450]}",
                )
        db.retire_endpoint(
            g.endpoint["id"],
            clear_cloudflare_cert_id=not cert_revocation_failed,
        )

    if not db.complete_job_result_processing(job_id):
        return jsonify({"error": "result_processing_not_completed"}), 500

    return jsonify({"ok": True})


@bp.route("/api/agent/remote-relay-failed", methods=["POST"])
@agent_auth_required
def remote_relay_failed():
    """Agent reports that its side of a remote-desktop pairing attempt
    failed (see agent-go/remote.go's reportRelayFailure) — e.g. no
    interactive console session, the helper process couldn't start, or the
    WSS dial itself failed. Lets the viewer show the real reason within a
    few seconds instead of only finding out via ws_proxy's 60s
    PAIR_TIMEOUT."""
    body = request.get_json(silent=True) or {}
    session_id = str(body.get("session_id") or "").strip()
    reason = str(body.get("reason") or "")[:500]

    if not session_id:
        return jsonify({"error": "missing_session_id"}), 400

    session = db.get_remote_session(session_id)
    if not session or str(session["endpoint_id"]) != str(g.endpoint["id"]):
        return jsonify({"error": "not_found"}), 404

    db.mark_remote_session_failed(session_id, reason)
    db.log_endpoint_event(g.endpoint["id"], "remote_relay_failed", {
        "session_id": session_id,
        "reason": reason,
    })
    return jsonify({"ok": True})


@bp.route("/api/agent/remote-consent", methods=["POST"])
@agent_auth_required
def remote_consent():
    body = request.get_json(silent=True) or {}
    session_id = str(body.get("session_id") or "").strip()
    status = str(body.get("status") or "").strip()
    if status not in {"not_required", "pending", "approved", "denied", "expired"}:
        return jsonify({"error": "invalid_status"}), 400
    session = db.get_remote_session(session_id)
    if not session or str(session.get("endpoint_id")) != str(g.endpoint["id"]):
        return jsonify({"error": "not_found"}), 404
    if session.get("status") != "active":
        return jsonify({"error": "session_not_active"}), 409
    if session.get("consent_required") and status == "not_required":
        return jsonify({"error": "consent_required"}), 409
    db.update_remote_session_support_state(session_id, consent_status=status)
    db.create_remote_session_event(
        session_id, g.endpoint["company_id"], None, "consent",
        f"Endpoint consent status: {status}",
    )
    db.log_endpoint_event(g.endpoint["id"], "remote_consent", {
        "session_id": session_id, "status": status,
    })
    return jsonify({"ok": True})


@bp.route("/api/agent/remote-chat", methods=["POST"])
@agent_auth_required
def remote_chat():
    body = request.get_json(silent=True) or {}
    session_id = str(body.get("session_id") or "").strip()
    text = str(body.get("text") or "").strip()
    if not text or len(text) > 4000:
        return jsonify({"error": "invalid_text"}), 400
    session = db.get_remote_session(session_id)
    if not session or str(session.get("endpoint_id")) != str(g.endpoint["id"]):
        return jsonify({"error": "not_found"}), 404
    if session.get("status") != "active":
        return jsonify({"error": "session_not_active"}), 409
    db.create_remote_session_event(
        session_id, g.endpoint["company_id"], None, "chat_endpoint", text,
        {"source": "authenticated_endpoint_agent"},
    )
    return jsonify({"ok": True})


@bp.route("/api/agent/log-append", methods=["POST"])
@agent_auth_required
def log_append():
    """Stream log lines for a running job."""
    body = request.get_json(silent=True) or {}
    job_id = str(body.get("job_id") or "").strip()
    lines = body.get("lines", "")

    if not job_id or not isinstance(lines, str) or not lines:
        return jsonify({"error": "missing_fields"}), 400

    job = db.get_job(job_id)
    if not job or str(job["endpoint_id"]) != str(g.endpoint["id"]):
        return jsonify({"error": "not_found"}), 404

    db.append_job_log(job_id, lines)
    return jsonify({"ok": True})


@bp.route("/api/agent/users", methods=["POST"])
@agent_auth_required
def report_users():
    """
    Agent reports current local Windows users.
    Body: {
        "users": [
            {"username": "john", "display_name": "John Doe", "is_admin": false, "is_enabled": true},
            ...
        ]
    }
    """
    body = request.get_json(silent=True) or {}
    users = body.get("users")
    if not isinstance(users, list) or len(users) > 512:
        return jsonify({"error": "invalid_users"}), 400

    cleaned = []
    seen = set()
    sid_pattern = re.compile(r"^S-\d(?:-\d+)+$", re.IGNORECASE)
    allowed_types = {"local", "domain", "entra", "microsoft", "unknown"}
    for user in users:
        if not isinstance(user, dict):
            return jsonify({"error": "invalid_user"}), 400
        username = str(user.get("username") or "").strip()
        if not username or len(username) > 256 or any(ord(c) < 32 for c in username):
            return jsonify({"error": "invalid_username"}), 400
        folded = username.casefold()
        if folded in seen:
            return jsonify({"error": "duplicate_username"}), 400
        seen.add(folded)

        sid = str(user.get("sid") or "").strip()
        if sid and (len(sid) > 184 or not sid_pattern.fullmatch(sid)):
            return jsonify({"error": "invalid_sid"}), 400
        account_type = str(user.get("account_type") or "local").lower()
        if account_type not in allowed_types:
            account_type = "unknown"
        is_admin = user.get("is_admin", False)
        is_enabled = user.get("is_enabled", True)
        if not isinstance(is_admin, bool) or not isinstance(is_enabled, bool):
            return jsonify({"error": "invalid_account_flags"}), 400
        cleaned.append({
            "username": username,
            "display_name": str(user.get("display_name") or "")[:256],
            "sid": sid,
            "principal_name": str(user.get("principal_name") or "")[:512],
            "account_type": account_type,
            "domain_name": str(user.get("domain_name") or "")[:255],
            "is_admin": is_admin,
            "is_enabled": is_enabled,
        })

    count = db.replace_windows_users(g.endpoint["id"], cleaned)
    return jsonify({"ok": True, "count": count})


@bp.route("/api/agent/software", methods=["POST"])
@agent_auth_required
def report_software():
    """
    Agent reports installed software inventory.
    Body: {
        "software": [
            {"name": "Chrome", "version": "124.0", "publisher": "Google", "install_date": "..."},
            ...
        ]
    }
    """
    body = request.get_json(silent=True) or {}
    items = body.get("software", [])
    if not isinstance(items, list) or len(items) > 5000:
        return jsonify({"error": "software must be an array of at most 5000 items"}), 400
    accepted = []
    windows_absolute_path = re.compile(r"^[A-Za-z]:\\")
    for item in items:
        if not isinstance(item, dict):
            return jsonify({"error": "invalid software item"}), 400
        name = str(item.get("name") or "").strip()[:500]
        if not name:
            continue
        executable_path = str(item.get("executable_path") or "").strip()[:2048]
        install_location = str(item.get("install_location") or "").strip()[:2048]
        if executable_path and (
            not windows_absolute_path.match(executable_path)
            or not executable_path.lower().endswith(".exe")
            or ".." in executable_path.replace("/", "\\").split("\\")
        ):
            executable_path = ""
        if install_location and (
            not windows_absolute_path.match(install_location)
            or ".." in install_location.replace("/", "\\").split("\\")
        ):
            install_location = ""
        accepted.append({
            "name": name,
            "version": str(item.get("version") or "")[:200],
            "publisher": str(item.get("publisher") or "")[:500],
            "install_date": str(item.get("install_date") or "")[:100],
            "install_location": install_location or None,
            "executable_path": executable_path or None,
        })
    db.replace_software_inventory(g.endpoint["id"], accepted)
    db._patch(f"endpoints?id=eq.{db._q(g.endpoint['id'])}",{"software_inventory_at":db._now_iso()})
    return jsonify({"ok": True, "count": len(accepted)})


@bp.post('/api/agent/support-request')
@agent_auth_required
def request_support():
    if not check_rate_limit('support:'+str(g.endpoint['id']),5,fail_closed=True):
        return jsonify(error='rate_limited'),429
    body=request.get_json(silent=True) or {}
    if not isinstance(body,dict):return jsonify(error='invalid_request'),400
    username=str(body.get('username') or '').strip()
    message=str(body.get('message') or '').strip()
    if not 1<=len(username)<=256 or not 1<=len(message)<=2000 or any(ord(c)<32 and c not in '\n\t' for c in username+message):
        return jsonify(error='invalid_request'),400
    endpoint=g.endpoint
    path=f"support_requests?endpoint_id=eq.{db._q(endpoint['id'])}&company_id=eq.{db._q(endpoint['company_id'])}&status=in.(open,claimed)&limit=1"
    existing=db._get(path)
    if existing:return jsonify(ok=True,request_id=existing[0]['id'],existing=True)
    company=db.get_company_by_id(endpoint['company_id'])
    encrypted=db.encrypt_field(company,dict(username=username,message=message),'support.request')
    try:
        row=db._post('support_requests',dict(company_id=endpoint['company_id'],endpoint_id=endpoint['id'],request_encrypted=encrypted))[0]
    except Exception:
        existing=db._get(path)
        if existing:return jsonify(ok=True,request_id=existing[0]['id'],existing=True)
        raise
    db.audit(endpoint['company_id'],None,'support_requested',dict(request_id=row['id']),branch_id=endpoint.get('branch_id'),endpoint_id=endpoint['id'])
    return jsonify(ok=True,request_id=row['id'])


@bp.get('/api/agent/traffic-config')
@agent_auth_required
def traffic_config():
    from services.fleet_tools import traffic_for
    rule=traffic_for(g.endpoint)
    if not rule:return jsonify(traffic=None)
    return jsonify(traffic={key:rule[key] for key in ('business_start','business_end','business_kbps','offhours_kbps')})


@bp.get('/api/agent/package-cache')
@agent_auth_required
def package_cache_config():
    from services.fleet_tools import traffic_for
    from services.home_grants import issue_package_grant
    rule=traffic_for(g.endpoint)
    if not rule or not rule.get('package_cache_node_id'):return jsonify(cache=None)
    app=db.get_app(request.args.get('app_id'))
    if not app or (app.get('company_id') and str(app['company_id'])!=str(g.endpoint['company_id'])):abort(404)
    if request.args.get('sha256')!=app.get('sha256'):abort(409)
    node=next((n for n in db.get_home_nodes(g.endpoint['company_id']) if str(n['id'])==str(rule['package_cache_node_id'])),None)
    if not node or node.get('status')!='online' or (node.get('branch_id') and str(node['branch_id'])!=str(g.endpoint.get('branch_id'))):return jsonify(cache=None)
    if not (node.get('capabilities') or {}).get('package_cache'):return jsonify(cache=None)
    if node.get('deployment_mode')=='p2p':return jsonify(cache=None)
    # Cache uses exactly the same TLS/mTLS transport as Home, never an HTTP LAN shortcut.
    return jsonify(cache=dict(id=node['id'],local_url=node.get('local_url'),public_url=node.get('public_url'),
        connection_mode=node.get('deployment_mode') or 'local',p2p_url=f"https://warden-home-{node['id']}.internal:9443",
        stun_urls=config.HOME_P2P_STUN_URLS,tls_fingerprint=node.get('tls_fingerprint'),
        ca_certificate_pem=node.get('ca_certificate_pem'),require_mtls=bool(node.get('require_mtls',True)),
        grant=issue_package_grant(g.endpoint,node,app)))


@bp.route("/api/agent/patch-inventory", methods=["POST"])
@agent_auth_required
def report_patch_inventory():
    body = request.get_json(silent=True) or {}
    items = body.get("updates")
    if not isinstance(items, list) or len(items) > 500:
        return jsonify({"error": "updates must be an array of at most 500 items"}), 400
    accepted = []
    for item in items:
        if not isinstance(item, dict):
            return jsonify({"error": "invalid update item"}), 400
        update_id = str(item.get("update_id") or "").strip()[:200]
        title = str(item.get("title") or "").strip()[:500]
        if not update_id or not title:
            return jsonify({"error": "update_id and title are required"}), 400
        accepted.append({
            "update_id": update_id, "title": title,
            "kb_articles": [str(v)[:30] for v in (item.get("kb_articles") or [])[:20]],
            "severity": str(item.get("severity") or "Unspecified")[:40],
            "categories": [str(v)[:100] for v in (item.get("categories") or [])[:20]],
            "reboot_required": bool(item.get("reboot_required")),
        })
    db.replace_patch_inventory(g.endpoint["company_id"], g.endpoint["id"], accepted)
    db.log_endpoint_event(g.endpoint["id"], "patch_inventory_reported", {"missing_updates": len(accepted)})
    return jsonify({"ok": True, "count": len(accepted)})


def _bounded_db_text(value, limit):
    """Return Postgres-safe endpoint telemetry text.

    Windows process metadata can contain NUL characters, which JSON accepts
    but PostgreSQL text rejects and would otherwise discard the entire batch.
    """
    text = str(value or "").replace("\x00", "").strip()
    return text[:limit] or None


def _normalise_network_flow(flow, rules):
    from services.firewall_analysis import evaluate_flow

    protocol = str(flow.get("protocol") or "").lower()
    if protocol not in {"tcp", "udp"}:
        return None
    clean = {"protocol": protocol, "direction": "outbound"}
    for field in ("local_address", "remote_address"):
        value = str(flow.get(field) or "").strip()
        # Windows appends an interface scope (for example "%7") to
        # link-local IPv6 endpoints. PostgreSQL inet stores the address but
        # does not accept that host-local scope identifier.
        if ":" in value and "%" in value:
            value = value.split("%", 1)[0]
        if value and value not in {"*", "0.0.0.0", "::"}:
            try:
                clean[field] = str(ipaddress.ip_address(value))
            except ValueError:
                clean[field] = None
        else:
            clean[field] = None
    for field in ("local_port", "remote_port"):
        try:
            value = int(flow.get(field) or 0)
        except (TypeError, ValueError, OverflowError):
            value = 0
        clean[field] = value if 0 < value <= 65535 else None
    try:
        process_id = int(flow.get("process_id") or 0)
    except (TypeError, ValueError, OverflowError):
        process_id = 0
    clean["process_id"] = min(max(0, process_id), 2147483647)
    clean.update({
        "process_name": _bounded_db_text(flow.get("process_name"), 260),
        "process_path": _bounded_db_text(flow.get("process_path"), 2048),
        "state": _bounded_db_text(flow.get("state"), 80),
    })
    decision = evaluate_flow(clean, rules)
    action = str(decision.get("action") or "unmatched").lower()
    clean["policy_action"] = action if action in {"allow", "block", "unmatched"} else "unmatched"
    clean["policy_rule"] = _bounded_db_text(decision.get("rule"), 300)
    try:
        weight = int(decision.get("weight") or 0)
    except (TypeError, ValueError, OverflowError):
        weight = 0
    clean["policy_weight"] = min(max(-2147483648, weight), 2147483647)
    return clean


@bp.route("/api/agent/network-flows", methods=["POST"])
@agent_auth_required
def report_network_flows():
    from services.effective_policy import resolve_effective_policy
    body = request.get_json(silent=True) or {}
    flows = body.get("flows")
    if not isinstance(flows, list) or len(flows) > 1000:
        return jsonify({"error": "flows must be an array of at most 1000 items"}), 400
    accepted = []
    rules = []
    try:
        resolved = resolve_effective_policy(
            g.endpoint, db.get_policy_assignments(g.endpoint["company_id"]),
        )
        raw_rules = resolved["settings"].get("windows_firewall_rules", "[]")
        rules = json.loads(raw_rules) if isinstance(raw_rules, str) else (raw_rules or [])
    except (ValueError, TypeError):
        rules = []
    for flow in flows:
        if not isinstance(flow, dict):
            return jsonify({"error": "invalid flow item"}), 400
        clean = _normalise_network_flow(flow, rules)
        if clean:
            accepted.append(clean)
    db.replace_network_flows(g.endpoint["company_id"], g.endpoint["id"], accepted)
    db.log_endpoint_event(g.endpoint["id"], "network_flows_reported", {"count": len(accepted)})
    return jsonify({"ok": True, "count": len(accepted)})


@bp.route("/api/agent/escalation-check", methods=["POST"])
@agent_auth_required
def escalation_check():
    """
    Agent checks if a requested operation has an approved escalation token.
    Body: {
        "operation": "INSTALL_APP",
        "windows_user": "john",
        "payload": {...},
        "reason": "Need Chrome for presentation"
    }
    Response (if auto-approved by policy):
        {"approved": true, "token": "..."}
    Response (if needs manual approval):
        {"approved": false, "request_id": "...", "message": "Pending admin approval"}
    """
    body = request.get_json(silent=True) or {}
    operation = body.get("operation", "").strip()
    windows_user = body.get("windows_user", "").strip()
    payload = body.get("payload") or {}
    reason = body.get("reason", "").strip()
    endpoint = g.endpoint

    if not operation or not windows_user:
        return jsonify({"error": "missing_fields"}), 400

    # Validate operation before any policy lookup (M-10)
    from routes.enroll import ALLOWED_OPERATIONS
    if operation not in ALLOWED_OPERATIONS:
        return jsonify({"error": "operation_not_allowed"}), 403

    if operation == "PUSH_LOCAL_POLICY":
        from policy_templates import POLICY_TEMPLATES
        if payload.get("template", "") not in POLICY_TEMPLATES:
            return jsonify({"error": "unknown_policy_template"}), 400

    # Check for a matching saved policy
    policy = db.find_matching_policy(
        endpoint["company_id"], endpoint["id"], windows_user, operation, payload
    )
    if policy:
        # A saved policy can provide the first approval, but must never waive
        # the organization's independent second approval for high-risk operations.
        dual_approval_ops = {
            "DELETE_USER", "SHUTDOWN", "REBOOT", "UNINSTALL_AGENT",
            "PUSH_LOCAL_POLICY",
        }
        company = db.get_company_by_id(endpoint["company_id"]) or {}
        requires_dual = (
            operation in dual_approval_ops
            and company.get("require_dual_approval", True)
        )
        esc_req = db.create_escalation_request(
            company_id=endpoint["company_id"],
            branch_id=endpoint["branch_id"],
            endpoint_id=endpoint["id"],
            windows_user=windows_user,
            operation=operation,
            payload=payload,
            reason=reason,
            requires_dual=requires_dual,
        )
        if esc_req:
            token, approved = db.approve_escalation(
                esc_req["id"], policy.get("approved_by"), "pending"
            )
            db.log_endpoint_event(endpoint["id"], "escalation_auto_approved", {
                "operation": operation,
                "policy_id": policy["id"],
                "windows_user": windows_user,
                "requires_dual_approval": requires_dual,
            })
            if approved and approved.get("status") == "approved":
                return jsonify({"approved": True, "token": token, "request_id": esc_req["id"]})
            return jsonify({
                "approved": False,
                "request_id": str(esc_req["id"]),
                "message": "Policy matched; awaiting independent second approval.",
            })

    # No matching policy — create pending request for admin review
    esc_req = db.create_escalation_request(
        company_id=endpoint["company_id"],
        branch_id=endpoint["branch_id"],
        endpoint_id=endpoint["id"],
        windows_user=windows_user,
        operation=operation,
        payload=payload,
        reason=reason,
    )
    if not esc_req:
        return jsonify({"error": "failed_to_create_request"}), 500

    return jsonify({
        "approved": False,
        "request_id": str(esc_req["id"]),
        "message": "Escalation request submitted. Awaiting admin approval.",
    })


@bp.route("/api/agent/escalation-poll", methods=["POST"])
@agent_auth_required
def escalation_poll():
    """
    Agent polls for escalation approval status.
    Body: {"request_id": "uuid"}
    """
    body = request.get_json(silent=True) or {}
    req_id = body.get("request_id", "").strip()
    if not req_id:
        return jsonify({"error": "missing_request_id"}), 400

    esc = db.get_escalation_request(req_id)
    if not esc or str(esc["endpoint_id"]) != str(g.endpoint["id"]):
        return jsonify({"error": "not_found"}), 404

    # escalation_token stored as SHA-256 hash — cannot return it as-is.
    # The plaintext token was returned directly from approve_escalation() at approval time.
    # Poll endpoint confirms approval status only; token was delivered via the approval flow.
    return jsonify({
        "status": esc["status"],
        "approved": esc["status"] == "approved",
    })


@bp.route("/api/agent/file-content", methods=["POST"])
@agent_auth_required
def file_content():
    """
    Agent posts the result of a FILE_PULL or CAPTURE_PACKETS job.
    Body: {"job_id": "uuid", "path": "C:\\...", "content_b64": "<base64>", "size_bytes": 1234}
    Content is stored on the job record as structured output.
    """
    body = request.get_json(silent=True) or {}
    job_id = body.get("job_id", "").strip()
    if not job_id:
        return jsonify({"error": "missing job_id"}), 400

    job = db.get_job(job_id)
    if (not job or str(job["endpoint_id"]) != str(g.endpoint["id"])
            or job.get("type") not in {"FILE_PULL", "CAPTURE_PACKETS"}):
        return jsonify({"error": "not_found"}), 404

    content_b64 = body.get("content_b64")
    size_bytes = body.get("size_bytes")
    if not isinstance(content_b64, str) or len(content_b64) > (8 * 1024 * 1024 * 4 // 3 + 8):
        return jsonify({"error": "file_too_large"}), 413
    if not isinstance(size_bytes, int) or size_bytes < 0 or size_bytes > 8 * 1024 * 1024:
        return jsonify({"error": "invalid_size"}), 400
    try:
        decoded = base64.b64decode(content_b64, validate=True)
    except (ValueError, TypeError):
        return jsonify({"error": "invalid_content"}), 400
    if len(decoded) != size_bytes:
        return jsonify({"error": "size_mismatch"}), 400
    if job.get("type") == "CAPTURE_PACKETS" and (
            len(decoded) < 4 or decoded[:4] != b"\x0a\x0d\x0d\x0a"):
        return jsonify({"error": "invalid_pcapng"}), 400

    import json as _json
    finished = db.finish_running_job(
        job_id, "completed",
        log_output=_json.dumps({
            "path":        body.get("path"),
            "download_name": body.get("download_name"),
            "content_b64": content_b64,
            "size_bytes":  size_bytes,
        }),
        exit_code=0,
    )
    return jsonify({"ok": True, "duplicate": not finished})


@bp.route("/api/agent/event-logs", methods=["POST"])
@agent_auth_required
def event_logs():
    """
    Agent posts the result of a GET_EVENT_LOGS job.
    Body: {"job_id": "uuid", "log_name": "System", "events_json": "[...]"}
    """
    body = request.get_json(silent=True) or {}
    job_id = body.get("job_id", "").strip()
    if not job_id:
        return jsonify({"error": "missing job_id"}), 400

    job = db.get_job(job_id)
    if (not job or str(job["endpoint_id"]) != str(g.endpoint["id"])
            or job.get("type") != "GET_EVENT_LOGS"):
        return jsonify({"error": "not_found"}), 404

    import json as _json
    events_raw = body.get("events_json", "[]")
    try:
        events = _json.loads(events_raw) if isinstance(events_raw, str) else events_raw
        count = len(events) if isinstance(events, list) else 0
    except Exception:
        events = []
        count = 0

    finished = db.finish_running_job(
        job_id, "completed",
        log_output=_json.dumps({
            "log_name": body.get("log_name"),
            "count":    count,
            "events":   events,
        }),
        exit_code=0,
    )
    return jsonify({"ok": True, "duplicate": not finished})


@bp.route("/api/agent/compliance-result", methods=["POST"])
@agent_auth_required
def compliance_result():
    """
    Agent submits the result of a COMPLIANCE_SCAN job.
    Body: {
        "job_id": "uuid",
        "policy_id": "uuid or null",
        "overall_status": "compliant|non_compliant|error",
        "score": 85,
        "results": [{"check": "bitlocker_enabled", "status": "pass", "detail": "..."}]
    }
    """
    body = request.get_json(silent=True) or {}
    endpoint = g.endpoint

    overall_status = body.get("overall_status", "error")
    if overall_status not in ("compliant", "non_compliant", "error"):
        overall_status = "error"

    db.upsert_compliance_result(
        endpoint_id=endpoint["id"],
        company_id=endpoint["company_id"],
        policy_id=body.get("policy_id"),
        overall_status=overall_status,
        score=body.get("score", 0),
        results=body.get("results", []),
    )

    # Auto-create alert if non-compliant
    if overall_status == "non_compliant":
        score = body.get("score", 0)
        if not db.get_open_alert(endpoint["id"], "compliance_failure"):
            db.create_alert(
                company_id=endpoint["company_id"],
                branch_id=endpoint.get("branch_id"),
                endpoint_id=endpoint["id"],
                alert_type="compliance_failure",
                severity="warning",
                title=f"Compliance failure on {endpoint['hostname']}",
                message=f"Compliance score: {score}/100",
                detail={"results": body.get("results", [])},
            )
    elif overall_status == "compliant":
        # Auto-resolve any open compliance alert
        alert = db.get_open_alert(endpoint["id"], "compliance_failure")
        if alert:
            db.resolve_alert(alert["id"], None, "Endpoint returned to compliance")

    db.log_endpoint_event(endpoint["id"], "compliance_scan_completed", {
        "overall_status": overall_status,
        "score": body.get("score"),
    })

    return jsonify({"ok": True})


@bp.route("/api/agent/latest-exe")
@agent_auth_required
def latest_exe():
    """
    Serves the raw warden-agent.exe from the most recently completed agent
    build — the file an UPDATE_AGENT job's download_url points at (see
    routes/endpoints.py's dispatch_job and agent-go/commands.go's
    updateAgent()). Agent-authenticated (X-Agent-Key) rather than public:
    this is a full agent binary that gets executed as a privileged Windows
    service, so it gets the same auth bar as every other agent endpoint,
    not just "unguessable URL."

    The compiled exe is byte-identical across builds (only
    config.json differs per build, not the binary — see
    db.get_latest_completed_build()'s docstring), so it's safe to serve
    the single latest completed build to any authenticated endpoint
    regardless of which enrollment profile requested it.
    """
    target_platform = db.endpoint_target_platform(g.endpoint)
    build = db.get_latest_completed_build(target_platform)
    if not build:
        abort(404)

    dest_dir = config.AGENT_DIST_DIR / str(build["id"])
    zip_path = dest_dir / "agent-installer.zip"
    if not zip_path.exists():
        abort(404)

    with zipfile.ZipFile(str(zip_path)) as zf:
        binary_name = "warden-agent.exe" if target_platform.startswith("windows-") else "warden-agent"
        exe_bytes = zf.read(binary_name)

    return send_file(
        io.BytesIO(exe_bytes),
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name="warden-agent.exe" if target_platform.startswith("windows-") else "warden-agent",
    )


def _send_versioned_update_artifact(build_id, kind):
    try:
        build = build_for_endpoint(str(build_id), g.endpoint)
        stream, filename = as_download(build, kind)
    except AgentBuildUnavailable:
        abort(404)
    response = send_file(
        stream,
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=filename,
    )
    response.headers["Cache-Control"] = "private, no-store"
    return response


@bp.route("/api/agent/builds/<uuid:build_id>/agent")
@agent_auth_required
def versioned_agent_artifact(build_id):
    """Serve the exact agent build named in a signed update job."""
    return _send_versioned_update_artifact(build_id, "agent")


@bp.route("/api/agent/builds/<uuid:build_id>/credential-provider")
@agent_auth_required
def versioned_credential_provider(build_id):
    """Serve the build-paired, signed Windows Credential Provider DLL."""
    return _send_versioned_update_artifact(build_id, "credential_provider")


@bp.route("/api/agent/apps/<app_id>/download")
@agent_auth_required
def download_app(app_id):
    """Serves an app-library installer to the agent for an INSTALL_APP job's
    app_url (see routes/endpoints.py's dispatch_job and agent-go/commands.go's
    installApp()). Agent-authenticated (X-Agent-Key) — the agent has no
    browser session to present, so it can't use routes/apps.py's
    login_required download route; this is the agent-facing equivalent,
    scoped to the calling endpoint's own company (or a global app)."""
    import pathlib
    from flask import send_from_directory

    app = db.get_app(app_id)
    if not app:
        abort(404)
    if app.get("company_id") and str(app["company_id"]) != str(g.endpoint["company_id"]):
        abort(403)

    file_path = config.UPLOAD_DIR / app["file_path"]
    if not file_path.exists():
        abort(404)

    return send_from_directory(str(file_path.parent), file_path.name, as_attachment=True)


@bp.route("/api/agent/self-service/apps", methods=["GET"])
@agent_auth_required
def self_service_apps():
    """Catalog consumed by the agent tray/self-service client. Only apps an
    administrator explicitly published are returned; installer paths and
    storage details never leave the control plane."""
    import pathlib
    platform = str(g.endpoint.get("platform") or "windows").lower()
    allowed = {"windows": {".exe", ".msi"}, "linux": {".deb", ".rpm"}, "darwin": {".pkg"}}
    rows = []
    for app in db.get_app_library(g.endpoint["company_id"]):
        ext = pathlib.Path(app.get("file_path") or "").suffix.lower()
        if app.get("self_service") and ext in allowed.get(platform, set()):
            rows.append({
                "id": str(app["id"]), "name": app.get("name"),
                "version": app.get("version"), "description": app.get("description"),
                "size_bytes": app.get("size_bytes"),
            })
    return jsonify({"apps": rows})


@bp.route("/api/agent/self-service/apps/<app_id>/install", methods=["POST"])
@agent_auth_required
def request_self_service_install(app_id):
    import pathlib
    app = db.get_app(app_id)
    endpoint = g.endpoint
    if not app or not app.get("self_service"):
        abort(404)
    if app.get("company_id") and str(app.get("company_id")) != str(endpoint["company_id"]):
        abort(404)
    platform = str(endpoint.get("platform") or "windows").lower()
    ext = pathlib.Path(app.get("file_path") or "").suffix.lower()
    compatible = {"windows": {".exe", ".msi"}, "linux": {".deb", ".rpm"}, "darwin": {".pkg"}}
    if ext not in compatible.get(platform, set()):
        return jsonify({"error": "app_not_compatible"}), 409
    from services.entitlements import check_job
    decision = check_job(endpoint["company_id"], "INSTALL_APP")
    if not decision.allowed:
        return jsonify({"error": decision.code, "message": decision.message}), 403
    job = db.create_job(endpoint["company_id"], endpoint.get("branch_id"), endpoint["id"], "INSTALL_APP", {
        "app_url": f"{config.SERVER_URL}/api/agent/apps/{app_id}/download",
        "sha256": app["sha256"], "ext": ext, "install_args": app.get("install_args") or "",
        "self_service": True,
    }, None)
    db.log_endpoint_event(endpoint["id"], "self_service_app_requested", {
        "app_id": app_id, "name": app.get("name"), "job_id": str(job.get("id")) if job else None,
    })
    return jsonify({"ok": True, "job_id": str(job["id"]) if job else None}), 202
