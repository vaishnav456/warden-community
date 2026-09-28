"""
Warden — Background alert engine
Checks endpoint metrics every 60 seconds and auto-creates alerts when
thresholds are breached. Run in a background thread.
"""
import time
import threading
import logging
from datetime import datetime, timezone, timedelta

import db
import services.health_tracker as health_tracker

log = logging.getLogger("warden.alert_engine")

_INTERVAL = 60  # seconds

_DEFAULT_CPU_PCT = 90
_DEFAULT_RAM_PCT = 90
_DEFAULT_DISK_FREE_GB = 5
_DEFAULT_OFFLINE_MINUTES = 5

# ── Connection anomaly thresholds ─────────────────────────────────────────────
# A single IP change or a single TLS cert rotation is routine (laptops move
# networks; CDN/tunnel edge certs are reissued periodically — see
# comms.py's trust-on-first-use re-pin). What's actually anomalous is
# *frequency*: several distinct events in a short window, which a single
# legitimate cause wouldn't produce.
_IP_CHANGE_WINDOW_MINUTES = 60
_IP_CHANGE_ALERT_THRESHOLD = 3   # 3+ ip_changed events within the window
_CERT_ROTATION_WINDOW_HOURS = 24
_CERT_ROTATION_ALERT_THRESHOLD = 2  # 2+ rotations within the window (normal CDN
                                     # rotation cadence is ~every 90 days)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _check_once():
    try:
        thresholds_list = db.get_all_alert_configs()
        companies = db.get_all_companies()
    except Exception as e:
        log.warning("alert_engine: loading companies/alert configs failed: %s", e)
        return

    # A tenant should be protected by the documented defaults before anyone
    # visits Settings and creates an alert_config row. Previously the engine
    # iterated only that table, silently skipping every new/default tenant.
    configs_by_company = {
        str(item.get("company_id")): item
        for item in thresholds_list
        if item.get("company_id")
    }

    for company in companies or []:
        if not company.get("is_active", True):
            continue
        company_id = company["id"]
        t = configs_by_company.get(str(company_id), {})

        # Apply per-company thresholds with defaults for missing/null values
        cpu_pct = t.get("cpu_pct") or _DEFAULT_CPU_PCT
        ram_pct = t.get("ram_pct") or _DEFAULT_RAM_PCT
        disk_free_gb = t.get("disk_free_gb") or _DEFAULT_DISK_FREE_GB
        offline_minutes = t.get("offline_minutes") or _DEFAULT_OFFLINE_MINUTES

        try:
            endpoints = db.get_endpoints_for_alert_check(company_id)
        except Exception as e:
            log.warning("alert_engine: get_endpoints_for_alert_check failed for company %s: %s", company_id, e)
            continue

        for ep in endpoints:
            try:
                _check_endpoint(ep, company_id, cpu_pct, ram_pct, disk_free_gb, offline_minutes)
            except Exception as e:
                log.warning("alert_engine: error checking endpoint %s: %s", ep.get("id"), e)


def _check_endpoint(ep, company_id, cpu_pct, ram_pct, disk_free_gb, offline_minutes):
    endpoint_id = ep["id"]
    branch_id = ep.get("branch_id")
    hostname = ep.get("hostname", endpoint_id)

    # --- Offline check ---
    # Evaluate the tenant's configured threshold against last_seen directly.
    # Endpoint status is maintained by a separate three-minute stale checker;
    # using only that flag made offline_minutes cosmetic (and wrong for every
    # value other than three).
    last_seen = ep.get("last_seen")
    offline_now = ep.get("status") == "offline" and not last_seen
    if last_seen:
        try:
            seen_at = datetime.fromisoformat(str(last_seen).replace("Z", "+00:00"))
            offline_now = datetime.now(timezone.utc) - seen_at > timedelta(minutes=offline_minutes)
        except (TypeError, ValueError):
            offline_now = ep.get("status") == "offline"
    if offline_now:
        if db.get_open_alert(endpoint_id, "endpoint_offline") is None:
            db.create_alert(
                company_id,
                branch_id,
                endpoint_id,
                "endpoint_offline",
                "critical",
                f"{hostname} is offline",
                f"No heartbeat received for more than {offline_minutes} minutes",
            )
    else:
        _resolve_if_open(endpoint_id, "endpoint_offline", "Endpoint is online again")

    # --- High CPU check ---
    ep_cpu = ep.get("cpu_pct")
    if ep_cpu is not None and ep_cpu > cpu_pct:
        if db.get_open_alert(endpoint_id, "high_cpu") is None:
            db.create_alert(
                company_id,
                branch_id,
                endpoint_id,
                "high_cpu",
                "warning",
                f"High CPU on {hostname}",
                f"CPU usage is {ep_cpu}% (threshold: {cpu_pct}%)",
            )
    elif ep_cpu is not None:
        _resolve_if_open(endpoint_id, "high_cpu", "CPU returned below threshold")

    # --- High RAM check ---
    ep_ram = ep.get("ram_used_pct")
    if ep_ram is not None and ep_ram > ram_pct:
        if db.get_open_alert(endpoint_id, "high_ram") is None:
            db.create_alert(
                company_id,
                branch_id,
                endpoint_id,
                "high_ram",
                "warning",
                f"High RAM on {hostname}",
                f"RAM usage is {ep_ram}% (threshold: {ram_pct}%)",
            )
    elif ep_ram is not None:
        _resolve_if_open(endpoint_id, "high_ram", "RAM returned below threshold")

    # --- Low disk check ---
    ep_disk = ep.get("disk_free_gb")
    if ep_disk is not None and ep_disk < disk_free_gb:
        if db.get_open_alert(endpoint_id, "low_disk") is None:
            # Critical if free space is below half the threshold, otherwise warning
            severity = "critical" if ep_disk < disk_free_gb / 2 else "warning"
            db.create_alert(
                company_id,
                branch_id,
                endpoint_id,
                "low_disk",
                severity,
                f"Low disk space on {hostname}",
                f"Free disk space is {ep_disk:.1f} GB (threshold: {disk_free_gb} GB)",
            )
    elif ep_disk is not None:
        _resolve_if_open(endpoint_id, "low_disk", "Disk space returned above threshold")

    _check_connection_anomalies(endpoint_id, company_id, branch_id, hostname)


def _resolve_if_open(endpoint_id, alert_type, note):
    alert = db.get_open_alert(endpoint_id, alert_type)
    if alert:
        db.resolve_alert(alert["id"], None, note)


def _check_connection_anomalies(endpoint_id, company_id, branch_id, hostname):
    """
    Flag suspicious connection *patterns*, not single occurrences — a lone
    IP change or TLS cert rotation is routine (see thresholds above). Builds
    entirely on server/routes/agent_api.py's existing ip_changed and
    tls_cert_rotation_detected endpoint_events; no new data collection, just
    a frequency check over the existing audit trail.
    """
    now = datetime.now(timezone.utc)

    # --- Frequent IP changes ---
    since = _iso(now - timedelta(minutes=_IP_CHANGE_WINDOW_MINUTES))
    try:
        ip_events = db.get_recent_endpoint_events(endpoint_id, "ip_changed", since)
    except Exception as e:
        log.warning("alert_engine: get_recent_endpoint_events(ip_changed) failed for %s: %s", endpoint_id, e)
        ip_events = []
    if len(ip_events) >= _IP_CHANGE_ALERT_THRESHOLD:
        if db.get_open_alert(endpoint_id, "frequent_ip_changes") is None:
            distinct_ips = sorted({e.get("detail", {}).get("new_ip") for e in ip_events if e.get("detail")})
            db.create_alert(
                company_id,
                branch_id,
                endpoint_id,
                "frequent_ip_changes",
                "warning",
                f"{hostname} connected from {len(ip_events)} different IPs recently",
                f"{len(ip_events)} IP changes in the last {_IP_CHANGE_WINDOW_MINUTES} minutes "
                f"(threshold: {_IP_CHANGE_ALERT_THRESHOLD}): {', '.join(filter(None, distinct_ips))}",
            )

    # --- Frequent TLS cert rotations ---
    since = _iso(now - timedelta(hours=_CERT_ROTATION_WINDOW_HOURS))
    try:
        rotation_events = db.get_recent_endpoint_events(endpoint_id, "tls_cert_rotation_detected", since)
    except Exception as e:
        log.warning("alert_engine: get_recent_endpoint_events(tls_cert_rotation_detected) failed for %s: %s", endpoint_id, e)
        rotation_events = []
    if len(rotation_events) >= _CERT_ROTATION_ALERT_THRESHOLD:
        if db.get_open_alert(endpoint_id, "frequent_cert_rotation") is None:
            db.create_alert(
                company_id,
                branch_id,
                endpoint_id,
                "frequent_cert_rotation",
                "critical",
                f"{hostname}'s server TLS certificate rotated unusually often",
                f"{len(rotation_events)} TLS fingerprint rotations detected in the last "
                f"{_CERT_ROTATION_WINDOW_HOURS}h (threshold: {_CERT_ROTATION_ALERT_THRESHOLD}) — "
                f"normal CDN/tunnel cert renewal happens roughly every 90 days, not multiple "
                f"times a day. Each rotation was individually accepted because it passed full "
                f"CA-chain verification (see agent/comms.py), but this frequency is worth "
                f"investigating.",
            )


def _loop():
    while True:
        time.sleep(_INTERVAL)
        health_tracker.ping("alert_engine")
        _check_once()


def start():
    t = threading.Thread(target=_loop, daemon=True, name="alert-engine")
    t.start()
    log.info("Alert engine started")
