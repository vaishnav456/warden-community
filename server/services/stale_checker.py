"""
Warden — Background stale checker
Marks endpoints offline when heartbeat stops, expires escalations,
creates offline alerts. Run in a background thread.
"""
import time
import threading
import logging

import db
import config
import services.health_tracker as health_tracker
from services.experience_assets import cleanup_expired

log = logging.getLogger("warden.stale_checker")

_INTERVAL = 60  # seconds
_ENDPOINT_OFFLINE_MINUTES = 3


def _check_once():
    try:
        db.mark_endpoints_stale(_ENDPOINT_OFFLINE_MINUTES)
    except Exception as e:
        log.warning(f"mark_endpoints_stale failed: {e}")

    try:
        db.expire_stale_escalations()
    except Exception as e:
        log.warning(f"expire_stale_escalations failed: {e}")

    try:
        db.cleanup_expired_tokens()
    except Exception:
        pass

    try:
        cleanup_expired(config.UPLOAD_DIR)
    except Exception as e:
        log.warning(f"experience asset cleanup failed: {e}")


def _loop():
    from services.lifecycle import stopping
    while not stopping.wait(_INTERVAL):
        health_tracker.ping("stale_checker")
        _check_once()


def start():
    t = threading.Thread(target=_loop, daemon=True, name="stale-checker")
    t.start()
    log.info("Stale checker started")
