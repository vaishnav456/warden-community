"""
health_tracker.py — In-process health registry for Warden background services.

Each background service calls `ping(name)` once per loop iteration.
The status page reads `get_status()` to display service health.
ws_proxy calls `set_connections(n)` when connections open/close.
"""
import time
import threading

_lock = threading.Lock()

# Registered services, their last-tick timestamps, and expected interval (seconds)
_services: dict[str, dict] = {
    "stale_checker": {"last_tick": None, "ticks": 0, "interval": 60},
    "alert_engine":  {"last_tick": None, "ticks": 0, "interval": 60},
    "scheduler":     {"last_tick": None, "ticks": 0, "interval": 60},
}

_active_connections: int = 0
_start_time: float = time.time()


def ping(service: str) -> None:
    """Called by each background service at the top of every loop iteration."""
    with _lock:
        if service not in _services:
            _services[service] = {"last_tick": None, "ticks": 0, "interval": 60}
        _services[service]["last_tick"] = time.time()
        _services[service]["ticks"] += 1


def set_connections(n: int) -> None:
    """Called by ws_proxy when a connection opens or closes."""
    global _active_connections
    with _lock:
        _active_connections = max(0, n)


def increment_connections() -> None:
    global _active_connections
    with _lock:
        _active_connections += 1


def decrement_connections() -> None:
    global _active_connections
    with _lock:
        _active_connections = max(0, _active_connections - 1)


def get_status() -> dict:
    """Return a snapshot of all service health for the status page."""
    now = time.time()
    with _lock:
        services = []
        for name, info in _services.items():
            last = info["last_tick"]
            if last is None:
                age_sec = None
                healthy = False
            else:
                age_sec = int(now - last)
                # Healthy if ticked within 3× its expected interval
                healthy = age_sec < (info.get("interval", 60) * 3)
            services.append({
                "name": name,
                "last_tick": last,
                "age_sec": age_sec,
                "ticks": info["ticks"],
                "healthy": healthy,
            })
        return {
            "uptime_sec": int(now - _start_time),
            "services": services,
            "active_connections": _active_connections,
        }
