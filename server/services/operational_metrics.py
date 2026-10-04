"""Bounded process-local telemetry. Never retain URLs, identities or payloads."""
import functools
import math
import threading
import time

BOUNDS = (.01, .05, .1, .25, .5, 1, 2, 5, 15, 60)


class Metrics:
    def __init__(self):
        self.lock = threading.Lock()
        self.rows = {}

    def observe(self, label, seconds, failed=False):
        if not math.isfinite(seconds) or seconds < 0:
            return
        with self.lock:
            if label not in self.rows and len(self.rows) >= 127:
                label = 'other'
            row = self.rows.setdefault(label, dict(count=0, errors=0, total_seconds=0,
                                                   max_seconds=0, buckets=[0] * (len(BOUNDS) + 1)))
            row['count'] += 1
            row['errors'] += int(bool(failed))
            row['total_seconds'] += seconds
            row['max_seconds'] = max(row['max_seconds'], seconds)
            index = next((i for i, bound in enumerate(BOUNDS) if seconds <= bound), len(BOUNDS))
            row['buckets'][index] += 1

    def snapshot(self):
        with self.lock:
            return {name: {**row, 'buckets': list(row['buckets'])} for name, row in self.rows.items()}


metrics = Metrics()


def observe_database(function):
    @functools.wraps(function)
    def wrapped(*args, **kwargs):
        started = time.monotonic()
        failed = True
        try:
            result = function(*args, **kwargs)
            failed = False
            return result
        finally:
            elapsed = max(0, time.monotonic() - started)
            metrics.observe('database', elapsed, failed)
            from flask import g, has_request_context
            if has_request_context():
                g.database_calls = g.get('database_calls', 0) + 1
                g.database_seconds = g.get('database_seconds', 0) + elapsed
    return wrapped
