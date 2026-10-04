"""Single-process pressure admission; never interrupts existing device traffic."""
import collections
import math
import logging
import os
import threading
import time
from pathlib import Path


class LoadController:
    def __init__(self):
        self.lock = threading.Lock()
        self.pressure = 0.0
        self.busy = False
        self.high_samples = self.low_samples = 0
        self.active_http = 0
        self.http_latency = 0.0
        self.loop_lag = 0.0
        self.cpu = self.memory = 0.0
        self.last_cpu = None
        self.metric_times = collections.OrderedDict()

    def begin_request(self):
        with self.lock:
            self.active_http += 1
        return time.monotonic()

    def end_request(self, started):
        elapsed = max(0.0, time.monotonic() - started)
        with self.lock:
            self.active_http = max(0, self.active_http - 1)
            self.http_latency = max(elapsed, self.http_latency * 0.9)

    def observe(self, cpu=0.0, memory=0.0, lag=0.0):
        # Normalize each signal independently; a saturated relay matters even
        # when overall host CPU remains low. Three high samples enter shedding;
        # ten healthy samples recover, preventing reconnect/admission oscillation.
        values = (cpu / .85, memory / .85, lag / .15)
        if not all(math.isfinite(v) and v >= 0 for v in values):
            return
        with self.lock:
            was_busy = self.busy
            self.loop_lag = lag
            self.cpu, self.memory = cpu, memory
            http = self.http_latency / 1.0
            self.http_latency *= .8  # stale slow requests must decay
            self.pressure = max(*values, http)
            self.high_samples = self.high_samples + 1 if self.pressure >= 1 else 0
            healthy = cpu < .65 and memory < .80 and lag < .075 and http < .5
            self.low_samples = self.low_samples + 1 if healthy else 0
            if self.high_samples >= 3 or memory >= .95:
                self.busy = True
            elif self.low_samples >= 10:
                self.busy = False
            if was_busy != self.busy:
                logging.getLogger("warden.load_control").info(
                    "Adaptive relay admission %s (pressure=%.2f cpu=%.2f memory=%.2f lag=%.3fs)",
                    "paused" if self.busy else "resumed", self.pressure, cpu, memory, lag)

    def sample(self, lag):
        cpu = memory = 0.0
        now = time.monotonic()
        try:
            fields = dict(line.split() for line in Path("/sys/fs/cgroup/cpu.stat").read_text().splitlines())
            usage = int(fields["usage_usec"]) / 1_000_000
            quota, period = Path("/sys/fs/cgroup/cpu.max").read_text().split()
            cores = int(quota) / int(period) if quota != "max" else len(os.sched_getaffinity(0))
            if self.last_cpu is not None:
                old_time, old_usage = self.last_cpu
                cpu = max(0, (usage - old_usage) / max(.001, now - old_time) / max(.01, cores))
            self.last_cpu = now, usage
        except (OSError, ValueError, KeyError, AttributeError, ZeroDivisionError):
            pass  # non-Linux deployments still use HTTP latency and loop lag
        try:
            maximum = Path("/sys/fs/cgroup/memory.max").read_text().strip()
            if maximum != "max":
                memory = int(Path("/sys/fs/cgroup/memory.current").read_text()) / int(maximum)
            else:
                info = dict((k, int(v.split()[0])) for k, v in
                            (line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines()))
                memory = 1 - info["MemAvailable"] / info["MemTotal"]
        except (OSError, ValueError, KeyError, ZeroDivisionError):
            pass
        self.observe(cpu, memory, max(0, lag))

    def reject_remote(self, owners, company_id):
        # No fixed tenant allowance: idle capacity is borrowable. Near pressure,
        # a tenant already using the largest share yields to other tenants.
        with self.lock:
            if self.busy:
                return True
            if self.pressure < .8:
                return False
            counts = collections.Counter(str(owner) for owner in owners)
            own = counts.get(str(company_id), 0)
            return len(counts) > 1 and own > 0 and own >= max(counts.values())

    def allow_metric(self, endpoint_id):
        with self.lock:
            if not self.busy:
                return True
            now = time.monotonic()
            key = str(endpoint_id)
            previous = self.metric_times.get(key)
            if previous is not None and now - previous < 60:
                return False
            self.metric_times[key] = now
            self.metric_times.move_to_end(key)
            while len(self.metric_times) > 10000:
                self.metric_times.popitem(last=False)
            return True

    def snapshot(self):
        with self.lock:
            return dict(pressure=self.pressure, busy=self.busy, active_http=self.active_http,
                        cpu_ratio=self.cpu, memory_ratio=self.memory, loop_lag_seconds=self.loop_lag)


controller = LoadController()
