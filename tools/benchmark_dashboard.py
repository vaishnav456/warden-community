"""Synthetic CPU/query-count benchmark; not an end-to-end capacity test.

Run with PYTHONPATH=server and the normal isolated test environment.
No network, enrollment, device command or production data is used.
"""
import json
import statistics
import time
from datetime import datetime, timezone
from unittest import mock

import db
from services.dashboard_view import prepare_endpoints


def run(size, trials=7):
    now = datetime.now(timezone.utc)
    endpoints = [dict(id=str(index), platform='linux' if index % 3 else 'windows',
                      arch='arm64' if index % 3 == 2 else 'amd64',
                      hostname=f'PC-{index}', display_name=f'Device {index}',
                      status='online', last_seen=now.isoformat(), agent_version='2.6.58')
                 for index in range(size)]
    timings = []
    reads_per_trial = []
    for _ in range(trials):
        with mock.patch.object(db, 'get_latest_completed_build', return_value={'agent_version': '2.6.59'}) as reads:
            start = time.perf_counter()
            rows = prepare_endpoints(endpoints, now=now)
            timings.append((time.perf_counter() - start) * 1000)
        assert len(rows) == size and all(row['_agent_update'] for row in rows)
        reads_per_trial.append(reads.call_count)
    return dict(endpoints=size, trials=trials, median_cpu_ms=round(statistics.median(timings), 2),
                build_reads_per_trial=reads_per_trial, database_and_network='mocked')


if __name__ == '__main__':
    print(json.dumps({'benchmark': 'synthetic dashboard preparation only',
                      'results': [run(size) for size in (1000, 10000)]}, indent=2))
