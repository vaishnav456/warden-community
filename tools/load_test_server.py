"""Bounded GET-only development load probe. Never enrolls or commands devices."""
import argparse
import collections
import concurrent.futures
import json
import os
import statistics
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

ALLOWED_PATHS = {'/ready', '/dashboard', '/status/json', '/status/queue'}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Never forward authentication to a redirected host.


def run(base_url, path='/ready', requests=100, concurrency=4):
    parsed = urlsplit(base_url)
    if (parsed.scheme not in {'https', 'http'} or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment or parsed.path not in {'', '/'}):
        raise ValueError('Use a server origin without credentials, paths or query strings')
    if parsed.scheme != 'https' and parsed.hostname not in {'localhost', '127.0.0.1', '::1'}:
        raise ValueError('Non-loopback tests require verified HTTPS')
    if path not in ALLOWED_PATHS or not 1 <= requests <= 10000 or not 1 <= concurrency <= 64:
        raise ValueError('Invalid read-only workload or bounds')
    token = os.environ.get('WARDEN_LOAD_TEST_TOKEN')
    def once(_):
        started = time.monotonic()
        request = urllib.request.Request(base_url.rstrip('/') + path,
                                         headers={'Accept': 'application/json'})
        if token:
            request.add_header('Authorization', 'Bearer ' + token)
        status = 'network_error'
        try:
            opener = urllib.request.build_opener(NoRedirect())
            with opener.open(request, timeout=15) as response:
                response.read(1024 * 1024)
                status = str(response.status)
        except urllib.error.HTTPError as error:
            status = str(error.code)
            error.close()
        except (OSError, urllib.error.URLError):
            pass
        return status, time.monotonic() - started
    started = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        results = list(executor.map(once, range(requests)))
    elapsed = time.monotonic() - started
    timings = sorted(item[1] for item in results)
    statuses = collections.Counter(item[0] for item in results)
    return dict(requests=requests, concurrency=concurrency, elapsed_seconds=round(elapsed, 3),
                requests_per_second=round(requests / max(elapsed, .001), 2),
                median_ms=round(statistics.median(timings) * 1000, 2),
                p95_ms=round(timings[min(len(timings)-1, (95*len(timings)-1)//100)] * 1000, 2),
                statuses=dict(statuses), scope='GET-only; excludes heartbeat writes and video traffic')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url', required=True)
    parser.add_argument('--path', default='/ready', choices=sorted(ALLOWED_PATHS))
    parser.add_argument('--requests', type=int, default=100)
    parser.add_argument('--concurrency', type=int, default=4)
    parser.add_argument('--confirm-development', action='store_true')
    args = parser.parse_args()
    if not args.confirm_development:
        parser.error('Explicit --confirm-development is required. Do not load-test production.')
    report = run(args.base_url, args.path, args.requests, args.concurrency)
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report['statuses'].get('200') == args.requests else 1)
