import concurrent.futures
import json
import os
import pathlib
import signal
import socket
import subprocess
import sys
import time
import unittest
import urllib.error
import urllib.request


@unittest.skipUnless(os.name == 'posix', 'Gunicorn deployment test requires Linux')
class GunicornDrainTests(unittest.TestCase):
    def test_sigterm_finishes_inflight_request_and_exits(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        environment = dict(os.environ, HOST='127.0.0.1', PORT=str(port),
                           PYTHONPATH=str(root / 'tests') + os.pathsep + str(root))
        process = subprocess.Popen(
            [sys.executable, '-m', 'gunicorn', '-c', str(root / 'gunicorn.conf.py'), 'gunicorn_smoke_app:app'],
            cwd=root, env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        def get(path):
            with urllib.request.urlopen(f'http://127.0.0.1:{port}' + path, timeout=3) as response:
                return json.load(response)
        try:
            deadline = time.monotonic() + 8
            while True:
                try:
                    get('/ready')
                    break
                except (OSError, urllib.error.URLError):
                    if time.monotonic() >= deadline or process.poll() is not None:
                        self.fail('Isolated Gunicorn did not become ready')
                    time.sleep(.05)
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                pending = executor.submit(get, '/slow')
                deadline = time.monotonic() + 3
                while not get('/ready')['active']:
                    if time.monotonic() >= deadline:
                        self.fail('Slow request did not start')
                    time.sleep(.01)
                process.send_signal(signal.SIGTERM)
                self.assertEqual(pending.result(timeout=4), {'finished': True})
            self.assertEqual(process.wait(timeout=8), 0)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
