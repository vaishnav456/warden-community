"""Cooperative drain: finish current units; do not claim more durable work."""
import signal
import threading
import time

stopping = threading.Event()


def begin_shutdown():
    stopping.set()


def wait_for_workers(timeout=15):
    deadline = time.monotonic() + timeout
    names = {'scheduler', 'stale-checker', 'alert-engine', 'smtp-outbox', 'warden-ws-relay'}
    for thread in threading.enumerate():
        if thread is not threading.current_thread() and thread.name in names:
            thread.join(max(0, deadline - time.monotonic()))


def install_signal_handlers():
    # Called in the Gunicorn worker, after its own signal handlers are installed.
    # Chain them rather than replacing Gunicorn's graceful-exit behavior.
    for number in (signal.SIGTERM, signal.SIGINT, signal.SIGQUIT):
        previous = signal.getsignal(number)
        def handle(signum, frame, previous=previous):
            begin_shutdown()
            if callable(previous):
                previous(signum, frame)
        signal.signal(number, handle)
