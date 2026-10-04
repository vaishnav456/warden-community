"""
Gunicorn configuration for Warden server.
Usage:  gunicorn -c gunicorn.conf.py app:app
"""
import os

# Loopback by default (matches the Caddy-fronted deployment, where Caddy is
# the only process able to reach this port). Set HOST=0.0.0.0 only when
# fronted by a reverse proxy on a different host/container (e.g. an nginx
# container reached over a Docker network instead of localhost).
bind = "{}:{}".format(os.environ.get("HOST", "127.0.0.1"), os.environ.get("PORT", "35020"))
# Warden's WebSocket pair registry, scheduler and health trackers are
# deliberately process-local. Multiple preloaded workers neither share that
# registry nor preserve threads created before Gunicorn forks, so the browser
# and agent could never reliably meet in the same relay process. Use one
# threaded worker: HTTP requests remain concurrent while there is exactly one
# owner for background services and the relay registry.
workers = 1
worker_class = "gthread"
threads = 8
worker_connections = 1000
timeout = 120          # allow slow PDF builds and file uploads
keepalive = 5
# An automatic recycle would terminate every live remote session at an
# arbitrary request count. Let the container restart policy handle genuine
# process failures instead.
max_requests = 0
max_requests_jitter = 0

# Logging
loglevel = "info"
accesslog = "-"        # stdout
errorlog = "-"         # stderr
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)sus'

# Process naming
proc_name = "warden-server"

# Import inside the worker so app.py's background threads are created after
# Gunicorn has forked. Threads created by a preloaded master do not survive
# into workers.
preload_app = False

# Graceful restart
graceful_timeout = 30


def post_worker_init(worker):
    from services.lifecycle import install_signal_handlers
    install_signal_handlers()


def worker_exit(server, worker):
    from services.lifecycle import begin_shutdown, wait_for_workers
    begin_shutdown()
    wait_for_workers()
