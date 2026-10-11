import os
port = int(os.environ.get("WARDEN_ADMIN_PORT", "35750"))
if not 1024 <= port <= 65535:
    raise RuntimeError("Invalid private admin port")
bind = f"127.0.0.1:{port}"
workers = 1
worker_class = "gthread"
threads = 4
timeout = 300
preload_app = False
accesslog = None
errorlog = "-"
loglevel = "warning"
max_requests = 0
