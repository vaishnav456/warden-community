"""One process owns BYOK state; threads share the engine's synchronized cache."""
bind = "unix:/run/warden-keys/service.sock"
workers = 1
worker_class = "gthread"
threads = 8
timeout = 30
umask = 0o117  # Unix socket 0660; its directory is owned by UID 10003/GID 10001.
accesslog = None
errorlog = "-"
loglevel = "info"


def on_starting(server):
    import logging
    logging.getLogger("key_service.audit").setLevel(logging.INFO)
