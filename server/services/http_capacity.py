"""One shared, bounded thread setting for HTTP admission and Gunicorn."""
import os


def http_threads():
    value = int(os.environ.get("WARDEN_HTTP_THREADS", "32"))
    if not 4 <= value <= 128:
        raise ValueError("WARDEN_HTTP_THREADS must be between 4 and 128")
    return value
