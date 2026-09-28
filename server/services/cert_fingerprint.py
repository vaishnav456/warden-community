"""
Fetches the SHA-256 fingerprint of the certificate currently presented by
SERVER_URL's TLS endpoint, live, at call time — used by generate_installer()
so a fresh installer is always pinned to whatever certificate is actually
live right now, instead of a static config value that goes stale every time
Cloudflare rotates its edge cert (~every 90 days) and would otherwise need
manual re-fetching before each installer build.
"""
import hashlib
import socket
import ssl
from urllib.parse import urlparse


def fetch_live_cert_fingerprint(server_url, timeout=10):
    parsed = urlparse(server_url)
    host = parsed.hostname
    port = parsed.port or 443
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
            der_cert = tls_sock.getpeercert(binary_form=True)
    return hashlib.sha256(der_cert).hexdigest()
