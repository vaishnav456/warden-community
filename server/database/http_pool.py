"""Opt-in bounded keep-alive for one trusted database origin; no retries."""
import collections
import http.client
import io
import ssl
import threading
import time
import urllib.error
from urllib.parse import urlsplit


class Response:
    def __init__(self, pool, connection, response):
        self.pool, self.connection, self.response = pool, connection, response
        self.headers, self.status = response.headers, response.status
        self.complete = False
        self.closed = False

    def read(self, amount=None):
        data = self.response.read(amount)
        self.complete = self.response.isclosed()
        return data

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            self.response.close()
        finally:
            self.pool.release(self.connection, self.complete and not self.response.will_close)


class Pool:
    def __init__(self, origin, context, capacity=8):
        parsed = urlsplit(origin)
        if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError('Invalid database origin')
        if not 1 <= capacity <= 32:
            raise ValueError('Invalid connection-pool capacity')
        if parsed.scheme == 'https' and (context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname):
            raise ValueError('Verified TLS is required')
        self.origin = (parsed.scheme, parsed.hostname, parsed.port)
        self.context = context
        self.slots = threading.BoundedSemaphore(capacity)
        self.lock = threading.Lock()
        self.idle = collections.deque()
        self.closed = False

    def open(self, request):
        parsed = urlsplit(request.full_url)
        if (parsed.scheme, parsed.hostname, parsed.port) != self.origin or parsed.fragment or parsed.username or parsed.password:
            raise ValueError('Database pool cannot forward credentials to another origin')
        if not self.slots.acquire(timeout=1):
            raise urllib.error.URLError('Database connection pool busy')
        connection = None
        try:
            with self.lock:
                if self.closed:
                    raise urllib.error.URLError('Database connection pool closed')
                while self.idle:
                    candidate, idle_since = self.idle.pop()
                    if time.monotonic()-idle_since < 30:
                        connection = candidate
                        break
                    candidate.close()
            if connection is None:
                kind = http.client.HTTPSConnection if parsed.scheme == 'https' else http.client.HTTPConnection
                options = {'timeout':15}
                if parsed.scheme == 'https':
                    options['context'] = self.context
                connection = kind(parsed.hostname, parsed.port, **options)
            target = parsed.path or '/'
            if parsed.query:
                target += '?' + parsed.query
            connection.request(request.get_method(), target, body=request.data, headers=dict(request.header_items()))
            response = connection.getresponse()
            if response.status >= 300:
                # Never follow redirects with the service-role credential.
                body = response.read(4096)
                headers, status = response.headers, response.status
                response.close()
                raise urllib.error.HTTPError(request.full_url,status,'Database request failed',headers,io.BytesIO(body))
            return Response(self, connection, response)
        except Exception as error:
            if connection is not None:
                connection.close()
            self.slots.release()
            if isinstance(error, (OSError, http.client.HTTPException)) and not isinstance(error, urllib.error.URLError):
                raise urllib.error.URLError(error) from error
            raise

    def release(self, connection, reusable):
        try:
            with self.lock:
                if reusable and not self.closed:
                    self.idle.append((connection, time.monotonic()))
                else:
                    connection.close()
        finally:
            self.slots.release()

    def close(self):
        with self.lock:
            self.closed = True
            while self.idle:
                self.idle.pop()[0].close()
