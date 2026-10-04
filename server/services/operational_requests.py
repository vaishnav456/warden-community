"""Bounded expensive-request admission; agent control traffic is never shed."""
import os
import threading
import time
from flask import g, jsonify, request
from services.lifecycle import stopping
from services.operational_metrics import metrics
from services.load_control import controller


class Admission:
    def __init__(self, capacity=6):
        if not 1 <= capacity <= 1024:
            raise ValueError('Invalid heavy-request capacity')
        self.capacity = capacity
        self.lock = threading.Lock()
        self.active = {}

    def acquire(self, tenant, busy=False):
        tenant = str(tenant)
        with self.lock:
            total = sum(self.active.values())
            own = self.active.get(tenant, 0)
            others = total - own
            if busy or total >= self.capacity:
                return False
            # Idle capacity is borrowable; during contention reserve room for
            # another tenant instead of permitting one to fill every slot.
            if others and own >= max(1, (self.capacity + 1) // 2):
                return False
            self.active[tenant] = own + 1
            return True

    def release(self, tenant):
        with self.lock:
            count = self.active.get(str(tenant), 0)
            if count <= 1:
                self.active.pop(str(tenant), None)
            else:
                self.active[str(tenant)] = count - 1

    def snapshot(self):
        with self.lock:
            return dict(active=sum(self.active.values()), capacity=self.capacity,
                        active_tenants=len(self.active))


admission = Admission(int(os.environ.get('WARDEN_HEAVY_REQUEST_CAPACITY', '6')))


def expensive():
    path = request.path
    if path.startswith(('/api/agent/', '/api/home/', '/api/build/')):
        return False
    return (path.startswith(('/operations/reports/', '/operations/storage/reconciliation'))
            or (request.method == 'POST' and
                (request.mimetype == 'multipart/form-data'
                 or path.endswith(('/bulk', '/deploy', '/export')))))


def install(app):
    @app.before_request
    def operational_admission():
        g.operational_started = time.monotonic()
        # Never use an untrusted tenant header/subdomain as an admission key.
        company = g.get('company')
        if not g.get('admin') or not company or not expensive():
            return
        if stopping.is_set():
            response = jsonify(error='server_draining', message='Server is restarting. Retry shortly.')
            response.status_code = 503
            response.headers['Retry-After'] = '10'
            return response
        if not admission.acquire(company['id'], controller.busy):
            metrics.observe('admission_rejected', 0)
            response = jsonify(error='server_busy', message='Server is busy. Retry shortly.')
            response.status_code = 429
            response.headers['Retry-After'] = '5'
            return response
        g.operational_tenant = str(company['id'])

    @app.after_request
    def operational_response(response):
        started = g.get('load_started', g.get('operational_started'))
        if started is not None:
            # Endpoint names are fixed by the application, unlike raw URLs.
            metrics.observe('http:' + (request.endpoint or 'unmatched'),
                            max(0, time.monotonic() - started), response.status_code >= 500)
            metrics.observe('request_database', g.get('database_seconds', 0))
        return response

    @app.teardown_request
    def operational_release(error):
        tenant = g.pop('operational_tenant', None)
        if tenant is not None:
            admission.release(tenant)
