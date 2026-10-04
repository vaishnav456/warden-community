"""PostgREST transport with explicit response lifetime and metadata-only counts.

Pooling is opt-in. No retries of writes or changes to authentication,
schema profiles, TLS verification and the existing 15-second timeout.
"""
from contextlib import closing
import re
from urllib.parse import parse_qs, urlsplit
from services.operational_metrics import observe_database
import os
import threading

_NO_BODY = object()
_pool = None
_pool_lock = threading.Lock()


class RowPage(list):
    """A JSON list retaining pagination metadata, without changing callers."""
    def __init__(self, rows, offset=0, total=None):
        super().__init__(rows)
        self.offset = offset
        self.total = total


def _open(path, method, schema, data=_NO_BODY, prefer=None, rpc=False):
    import db
    headers = dict(db._RPC_HEADERS if rpc else db._HEADERS)
    headers['Accept-Profile' if method in ('GET', 'HEAD') else 'Content-Profile'] = schema
    if prefer is not None:
        headers['Prefer'] = prefer
    body = None if data is _NO_BODY else db.json.dumps(data).encode()
    request = db.urllib.request.Request(
        f'{db.config.SUPABASE_URL}/{path}', data=body, method=method, headers=headers,
    )
    if os.environ.get('WARDEN_DB_HTTP_POOL', 'false').lower() == 'true':
        # urllib honors proxy configuration; keep that path rather than
        # silently bypass an operator's configured database proxy.
        if db.urllib.request.getproxies():
            return db.urllib.request.urlopen(request, timeout=15, context=db._SSL_CTX)
        global _pool
        with _pool_lock:
            if _pool is None:
                from database.http_pool import Pool
                _pool = Pool(db.config.SUPABASE_URL, db._SSL_CTX,
                             int(os.environ.get('WARDEN_DB_HTTP_POOL_SIZE', '8')))
        return _pool.open(request)
    return db.urllib.request.urlopen(request, timeout=15, context=db._SSL_CTX)


@observe_database
def _json_request(path, method, schema, data=_NO_BODY, prefer=None, rpc=False, allow_empty=True, page=False):
    import db
    with closing(_open(path, method, schema, data, prefer, rpc)) as response:
        raw = response.read()
        if not raw and allow_empty:
            return None
        result = db.json.loads(raw)
        if page and isinstance(result, list):
            offset = int(parse_qs(urlsplit(path).query).get('offset', ['0'])[0])
            content_range = str(response.headers.get('Content-Range', ''))
            match = re.fullmatch(r'(?:\d+-\d+|\*)/(\d+|\*)', content_range)
            total = int(match[1]) if match and match[1].isdigit() else None
            return RowPage(result, offset, total)
        return result


def get(path, schema='endpt'):
    return _json_request(path, 'GET', schema, allow_empty=False, page=True)


def get_all(path, schema='endpt', *, page_size=500, max_pages=1000):
    """Traverse ordered reads without assuming a short page means the end.

    RowPage preserves actual response metadata; a configured PostgREST cap
    can be smaller than page_size. Plain lists remain supported for injected
    readers. This is a live read, not a transaction-wide snapshot.
    """
    import db
    query = parse_qs(urlsplit(path).query)
    if 'order' not in query or 'limit' in query or 'offset' in query:
        raise ValueError('Paged reads require stable ordering and no existing limit/offset')
    if not 1 <= page_size <= 1000 or not 1 <= max_pages <= 1000:
        raise ValueError('Invalid pagination bounds')
    rows = []
    separator = '&' if '?' in path else '?'
    for _ in range(max_pages):
        page = db._get(f'{path}{separator}limit={page_size}&offset={len(rows)}', schema=schema)
        if not isinstance(page, list):
            raise RuntimeError('Database page was not a list')
        if len(page) > page_size:
            raise RuntimeError('Database ignored pagination limit')
        if not page:
            return rows
        rows.extend(page)
        if isinstance(page, RowPage):
            if page.total is not None and len(rows) >= page.total:
                return rows
        elif len(page) < page_size:
            return rows
    raise RuntimeError('Database pagination safety bound exceeded; refusing partial results')


def post(path, data, schema='endpt', prefer='return=representation'):
    return _json_request(path, 'POST', schema, data, prefer)


def patch(path, data, schema='endpt'):
    if path.startswith('companies?'):
        from flask import g, has_request_context
        if has_request_context():
            g.pop('_db_company_cache', None)
    return _json_request(path, 'PATCH', schema, data)


def rpc(function_name, params, schema='endpt'):
    """Preserve atomic database transactions; never emulate an RPC with writes."""
    return _json_request(f'rpc/{function_name}', 'POST', schema, params, rpc=True)


@observe_database
def delete(path, schema='endpt'):
    with closing(_open(path, 'DELETE', schema)):
        pass


@observe_database
def count(path, schema='endpt'):
    """Exact count without downloading rows or silently accepting pagination."""
    with closing(_open(path, 'HEAD', schema, prefer='count=exact')) as response:
        total = response.headers.get('Content-Range', '').rsplit('/', 1)[-1]
        if not total.isdigit():
            raise RuntimeError('Database count unavailable')
        return int(total)
