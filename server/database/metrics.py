"""Metrics database operations."""


def insert_metric(endpoint_id, cpu_pct, ram_used_pct, disk_free_gb):
    # endpoint_metrics stores disk_free_pct; we omit disk here since the
    # current disk_free_gb is always available on the endpoints row itself.
    import db as _db
    data = {
        "endpoint_id": endpoint_id,
        "cpu_pct": cpu_pct,
        "ram_used_pct": ram_used_pct,
    }
    if _db.config.ENCRYPT_HEARTBEAT_TELEMETRY:
        company = _db._endpoint_company(endpoint_id)
        data["metrics_encrypted"] = _db._endpoint_encrypt(company, "metric", {
            "cpu_pct": cpu_pct, "ram_used_pct": ram_used_pct,
            "disk_free_gb": disk_free_gb,
        })
        data.update(cpu_pct=None, ram_used_pct=None)
    _db._post("endpoint_metrics", data, prefer="return=minimal")

def get_metrics(endpoint_id, hours=24, *, max_points=None):
    import db as _db
    if type(hours) is not int or not 1 <= hours <= 168:
        raise ValueError('Invalid metric time range')
    if max_points is not None and (type(max_points) is not int or not 1 <= max_points <= 1440):
        raise ValueError('Invalid metric sample bound')
    cutoff = (
        _db.datetime.now(_db.timezone.utc) - _db.timedelta(hours=hours)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    path = (
        f"endpoint_metrics?endpoint_id=eq.{_db._q(endpoint_id)}"
        f"&collected_at=gt.{_db._q(cutoff)}&order=collected_at.asc,id.asc"
    )
    company = None
    rows = None
    if max_points is not None:
        company = _db._endpoint_company(endpoint_id)
        if not company:
            raise ValueError('Metric endpoint owner missing')
        try:
            rows = _db._rpc('sample_endpoint_metrics', dict(p_company_id=str(company['id']),
                           p_endpoint_id=str(endpoint_id),p_hours=hours,p_points=max_points))
        except _db.urllib.error.HTTPError as error:
            from services.dashboard_fleet import missing_function
            if not missing_function(error):
                raise
    if rows is None:
        rows = _db._get_all(path)
        if max_points is not None:
            now = _db.datetime.now(_db.timezone.utc)
            start = now - _db.timedelta(hours=hours)
            buckets = {}
            for row in rows:
                seen = _db._parse_dt_iso(row.get('collected_at'))
                if seen and start < seen <= now:
                    bucket = min(max_points-1,int((seen-start).total_seconds()/(hours*3600/max_points)))
                    buckets[bucket] = row
            rows = [buckets[key] for key in sorted(buckets)]
    if not isinstance(rows, list) or (max_points is not None and len(rows) > max_points):
        raise RuntimeError('Invalid metric sample response')
    result = []
    for row in rows or []:
        item = dict(row)
        encrypted = item.pop("metrics_encrypted", None)
        if encrypted:
            company = company or _db._endpoint_company(endpoint_id)
            metrics = _db._endpoint_decrypt(company, "metric", encrypted)
            if not isinstance(metrics, dict):
                raise ValueError("invalid encrypted metrics")
            item.update({key: value for key, value in metrics.items() if key in _db._HEARTBEAT_METRIC_FIELDS})
        result.append(item)
    return result
