"""Inventory database operations."""


def get_software(endpoint_id, search=None, limit=100, offset=0):
    import db as _db
    path = f"software_inventory?endpoint_id=eq.{_db._q(endpoint_id)}&order=name.asc&limit={limit}&offset={offset}"
    if search:
        path += f"&name=ilike.{_db._q('%' + search + '%')}"
    return _db._get(path)

def replace_software_inventory(endpoint_id, items):
    # One transaction preserves identities and vulnerability review decisions.
    import db as _db
    _db._rpc("replace_software_inventory", {
        "p_endpoint_id": str(endpoint_id), "p_items": items or [],
    })

def replace_patch_inventory(company_id, endpoint_id, items):
    import db as _db
    _db._delete(f"patch_inventory?endpoint_id=eq.{_db._q(endpoint_id)}")
    if items:
        now = _db._now_iso()
        rows = []
        for item in items:
            row = dict(item)
            row.update({"company_id": company_id, "endpoint_id": endpoint_id, "reported_at": now})
            rows.append(row)
        _db._post("patch_inventory", rows, prefer="return=minimal")

def get_patch_inventory(company_id, branch_id=None, *, summary_only=False):
    import db as _db
    path = f"patch_inventory?company_id=eq.{_db._q(company_id)}"
    fields = "endpoint_id" if summary_only else "*"
    if branch_id:
        fields += ",endpoints!inner(branch_id)"
        path += f"&endpoints.branch_id=eq.{_db._q(branch_id)}"
    if summary_only or branch_id:
        path += f"&select={fields}"
    order = "endpoint_id.asc,id.asc" if summary_only else "severity.desc,title.asc,id.asc"
    return _db._get_all(path + f"&order={order}")

def get_patch_policies(company_id):
    import db as _db
    return _db._get(f"patch_policies?company_id=eq.{_db._q(company_id)}&order=name.asc")

def get_patch_policy(policy_id):
    import db as _db
    rows = _db._get(f"patch_policies?id=eq.{_db._q(policy_id)}&limit=1")
    return rows[0] if rows else None

def create_patch_policy(data):
    import db as _db
    rows = _db._post("patch_policies", data)
    return rows[0] if rows else None

def get_patch_deployments(company_id, limit=30):
    import db as _db
    return _db._get(
        f"patch_deployments?company_id=eq.{_db._q(company_id)}"
        f"&select=*,patch_policies(name)&order=created_at.desc&limit={min(int(limit), 100)}"
    )

def create_patch_deployment(company, policy, pilot_ids, broad_ids, payload, created_by):
    import db as _db
    encrypted = _db.encrypt_field(company, payload, "job.payload")
    return _db._rpc("create_patch_deployment", {
        "p_company_id": str(company["id"]), "p_policy_id": str(policy["id"]),
        "p_pilot_ids": [str(item) for item in pilot_ids],
        "p_broad_ids": [str(item) for item in broad_ids],
        "p_encrypted_payload": encrypted, "p_created_by": str(created_by),
    })

def get_due_patch_deployments():
    import db as _db
    return _db._get("patch_deployments?status=in.(pilot,waiting)&broad_at=lte.now()&select=id")

def promote_patch_deployment(deployment_id):
    import db as _db
    return int(_db._rpc("promote_patch_deployment", {"p_deployment_id": str(deployment_id)}) or 0)

def refresh_patch_deployment(job_id, succeeded):
    import db as _db
    return _db._rpc("refresh_patch_deployment", {
        "p_job_id": str(job_id), "p_succeeded": bool(succeeded),
    })

def replace_network_flows(company_id, endpoint_id, flows):
    # Keep a bounded seven-day diagnostic window and cap each observation.
    import db as _db
    cutoff = (_db.datetime.now(_db.timezone.utc) - _db.timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    _db._delete(f"network_flows?endpoint_id=eq.{_db._q(endpoint_id)}&observed_at=lt.{_db._q(cutoff)}")
    rows = []
    for flow in list(flows)[:1000]:
        rows.append({**flow, "company_id": company_id, "endpoint_id": endpoint_id})
    if rows:
        try:
            _db._post("network_flows", rows, prefer="return=minimal")
        except _db.urllib.error.HTTPError as exc:
            # PostgREST's short JSON diagnostic identifies a rejected column
            # without logging the submitted endpoint telemetry itself.
            detail = exc.read(2048).decode("utf-8", errors="replace")
            raise RuntimeError(f"network flow storage rejected: {detail}") from exc

def get_network_flows(company_id, endpoint_id=None, limit=500):
    import db as _db
    path = f"network_flows?company_id=eq.{_db._q(company_id)}&order=observed_at.desc&limit={min(int(limit), 1000)}"
    if endpoint_id:
        path += f"&endpoint_id=eq.{_db._q(endpoint_id)}"
    return _db._get(path)

def get_vulnerability_advisories(limit=5000):
    import db as _db
    return _db._get(f"vulnerability_advisories?order=known_exploited.desc,updated_at.desc&limit={min(int(limit), 10000)}")

def upsert_vulnerability_advisories(rows):
    import db as _db
    if rows:
        return _db._post("vulnerability_advisories?on_conflict=id", rows,
                     prefer="resolution=merge-duplicates,return=minimal")

def replace_vulnerability_findings(company_id, endpoint_id, findings):
    import db as _db
    now = _db._now_iso()
    seen = set()
    existing = _db._get(f"vulnerability_findings?endpoint_id=eq.{_db._q(endpoint_id)}")
    existing_by_key = {
        (str(row.get("software_id")), str(row.get("advisory_id"))): row
        for row in existing
    }
    for item in findings:
        software_id = str(item["software"]["id"])
        advisory_id = str(item["advisory"]["id"])
        key = (software_id, advisory_id)
        seen.add(key)
        row = existing_by_key.get(key)
        fields = {"confidence": item["confidence"], "evidence": item["evidence"], "last_seen": now}
        if row:
            if row.get("status") == "remediated":
                fields.update(status="open", resolved_at=None)
            _db._patch(f"vulnerability_findings?id=eq.{_db._q(row['id'])}", fields)
        else:
            _db._post("vulnerability_findings", {
                **fields, "company_id": company_id, "endpoint_id": endpoint_id,
                "software_id": software_id, "advisory_id": advisory_id,
            }, prefer="return=minimal")
    # Findings absent from the new inventory are remediated, while explicit
    # accepted-risk/false-positive decisions remain untouched.
    for row in existing:
        key = (str(row.get("software_id")), str(row.get("advisory_id")))
        if key not in seen and row.get("status") == "open":
            _db._patch(f"vulnerability_findings?id=eq.{_db._q(row['id'])}", {
                "status": "remediated", "resolved_at": now,
            })

def get_vulnerability_findings(company_id, limit=1000, status=None, endpoint_id=None):
    import db as _db
    status_filter = f"&status=eq.{_db._q(status)}" if status else ""
    endpoint_filter = f"&endpoint_id=eq.{_db._q(endpoint_id)}" if endpoint_id else ""
    rows = _db._get(
        f"vulnerability_findings?company_id=eq.{_db._q(company_id)}"
        f"{status_filter}{endpoint_filter}"
        "&select=*,endpoints(id,hostname,display_name),software_inventory(name,version,publisher),"
        f"vulnerability_advisories(*)&order=first_seen.desc&limit={min(int(limit), 2000)}"
    )
    company = _db.get_company_by_id(company_id)
    for row in rows:
        if row.get("endpoints"):
            row["endpoints"] = _db._decrypt_endpoint(row["endpoints"], company)
    return rows

def get_vulnerability_finding(finding_id):
    import db as _db
    rows = _db._get(f"vulnerability_findings?id=eq.{_db._q(finding_id)}&limit=1")
    return rows[0] if rows else None

def update_vulnerability_finding(finding_id, status):
    import db as _db
    fields = {"status": status}
    fields["resolved_at"] = _db._now_iso() if status in {"remediated", "false_positive"} else None
    rows = _db._patch(f"vulnerability_findings?id=eq.{_db._q(finding_id)}", fields)
    return rows[0] if rows else None
