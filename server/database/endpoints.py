"""Endpoints database operations."""


def get_endpoints(company_id, branch_id=None, *, sort_names=True):
    import db as _db
    path = f"endpoints?company_id=eq.{_db._q(company_id)}&is_active=eq.true&order=id.asc"
    if branch_id:
        path += f"&branch_id=eq.{_db._q(branch_id)}"
    company = _db.get_company_by_id(company_id)
    rows = [_db._decrypt_endpoint(row, company) for row in _db._get_all(path)]
    return sorted(rows, key=lambda row: str(row.get("display_name") or row.get("hostname") or "").casefold()) if sort_names else rows

def get_asset_register(company_id, branch_id=None):
    """Return active and historical devices so retirement never erases the
    asset ledger or its warranty/assignment record."""
    import db as _db
    path = f"endpoints?company_id=eq.{_db._q(company_id)}&order=id.asc"
    if branch_id:
        path += f"&branch_id=eq.{_db._q(branch_id)}"
    company = _db.get_company_by_id(company_id)
    rows = [_db._decrypt_endpoint(row, company) for row in _db._get_all(path)]
    return sorted(rows, key=lambda row: str(row.get("display_name") or row.get("hostname") or "").casefold())

def get_endpoint(endpoint_id):
    import db as _db
    rows = _db._get(f"endpoints?id=eq.{_db._q(endpoint_id)}&limit=1")
    return _db._decrypt_endpoint(rows[0]) if rows else None

def get_endpoint_recovery_keys(endpoint_id, current_only=False):
    import db as _db
    path = (
        f"endpoint_recovery_keys?endpoint_id=eq.{_db._q(endpoint_id)}"
        "&select=id,company_id,endpoint_id,volume_mount,protector_id,volume_status,"
        "protection_status,encryption_percentage,is_current,escrowed_at,last_reported_at"
    )
    if current_only:
        path += "&is_current=eq.true"
    return _db._get(path + "&order=escrowed_at.desc")

def update_endpoint_recovery_status(company_id, endpoint_id, key_id, volume_status,
                                    protection_status, encryption_percentage, collected_at):
    # A status refresh must not touch the encrypted recovery password, escrow
    # time or current/retired flags. Timestamp fencing rejects delayed reports.
    import db as _db
    return _db._patch(
        f"endpoint_recovery_keys?id=eq.{_db._q(key_id)}&company_id=eq.{_db._q(company_id)}"
        f"&endpoint_id=eq.{_db._q(endpoint_id)}&is_current=eq.true"
        f"&last_reported_at=lt.{_db._q(collected_at)}",
        {"volume_status": volume_status, "protection_status": protection_status,
         "encryption_percentage": encryption_percentage, "last_reported_at": collected_at},
    )

def escrow_endpoint_recovery_key(company, endpoint_id, volume_mount, protector_id,
                                 recovery_password, volume_status=None,
                                 protection_status=None, encryption_percentage=None):
    """Atomically store tenant-encrypted material and retire older keys."""
    import db as _db
    encrypted = _db.encrypt_field(company, recovery_password, "bitlocker.recovery-password")
    rows = _db._rpc("upsert_endpoint_recovery_key", {
        "p_company_id": company["id"], "p_endpoint_id": endpoint_id,
        "p_volume_mount": volume_mount, "p_protector_id": protector_id,
        "p_recovery_password_encrypted": encrypted,
        "p_volume_status": volume_status, "p_protection_status": protection_status,
        "p_encryption_percentage": encryption_percentage,
    })
    return rows[0] if isinstance(rows, list) and rows else rows

def reveal_endpoint_recovery_key(company, recovery_key_id):
    import db as _db
    rows = _db._get(
        f"endpoint_recovery_keys?id=eq.{_db._q(recovery_key_id)}"
        f"&company_id=eq.{_db._q(company['id'])}&limit=1"
    )
    if not rows:
        return None
    row = rows[0]
    row["recovery_password"] = _db.decrypt_field(
        company, row.pop("recovery_password_encrypted"), "bitlocker.recovery-password"
    )
    return row

def get_endpoint_by_api_key_hash(key_hash):
    import db as _db
    rows = _db._get(f"endpoints?api_key_hash=eq.{_db._q(key_hash)}&is_active=eq.true&limit=1")
    return _db._decrypt_endpoint(rows[0]) if rows else None

def retire_endpoint(endpoint_id, clear_cloudflare_cert_id=True):
    """Remove an uninstalled endpoint from the active fleet while preserving
    its jobs, events and audit history.  is_active=false also invalidates the
    agent API key because agent authentication only accepts active endpoints.
    """
    import db as _db
    fields = {
        "is_active": False,
        "status": "offline",
        "client_cert_fingerprint": None,
    }
    # Retain the external ID when Cloudflare deletion failed so an operator
    # can retry revocation; it is not used for app-level authentication.
    if clear_cloudflare_cert_id:
        fields["cloudflare_cert_id"] = None
    _db._patch(f"endpoints?id=eq.{_db._q(endpoint_id)}", fields)

def close_endpoint_work(endpoint_id, actor_id=None):
    """Close work that can no longer complete after an endpoint is retired."""
    import db as _db
    now = _db._now_iso()
    company = _db._endpoint_company(endpoint_id)
    _db._patch(
        f"jobs?endpoint_id=eq.{_db._q(endpoint_id)}&status=in.(pending,approved,running)",
        {"status": "cancelled", "completed_at": now},
    )
    _db._patch(
        f"alerts?endpoint_id=eq.{_db._q(endpoint_id)}&is_resolved=eq.false",
        {"is_resolved": True, "resolved_by": actor_id, "resolved_at": now,
         "resolution_note": _db._endpoint_encrypt(
             company, "alert.resolution_note",
             "Endpoint was removed from Warden",
         )},
    )

def create_endpoint(company_id, branch_id, hostname, api_key_hash,
                    vpn_ip=None, wg_pubkey=None, hardware_id=None,
                    installation_id=None, enrollment_token_id=None,
                    enrollment_profile_id=None, device_identity=None):
    import db as _db
    company = _db.get_company_by_id(company_id)
    data = _db._encrypt_endpoint_fields(company, {
        "company_id":   company_id,
        "branch_id":    branch_id,
        "hostname":     hostname,
        "api_key_hash": api_key_hash,
        "status":       "offline",
        "enrolled_at":  _db._now_iso(),
    })
    if vpn_ip:
        data["vpn_ip"] = str(vpn_ip)
    if wg_pubkey:
        data["wg_pubkey"] = wg_pubkey
    if hardware_id:
        data.update(_db._encrypt_endpoint_fields(company, {"hardware_id": hardware_id}))
    if installation_id:
        data.update(_db._encrypt_endpoint_fields(company, {"installation_id": installation_id}))
    if enrollment_token_id:
        data["enrollment_token_id"] = enrollment_token_id
    if enrollment_profile_id:
        data["enrollment_profile_id"] = enrollment_profile_id
    if device_identity:
        data.update(_db._encrypt_endpoint_fields(company, {"device_identity": device_identity}))
    rows = _db._post("endpoints", data)
    row = rows[0] if (rows and isinstance(rows, list)) else rows
    return _db._decrypt_endpoint(row, company)

def get_endpoint_by_installation_id(company_id, installation_id):
    import db as _db
    company = _db.get_company_by_id(company_id)
    lookup = _db.blind_index(company, installation_id, "endpoint.installation-id")
    rows = _db._get(
        f"endpoints?company_id=eq.{_db._q(company_id)}"
        f"&installation_id_hash=eq.{_db._q(lookup)}&limit=1"
    )
    return _db._decrypt_endpoint(rows[0], company) if rows else None

def get_endpoint_by_hardware_id(company_id, hardware_id):
    import db as _db
    if not hardware_id:
        return None
    company = _db.get_company_by_id(company_id)
    lookup = _db.blind_index(company, hardware_id, "endpoint.hardware-id")
    rows = _db._get(
        f"endpoints?company_id=eq.{_db._q(company_id)}"
        f"&hardware_id_hash=eq.{_db._q(lookup)}&order=created_at.desc&limit=1"
    )
    return _db._decrypt_endpoint(rows[0], company) if rows else None

def recover_endpoint_enrollment(endpoint_id, hostname, api_key_hash):
    import db as _db
    company = _db._endpoint_company(endpoint_id)
    rows = _db._patch(
        f"endpoints?id=eq.{_db._q(endpoint_id)}&is_active=eq.true",
        {**_db._encrypt_endpoint_fields(company, {"hostname": hostname}),
         "api_key_hash": api_key_hash},
    )
    return _db._decrypt_endpoint(rows[0], company) if rows else None

def reenroll_endpoint(endpoint_id, branch_id, hostname, api_key_hash,
                      hardware_id, enrollment_token_id, enrollment_profile_id=None,
                      device_identity=None, installation_id=None):
    """Re-enrol an existing installation in place.

    Manual retirement keeps the historical row and installation identity.
    Manual installer upgrades also keep that same identity. Reusing the row
    avoids a duplicate endpoint and the unique-installation-id collision while
    still requiring a fresh, tenant-scoped enrolment token.
    """
    import db as _db
    company = _db._endpoint_company(endpoint_id)
    data = _db._encrypt_endpoint_fields(company, {
        "branch_id": branch_id,
        "hostname": hostname,
        "api_key_hash": api_key_hash,
        "hardware_id": hardware_id or None,
        "enrollment_token_id": enrollment_token_id,
        "is_active": True,
        "status": "offline",
        "enrolled_at": _db._now_iso(),
        "client_cert_fingerprint": None,
        "cloudflare_cert_id": None,
        "enrollment_profile_id": enrollment_profile_id,
        "device_identity": device_identity or {},
    })
    if installation_id:
        data.update(_db._encrypt_endpoint_fields(company, {"installation_id": installation_id}))
    rows = _db._patch(
        f"endpoints?id=eq.{_db._q(endpoint_id)}",
        data,
    )
    return _db._decrypt_endpoint(rows[0], company) if rows else None

def set_endpoint_client_cert(endpoint_id, fingerprint, cloudflare_cert_id):
    """Record a newly-issued mTLS client cert's fingerprint + Cloudflare
    cert ID (see services/agent_ca.py). Requires
    migrations/2026-07-30-add-client-cert-fields.sql applied first."""
    import db as _db
    _db._patch(f"endpoints?id=eq.{_db._q(endpoint_id)}", {
        "client_cert_fingerprint": fingerprint,
        "cloudflare_cert_id": cloudflare_cert_id,
    })

def rotate_endpoint_client_cert(endpoint, fingerprint, reference, presented_fingerprint=None):
    """CAS rotation; old certificate stays usable for a response-loss retry."""
    import db as _db
    current = endpoint.get("client_cert_fingerprint")
    query = f"endpoints?id=eq.{_db._q(endpoint['id'])}&client_cert_fingerprint="
    query += "eq." + _db._q(current) if current else "is.null"
    retry = bool(presented_fingerprint and presented_fingerprint == endpoint.get("previous_client_cert_fingerprint"))
    rows = _db._patch(query, {
        "client_cert_fingerprint": fingerprint,
        "cloudflare_cert_id": reference,
        "previous_client_cert_fingerprint": endpoint.get("previous_client_cert_fingerprint") if retry else current,
        "previous_client_cert_expires_at": endpoint.get("previous_client_cert_expires_at") if retry else (_db.datetime.now(_db.timezone.utc) + _db.timedelta(hours=24)).isoformat() if current else None,
    })
    return bool(rows)

def clear_endpoint_client_cert(endpoint_id):
    """Clear a revoked endpoint's stored fingerprint — combine with
    services.agent_ca.revoke_agent_cert(cloudflare_cert_id) to also delete
    it from Cloudflare; clearing only the local fingerprint fails our own
    cross-check but doesn't stop Cloudflare's edge from still accepting the
    cert on its own."""
    import db as _db
    _db._patch(f"endpoints?id=eq.{_db._q(endpoint_id)}", {
        "client_cert_fingerprint": None,
        "cloudflare_cert_id": None,
        "previous_client_cert_fingerprint": None,
        "previous_client_cert_expires_at": None,
    })

def update_endpoint_heartbeat(endpoint_id, cpu_pct, ram_used_pct, disk_free_gb, agent_version=None,
                              agent_memory_mb=None, agent_uptime_sec=None, last_seen_ip=None,
                              local_ip=None, device_type=None, platform=None,
                              capabilities=None, capability_details=None,
                              interactive_user_marker=False, interactive_user=None,
                              net_sent_mbps=None, net_recv_mbps=None, topology_telemetry=None):
    import db as _db
    company = _db._endpoint_company(endpoint_id)
    data = {
        "status": "online",
        "last_seen": _db._now_iso(),
    }
    if cpu_pct is not None:
        data["cpu_pct"] = cpu_pct
    if ram_used_pct is not None:
        data["ram_used_pct"] = ram_used_pct
    if disk_free_gb is not None:
        data["disk_free_gb"] = disk_free_gb
    if agent_version:
        data["agent_version"] = agent_version
    if agent_memory_mb is not None:
        data["agent_memory_mb"] = agent_memory_mb
    if agent_uptime_sec is not None:
        data["agent_uptime_sec"] = agent_uptime_sec
    if net_sent_mbps is not None:
        data["net_sent_mbps"] = net_sent_mbps
    if net_recv_mbps is not None:
        data["net_recv_mbps"] = net_recv_mbps
    if isinstance(topology_telemetry, dict):
        data.update(_db._encrypt_endpoint_fields(
            company, {"topology_telemetry": topology_telemetry},
        ))
    if last_seen_ip:
        # Requires migrations/2026-07-30-add-last-seen-ip.sql applied to the
        # live DB first — PostgREST will reject the whole PATCH with an
        # unknown-column error otherwise, so deploy the migration before
        # this code.
        data["last_seen_ip"] = _db._endpoint_encrypt(company, "last_seen_ip", last_seen_ip)
    if local_ip:
        data["local_ip"] = _db._endpoint_encrypt(company, "local_ip", local_ip)
    if device_type in {"desktop", "laptop", "server", "iot", "unknown"}:
        data["device_type"] = device_type
    if platform in {"windows", "linux", "darwin", "unknown"}:
        data["platform"] = platform
    if isinstance(capabilities, list):
        data["capabilities"] = capabilities
    if isinstance(capability_details, dict):
        data.update(_db._encrypt_endpoint_fields(
            company, {"capability_details": capability_details},
        ))
    if interactive_user_marker:
        data["interactive_user"] = _db._endpoint_encrypt(
            company, "interactive_user", interactive_user,
        ) if interactive_user else None
        data["interactive_session_seen_at"] = _db._now_iso()
    data["private_data_encryption_version"] = 1
    if _db.config.ENCRYPT_HEARTBEAT_TELEMETRY:
        from flask import g, has_request_context
        previous = g.get("endpoint") if has_request_context() else None
        if not isinstance(previous, dict) or str(previous.get("id")) != str(endpoint_id):
            previous = _db.get_endpoint(endpoint_id) or {}
        metrics = {field: previous[field] for field in _db._HEARTBEAT_METRIC_FIELDS if field in previous}
        metrics.update({field: data[field] for field in _db._HEARTBEAT_METRIC_FIELDS if field in data})
        data["heartbeat_encrypted"] = _db._endpoint_encrypt(company, "heartbeat", metrics)
        # Do not leave a readable duplicate alongside the encrypted snapshot.
        data.update({field: None for field in _db._HEARTBEAT_METRIC_FIELDS})
    _db._patch(f"endpoints?id=eq.{_db._q(endpoint_id)}", data)

def update_endpoint_sysinfo(endpoint_id, info):
    import db as _db
    company = _db._endpoint_company(endpoint_id)
    data = {
        "os_name": info.get("os_name"),
        "os_version": info.get("os_version"),
        "os_build": info.get("os_build"),
        "os_edition": info.get("os_edition"),
        "arch": info.get("arch"),
        "cpu_model": info.get("cpu_model"),
        "ram_total_gb": info.get("ram_total_gb"),
        "disk_total_gb": info.get("disk_total_gb"),
        "platform": info.get("platform"),
    }
    filtered = {k: v for k, v in data.items() if v is not None}
    _db._patch(
        f"endpoints?id=eq.{_db._q(endpoint_id)}",
        _db._encrypt_endpoint_fields(company, filtered),
    )

def update_endpoint_hostname(endpoint_id, hostname):
    """Update the mutable device label without changing endpoint identity."""
    import db as _db
    company = _db._endpoint_company(endpoint_id)
    _db._patch(
        f"endpoints?id=eq.{_db._q(endpoint_id)}",
        _db._encrypt_endpoint_fields(company, {"hostname": hostname}),
    )

def update_endpoint_nickname(endpoint_id, nickname):
    import db as _db
    company = _db._endpoint_company(endpoint_id)
    _db._patch(f"endpoints?id=eq.{_db._q(endpoint_id)}",
           _db._encrypt_endpoint_fields(company, {"display_name": nickname or None}))

def set_endpoint_offline(endpoint_id):
    import db as _db
    _db._patch(f"endpoints?id=eq.{_db._q(endpoint_id)}", {"status": "offline"})

def update_endpoint_notes(endpoint_id, notes, tags):
    import db as _db
    company = _db._endpoint_company(endpoint_id)
    _db._patch(
        f"endpoints?id=eq.{_db._q(endpoint_id)}",
        _db._encrypt_endpoint_fields(company, {"notes": notes, "tags": tags}),
    )

def get_topology_floors(company_id, branch_id=None):
    import db as _db
    path = f"topology_floors?company_id=eq.{_db._q(company_id)}&order=building.asc,level_order.asc,name.asc"
    if branch_id:
        path += f"&branch_id=eq.{_db._q(branch_id)}"
    return _db._get(path)

def get_topology_floor(floor_id):
    import db as _db
    rows = _db._get(f"topology_floors?id=eq.{_db._q(floor_id)}&limit=1")
    return rows[0] if rows else None

def create_topology_floor(company_id, branch_id, building, name, level_order, aspect_ratio, created_by):
    import db as _db
    rows = _db._post("topology_floors", {
        "company_id": company_id, "branch_id": branch_id or None,
        "building": building, "name": name, "level_order": level_order,
        "aspect_ratio": aspect_ratio, "created_by": created_by,
    })
    return rows[0] if rows else None

def update_topology_floor(floor_id, company_id, fields):
    import db as _db
    fields = {key: value for key, value in fields.items()
              if key in {"building", "name", "level_order", "aspect_ratio", "layout_locked"}}
    fields["updated_at"] = _db._now_iso()
    rows = _db._patch(f"topology_floors?id=eq.{_db._q(floor_id)}&company_id=eq.{_db._q(company_id)}", fields)
    return rows[0] if rows else None

def delete_topology_floor(floor_id, company_id):
    import db as _db
    _db._delete(f"topology_floors?id=eq.{_db._q(floor_id)}&company_id=eq.{_db._q(company_id)}")

def get_topology_rooms(company_id, floor_id):
    import db as _db
    return _db._get(
        f"topology_rooms?company_id=eq.{_db._q(company_id)}&floor_id=eq.{_db._q(floor_id)}&order=name.asc"
    )

def get_topology_room(room_id):
    import db as _db
    rows = _db._get(f"topology_rooms?id=eq.{_db._q(room_id)}&limit=1")
    return rows[0] if rows else None

def create_topology_room(company_id, floor_id, values):
    import db as _db
    rows = _db._post("topology_rooms", {"company_id": company_id, "floor_id": floor_id, **values})
    return rows[0] if rows else None

def update_topology_room(room_id, company_id, values):
    import db as _db
    fields = {key: value for key, value in values.items()
              if key in {"name", "x", "y", "width", "height", "color", "capacity"}}
    fields["updated_at"] = _db._now_iso()
    rows = _db._patch(f"topology_rooms?id=eq.{_db._q(room_id)}&company_id=eq.{_db._q(company_id)}", fields)
    return rows[0] if rows else None

def delete_topology_room(room_id, company_id):
    import db as _db
    _db._delete(f"topology_rooms?id=eq.{_db._q(room_id)}&company_id=eq.{_db._q(company_id)}")

def get_topology_placements(company_id, floor_id=None):
    import db as _db
    path = (
        "topology_endpoint_placements?select=endpoint_id,company_id,floor_id,room_id,x,y,updated_at"
        f"&company_id=eq.{_db._q(company_id)}"
    )
    if floor_id:
        path += f"&floor_id=eq.{_db._q(floor_id)}"
    return _db._get(path)

def upsert_topology_placement(company_id, floor_id, room_id, endpoint_id, x, y, updated_by):
    import db as _db
    rows = _db._post("topology_endpoint_placements?on_conflict=endpoint_id", {
        "company_id": company_id, "floor_id": floor_id, "room_id": room_id or None,
        "endpoint_id": endpoint_id, "x": x, "y": y,
        "updated_by": updated_by, "updated_at": _db._now_iso(),
    }, prefer="resolution=merge-duplicates,return=representation")
    return rows[0] if rows else None

def delete_topology_placement(company_id, endpoint_id):
    import db as _db
    _db._delete(
        f"topology_endpoint_placements?company_id=eq.{_db._q(company_id)}&endpoint_id=eq.{_db._q(endpoint_id)}"
    )

def get_topology_nodes(company_id, floor_id):
    import db as _db
    return _db._get(
        f"topology_nodes?company_id=eq.{_db._q(company_id)}&floor_id=eq.{_db._q(floor_id)}&order=name.asc"
    )

def get_topology_node(node_id):
    import db as _db
    rows = _db._get(f"topology_nodes?id=eq.{_db._q(node_id)}&limit=1")
    return rows[0] if rows else None

def create_topology_node(company_id, floor_id, values):
    import db as _db
    rows = _db._post("topology_nodes", {"company_id": company_id, "floor_id": floor_id, **values})
    return rows[0] if rows else None

def update_topology_node(node_id, company_id, values):
    import db as _db
    allowed = {"name", "node_type", "ip_address", "details", "room_id", "x", "y"}
    fields = {key: value for key, value in values.items() if key in allowed}
    fields["updated_at"] = _db._now_iso()
    rows = _db._patch(f"topology_nodes?id=eq.{_db._q(node_id)}&company_id=eq.{_db._q(company_id)}", fields)
    return rows[0] if rows else None

def delete_topology_node(node_id, company_id):
    import db as _db
    _db._delete(f"topology_nodes?id=eq.{_db._q(node_id)}&company_id=eq.{_db._q(company_id)}")

def get_topology_links(company_id, floor_id):
    import db as _db
    return _db._get(
        f"topology_links?company_id=eq.{_db._q(company_id)}&floor_id=eq.{_db._q(floor_id)}&order=created_at.asc"
    )

def create_topology_link(company_id, floor_id, values):
    import db as _db
    rows = _db._post("topology_links", {"company_id": company_id, "floor_id": floor_id, **values})
    return rows[0] if rows else None

def get_topology_link(link_id):
    import db as _db
    rows = _db._get(f"topology_links?id=eq.{_db._q(link_id)}&limit=1")
    return rows[0] if rows else None

def delete_topology_link(link_id, company_id):
    import db as _db
    _db._delete(f"topology_links?id=eq.{_db._q(link_id)}&company_id=eq.{_db._q(company_id)}")

def delete_topology_links_for_object(company_id, object_type, object_id):
    import db as _db
    _db._delete(
        f"topology_links?company_id=eq.{_db._q(company_id)}"
        f"&or=(and(source_type.eq.{_db._q(object_type)},source_id.eq.{_db._q(object_id)}),"
        f"and(target_type.eq.{_db._q(object_type)},target_id.eq.{_db._q(object_id)}))"
    )

def get_topology_snapshots(company_id, floor_id, limit=50):
    import db as _db
    return _db._get(
        f"topology_snapshots?company_id=eq.{_db._q(company_id)}&floor_id=eq.{_db._q(floor_id)}"
        f"&select=id,floor_id,captured_at&order=captured_at.desc&limit={min(int(limit), 200)}"
    )

def get_topology_snapshot(snapshot_id, company_id, floor_id):
    import db as _db
    rows = _db._get(
        f"topology_snapshots?id=eq.{_db._q(snapshot_id)}&company_id=eq.{_db._q(company_id)}"
        f"&floor_id=eq.{_db._q(floor_id)}&limit=1"
    )
    return rows[0] if rows else None

def create_topology_snapshot(company_id, floor_id, state):
    import db as _db
    rows = _db._post("topology_snapshots", {
        "company_id": company_id, "floor_id": floor_id, "state": state,
    })
    return rows[0] if rows else None

def prune_topology_snapshots(company_id, floor_id, before):
    import db as _db
    _db._delete(
        f"topology_snapshots?company_id=eq.{_db._q(company_id)}&floor_id=eq.{_db._q(floor_id)}"
        f"&captured_at=lt.{_db._q(before)}"
    )

def update_endpoint_asset(endpoint_id, values):
    import db as _db
    allowed = {"asset_tag", "asset_state", "assigned_to", "purchase_date", "warranty_expiry", "asset_metadata"}
    payload = {key: value for key, value in values.items() if key in allowed}
    company = _db._endpoint_company(endpoint_id)
    payload = _db._encrypt_endpoint_fields(company, payload)
    rows = _db._patch(f"endpoints?id=eq.{_db._q(endpoint_id)}", payload)
    return _db._decrypt_endpoint(rows[0], company) if rows else None

def mark_endpoints_stale(minutes=3):
    import db as _db
    cutoff = (
        _db.datetime.now(_db.timezone.utc) - _db.timedelta(minutes=minutes)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    _db._patch(
        f"endpoints?status=eq.online&last_seen=lt.{_db._q(cutoff)}",
        {"status": "offline"}
    )
