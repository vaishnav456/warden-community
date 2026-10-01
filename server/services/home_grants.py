"""Short-lived, offline-verifiable Warden Home access grants."""

import base64
import hashlib
import json
import secrets
import time
from datetime import datetime, timezone

from services.signing import sign_canonical_payload
import config


_ONLINE_WINDOW_SECONDS = 7 * 60
_FAILOVER_FENCE_SECONDS = _ONLINE_WINDOW_SECONDS + 15 * 60
# Replica freshness must outlive the writer fence plus one five-minute Home
# Node heartbeat. Otherwise a fully caught-up backup can become ineligible at
# the exact moment it is finally safe to promote.
_REPLICA_FRESH_SECONDS = _FAILOVER_FENCE_SECONDS + 5 * 60


def _b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def issue_home_grant(*, company_id, endpoint_id, identity_id, space_id, node_id,
                     prefix, permissions, max_file_bytes=536870912,
                     quota_bytes=None, ttl_seconds=900,history_days=0):
    now = int(time.time())
    payload = {
        "v": 1, "iss": "warden", "aud": "warden-home-node",
        "company_id": str(company_id), "endpoint_id": str(endpoint_id),
        "identity_id": str(identity_id), "space_id": str(space_id),
        "node_id": str(node_id), "prefix": prefix,
        "max_file_bytes": int(max_file_bytes),
        "quota_bytes": int(quota_bytes) if quota_bytes else 0,
        "history_days":max(0,min(365,int(history_days))),
        "permissions": sorted(set(permissions)), "iat": now,
        "exp": now + max(60, min(int(ttl_seconds), 3600)),
        "nonce": secrets.token_urlsafe(18),
    }
    message = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    signature = sign_canonical_payload(payload)
    return f"{_b64(message)}.{_b64(signature)}"


def issue_replication_grant(*, company_id, source_node_id, target_node_id, space_id, prefix,
                            max_file_bytes=536870912, quota_bytes=None, ttl_seconds=900,history_days=0):
    """Authorize one node to mirror one tenant space to another node."""
    now = int(time.time())
    payload = {
        "v": 1, "iss": "warden", "aud": "warden-home-replication",
        "company_id": str(company_id), "source_node_id": str(source_node_id),
        "node_id": str(target_node_id), "space_id": str(space_id),
        "prefix": prefix.strip("/"), "permissions": ["read", "replicate"],
        "max_file_bytes": int(max_file_bytes),
        "quota_bytes": int(quota_bytes) if quota_bytes else 0,
        "history_days":max(0,min(365,int(history_days))),
        "iat": now, "exp": now + max(60, min(int(ttl_seconds), 3600)),
        "nonce": secrets.token_urlsafe(18),
    }
    message = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return f"{_b64(message)}.{_b64(sign_canonical_payload(payload))}"


def issue_package_grant(endpoint,node,app):
    now=int(time.time())
    payload=dict(v=1,iss='warden',aud='warden-package-cache',company_id=str(endpoint['company_id']),
        endpoint_id=str(endpoint['id']),node_id=str(node['id']),app_id=str(app['id']),
        package_sha256=app['sha256'],max_file_bytes=int(app.get('size_bytes') or 0),
        prefix='packages/'+app['sha256'],permissions=['package'],iat=now,exp=now+900,nonce=secrets.token_urlsafe(18))
    return f"{_b64(json.dumps(payload,sort_keys=True,separators=(',',':')).encode())}.{_b64(sign_canonical_payload(payload))}"


def _seen_age(node, now=None):
    raw = node.get("last_seen")
    if not raw:
        return None
    try:
        seen = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        return ((now or datetime.now(timezone.utc)) - seen).total_seconds()
    except (TypeError, ValueError):
        return None


def _healthy(node, now=None):
    age = _seen_age(node, now)
    return node.get("status") == "online" and age is not None and age <= _ONLINE_WINDOW_SECONDS


def _replica_fresh(node, space_id, now=None):
    capabilities = node.get("capabilities") or {}
    if capabilities.get("replication") is not True:
        return False
    try:
        synced = int((capabilities.get("replication_sync") or {}).get(str(space_id)) or 0)
        current = int((now or datetime.now(timezone.utc)).timestamp())
        return synced > 0 and current - synced <= _REPLICA_FRESH_SECONDS
    except (TypeError, ValueError, OverflowError):
        return False


def active_writer_ids(space, now=None):
    """Resolve writers without allowing overlapping failover grants.

    A failed independent primary is fenced for one full grant lifetime after
    it stops being considered healthy. Active-active is allowed only for
    front ends declaring the same shared storage identity.
    """
    memberships = sorted(space.get("home_space_nodes") or [], key=lambda item: int(item.get("priority") or 100))
    candidates = [item for item in memberships if item.get("role") in {"primary", "failover"}
                  or (not item.get("role") and item.get("writable", False))]
    mode = space.get("availability_mode") or "single"
    if mode == "shared_active_active":
        healthy = [item.get("home_storage_nodes") or {} for item in candidates
                   if _healthy(item.get("home_storage_nodes") or {}, now)]
        clusters = {str(node.get("storage_cluster_id") or "") for node in healthy}
        key_ids = {
            str((node.get("capabilities") or {}).get("encryption_key_id") or "")
            for node in healthy
        }
        if len(clusters) != 1 or "" in clusters or len(key_ids) != 1 or "" in key_ids:
            return []
        return [str(node["id"]) for node in healthy]
    if not candidates:
        return []
    if mode == "single":
        primary = candidates[0].get("home_storage_nodes") or {}
        return [str(primary["id"])] if _healthy(primary, now) else []

    current_id = str(space.get("active_writer_state") or (candidates[0].get("home_storage_nodes") or {}).get("id") or "")
    current = next(((item.get("home_storage_nodes") or {}) for item in candidates
                    if str((item.get("home_storage_nodes") or {}).get("id")) == current_id), None)
    if current and _healthy(current, now):
        return [current_id]
    # Never overlap a newly promoted writer with a still-valid 15-minute
    # grant that may have been issued to the old writer before it vanished.
    if current and (_seen_age(current, now) is not None) and _seen_age(current, now) < _FAILOVER_FENCE_SECONDS:
        return []
    for item in candidates:
        candidate = item.get("home_storage_nodes") or {}
        if (str(candidate.get("id")) != current_id and _healthy(candidate, now)
                and _replica_fresh(candidate, space.get("id"), now)):
            return [str(candidate["id"])]
    return []


def replication_config_for(node, spaces):
    """Return only peers sharing a space and company with this node."""
    result = []
    for space in spaces:
        memberships = space.get("home_space_nodes") or []
        own = next((item for item in memberships if str(item.get("home_storage_nodes", {}).get("id")) == str(node["id"])), None)
        writers = active_writer_ids(space)
        if not own or str(node["id"]) in writers or not writers:
            continue
        template = str(space.get("remote_prefix_template") or "homes/{identity_id}")
        prefix = template.replace("{space_id}", str(space["id"])).split("{")[0].strip("/") or "homes"
        for item in memberships:
            peer = item.get("home_storage_nodes") or {}
            if str(peer.get("id")) not in writers:
                continue
            result.append({
                "space_id": space["id"], "space_name": space["name"],
                "target_node_id": peer["id"], "local_url": peer.get("local_url"),
                "public_url": peer.get("public_url"), "tls_fingerprint": peer.get("tls_fingerprint"),
                "ca_certificate_pem": peer.get("ca_certificate_pem"),
                "connection_mode": peer.get("deployment_mode") or "local",
                "p2p_url": f"https://warden-home-{peer['id']}.internal:9443"
                if peer.get("deployment_mode") == "p2p" else None,
                "stun_urls": config.HOME_P2P_STUN_URLS
                if peer.get("deployment_mode") == "p2p" else [],
                "max_file_bytes": int(space.get("max_file_bytes") or 536870912),
                "quota_bytes": int(space.get("quota_bytes") or 0),
                "history_days":int(space.get('history_days') or 0),
                "prefix": prefix, "grant": issue_replication_grant(
                    company_id=node["company_id"], source_node_id=node["id"],
                    target_node_id=peer["id"], space_id=space["id"], prefix=prefix,
                    max_file_bytes=space.get("max_file_bytes") or 536870912,
                    quota_bytes=space.get("quota_bytes"),
                    history_days=space.get('history_days',0),
                ),
            })
            break
    return result


def reconcile_home_topology(company_id, spaces=None):
    """Persist writer changes and push fresh P2P grants to online endpoints."""
    import db
    spaces = spaces if spaces is not None else db.get_home_spaces(company_id)
    changed = []
    for space in spaces:
        writers = active_writer_ids(space)
        mode = space.get("availability_mode") or "single"
        if mode == "failover" and not writers:
            continue
        state = ",".join(sorted(writers))
        if state == str(space.get("active_writer_state") or ""):
            continue
        db.update_home_space_topology(space["id"], company_id, state or None)
        space["active_writer_state"] = state
        changed.append(str(space["id"]))
    if not changed:
        return 0
    assignments = db.get_home_assignments(company_id)
    endpoints = {str(item["id"]): item for item in db.get_endpoints(company_id)}
    queued = 0
    for identity in db.get_warden_identities(company_id):
        for assignment in identity.get("warden_identity_assignments") or []:
            endpoint = endpoints.get(str(assignment.get("endpoint_id")))
            if assignment.get("status") != "active" or not endpoint or not endpoint.get("is_active", True):
                continue
            home = home_config_for(endpoint, identity, spaces, assignments)
            if not any(str(item.get("id")) in changed for item in home):
                continue
            if db.create_system_job_once(company_id, endpoint.get("branch_id"), endpoint["id"],
                                         "SYNC_WARDEN_HOME", {"username": identity["username"], "refresh": True}):
                queued += 1
    return queued


def assignment_matches(assignment, endpoint, identity):
    scope = assignment.get("scope_type")
    value = str(assignment.get("scope_value") or "")
    if not assignment.get("enabled", True):
        return False
    if scope == "tenant":
        return True
    if scope == "branch":
        return value == str(endpoint.get("branch_id") or "")
    if scope == "tag":
        return value.casefold() in {str(tag).casefold() for tag in endpoint.get("tags") or []}
    if scope == "endpoint":
        return value == str(endpoint.get("id") or "")
    if scope == "identity":
        return value == str(identity.get("id") or "")
    return False


def home_config_for(endpoint, identity, spaces, assignments):
    rank = {"tenant": 1, "tag": 2, "branch": 3, "endpoint": 4, "identity": 5}
    selected = {}
    for item in assignments:
        if assignment_matches(item, endpoint, identity):
            key = str(item["space_id"])
            if key not in selected or rank.get(item.get("scope_type"), 0) > rank.get(selected[key].get("scope_type"), 0):
                selected[key] = item
    result = []
    for space in spaces:
        assignment = selected.get(str(space["id"]))
        if not assignment or not space.get("enabled", True):
            continue
        prefix = str(space.get("remote_prefix_template") or "homes/{identity_id}").format(
            identity_id=identity["id"], username=identity["username"], space_id=space["id"],
        ).strip("/")
        access_mode = assignment.get("access_mode") or "write"
        nodes = []
        preferred = str(assignment.get("preferred_node_id") or "")
        writers = set(active_writer_ids(space))
        def membership_order(item):
            node_id = str(item.get("home_storage_nodes", {}).get("id") or "")
            if (node_id == preferred and
                    (node_id in writers or
                     (access_mode == "read" and _replica_fresh(
                         item.get("home_storage_nodes") or {}, space.get("id"),
                     )))):
                return (0, 0)
            if node_id in writers and space.get("availability_mode") == "shared_active_active":
                seed = f"{endpoint['id']}:{space['id']}:{node_id}".encode()
                return (1, -int.from_bytes(hashlib.sha256(seed).digest()[:8], "big"))
            return (1 if node_id in writers else 2, int(item.get("priority") or 100))
        memberships = sorted(space.get("home_space_nodes") or [], key=membership_order)
        for membership in memberships:
            node = membership.get("home_storage_nodes") or {}
            if node.get("status") == "disabled":
                continue
            effective_writable = str(node.get("id")) in writers
            permissions = ["read"] + (["write", "delete"] if effective_writable and access_mode == "write" else [])
            nodes.append({
                "id": node.get("id"), "name": node.get("name"),
                "connection_mode": node.get("deployment_mode") or "local",
                "p2p_url": f"https://warden-home-{node.get('id')}.internal:9443"
                if node.get("deployment_mode") == "p2p" else None,
                "stun_urls": config.HOME_P2P_STUN_URLS
                if node.get("deployment_mode") == "p2p" else [],
                "local_url": node.get("local_url"), "public_url": node.get("public_url"),
                "tls_fingerprint": node.get("tls_fingerprint"),
                "ca_certificate_pem": node.get("ca_certificate_pem"),
                "require_mtls": bool(node.get("require_mtls", True)),
                "priority": membership.get("priority", 100),
                "writable": effective_writable,
                "grant": issue_home_grant(
                    company_id=endpoint["company_id"], endpoint_id=endpoint["id"],
                    identity_id=identity["id"], space_id=space["id"], node_id=node["id"],
                    prefix=prefix, permissions=permissions,
                    max_file_bytes=space.get("max_file_bytes") or 536870912,
                    quota_bytes=space.get("quota_bytes"),
                    history_days=space.get('history_days',0),
                ),
            })
        if nodes:
            result.append({
                "id": space["id"], "name": space["name"], "type": space["space_type"],
                "access_mode": access_mode,
                "prefix": prefix, "mappings": space.get("mappings") or [],
                "sync_mode": space.get("sync_mode"), "conflict_policy": space.get("conflict_policy"),
                "offline_cache": bool(space.get("offline_cache", True)),
                "max_file_bytes": int(space.get("max_file_bytes") or 536870912), "nodes": nodes,
            })
    return result
