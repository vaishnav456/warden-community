"""Organization-scoped physical computer topology and floor-plan operations."""
import ipaddress
import math
import re
from datetime import datetime, timedelta, timezone

from flask import Blueprint, abort, g, jsonify, render_template, request

import db
from middleware.auth import company_required, login_required, require_branch_scope, role_required

bp = Blueprint("topology", __name__)
_COLOR = re.compile(r"^#[0-9a-fA-F]{6}$")
_NODE_TYPES = {"switch", "firewall", "router", "server", "access_point", "printer", "asset"}
_LINK_TYPES = {"ethernet", "fiber", "wifi", "vpn", "logical"}
_ENDPOINT_OFFLINE_AFTER = timedelta(minutes=3)
# Existing coordinates are retained; floors grow in any direction.
_COORD_LIMIT = 9000


def _branch_id():
    if g.admin.get("role") == "branch_admin":
        branch_id = g.admin.get("branch_id")
        if not branch_id:
            abort(403)
        return str(branch_id)
    if g.admin.get("role") == "technician" and g.admin.get("branch_id"):
        return str(g.admin["branch_id"])
    return None


def _selected_branch_id():
    """Default to the assigned branch; only organization-wide users may switch."""
    assigned = _branch_id()
    requested = request.args.get("branch_id")
    if assigned:
        if requested not in (None, "", assigned):
            abort(403)
        return assigned
    selected = str(requested if requested is not None else g.admin.get("branch_id") or "").strip()
    if not selected:
        return None
    branch = db.get_branch(selected)
    if not branch or str(branch.get("company_id")) != str(g.company["id"]):
        abort(404)
    return selected


def _floor(floor_id):
    floor = db.get_topology_floor(floor_id)
    if not floor or str(floor.get("company_id")) != str(g.company["id"]):
        abort(404)
    require_branch_scope(floor.get("branch_id"))
    assigned = _branch_id()
    if assigned and str(floor.get("branch_id") or "") != assigned:
        abort(403)
    return floor


def _number(value, minimum, maximum, default=None):
    try:
        result = float(value)
    except (TypeError, ValueError):
        if default is not None:
            return default
        raise ValueError("invalid_number")
    if not math.isfinite(result) or result < minimum or result > maximum:
        raise ValueError("number_out_of_range")
    return round(result, 3)


def _snapshot_label(value):
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc).strftime("%d %b %Y, %H:%M UTC")
    except (TypeError, ValueError):
        return str(value or "Snapshot")


def _endpoint_addresses(endpoint):
    """Return every reported active interface address, with the primary first."""
    result, seen = [], {}

    def append(raw, interface_name=None, mac=None):
        value = str(raw or "").strip()
        if not value:
            return
        try:
            parsed = ipaddress.ip_interface(value)
        except ValueError:
            try:
                parsed = ipaddress.ip_interface(value.split("%", 1)[0])
            except ValueError:
                return
        address = str(parsed.ip)
        if parsed.ip.is_loopback or parsed.ip.is_unspecified or parsed.ip.is_multicast:
            return
        if address in seen:
            existing = seen[address]
            if interface_name and existing.get("interface") in (None, "Primary"):
                existing["interface"] = str(interface_name).strip()
                existing["mac"] = str(mac or "").strip() or None
                existing["cidr"] = str(parsed)
            return
        entry = {
            "address": address,
            "cidr": str(parsed),
            "family": "IPv4" if parsed.version == 4 else "IPv6",
            "interface": str(interface_name or "").strip() or None,
            "mac": str(mac or "").strip() or None,
            "primary": not result,
        }
        result.append(entry)
        seen[address] = entry

    append(endpoint.get("local_ip"), "Primary")
    telemetry = endpoint.get("topology_telemetry") or {}
    for interface in (telemetry.get("interfaces") or [])[:32]:
        if not isinstance(interface, dict):
            continue
        for address in (interface.get("addresses") or [])[:32]:
            append(address, interface.get("name"), interface.get("mac"))
    if not result:
        append(endpoint.get("last_seen_ip"), "Last contact")
    return result


def _endpoint_payload(endpoint):
    payload = {
        key: endpoint.get(key) for key in (
            "id", "hostname", "display_name", "branch_id", "status", "last_seen",
            "last_seen_ip", "local_ip", "device_type", "cpu_pct", "ram_used_pct", "disk_free_gb", "platform",
            "os_name", "interactive_user", "interactive_session_seen_at", "assigned_to",
            "capabilities", "capability_details", "tags", "net_sent_mbps", "net_recv_mbps",
            "topology_telemetry",
        )
    }
    if payload.get("status") == "online" and payload.get("last_seen"):
        try:
            seen = datetime.fromisoformat(str(payload["last_seen"]).replace("Z", "+00:00"))
            if seen.tzinfo is None:
                seen = seen.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) - seen.astimezone(timezone.utc) >= _ENDPOINT_OFFLINE_AFTER:
                payload["status"] = "offline"
        except (TypeError, ValueError):
            pass
    payload["ip_addresses"] = _endpoint_addresses(endpoint)
    return payload


def _topology_context(company_id, endpoints, nodes, links, placements, floor_id=None, branch_id=None):
    """Build read-only operational context from existing organization telemetry."""
    placed_ids = {str(item.get("endpoint_id")) for item in placements}
    placed_endpoints = [item for item in endpoints if str(item.get("id")) in placed_ids]
    endpoint_by_ip = {}
    for item in endpoints:
        if str(item.get("id")) not in placed_ids:
            continue
        for address in _endpoint_addresses(item):
            endpoint_by_ip[address["address"]] = item
    node_by_ip = {
        str(item.get("ip_address") or "").strip(): item for item in nodes
        if str(item.get("ip_address") or "").strip()
    }
    existing = {
        frozenset(((str(item.get("source_type")), str(item.get("source_id"))),
                   (str(item.get("target_type")), str(item.get("target_id")))))
        for item in links
    }
    discovered = []
    try:
        flows = db.get_network_flows(company_id, limit=500)
    except Exception:
        flows = []
    endpoint_ids = {str(item["id"]) for item in endpoints}
    flows = [item for item in flows if str(item.get("endpoint_id") or "") in endpoint_ids]
    def add_discovered(source, target_type, target, metadata):
        source_id, target_id = str(source["id"]), str(target["id"])
        pair = frozenset((("endpoint", source_id), (target_type, target_id)))
        if source_id == target_id or pair in existing or any(item["pair"] == pair for item in discovered):
            return
        discovered.append({
            "id": f"discovered:{source_id}:{target_type}:{target_id}",
            "source_type": "endpoint", "source_id": source_id,
            "target_type": target_type, "target_id": target_id,
            "link_type": metadata.get("link_type", "logical"),
            "label": metadata.get("label", "Observed traffic"), "status": metadata.get("status", "active"),
            "discovered": True, "pair": pair, **{key: value for key, value in metadata.items() if value is not None},
        })

    for source in placed_endpoints:
        telemetry = source.get("topology_telemetry") or {}
        def interface_speed(interface_name=None, interface_index=None):
            for adapter in (telemetry.get("adapters") or []):
                if not isinstance(adapter, dict):
                    continue
                name = adapter.get("Name") or adapter.get("name")
                index = adapter.get("ifIndex") or adapter.get("index")
                if (interface_name and str(name) == str(interface_name)) or (interface_index and str(index) == str(interface_index)):
                    return adapter.get("LinkSpeed") or adapter.get("link_speed")
            return None
        for neighbor in (telemetry.get("neighbors") or [])[:256]:
            if not isinstance(neighbor, dict):
                continue
            target_ip = str(neighbor.get("ip") or neighbor.get("dst") or neighbor.get("IPAddress") or "").split("%")[0].strip()
            target_endpoint, target_node = endpoint_by_ip.get(target_ip), node_by_ip.get(target_ip)
            if not target_endpoint and not target_node:
                continue
            protocol = str(neighbor.get("source") or "arp-ndp").lower()
            interface_name = neighbor.get("interface") or neighbor.get("dev")
            add_discovered(source, "endpoint" if target_endpoint else "node", target_endpoint or target_node, {
                "link_type": "ethernet", "label": protocol.upper(), "discovery_protocol": protocol,
                "interface_name": interface_name, "link_speed": interface_speed(interface_name=interface_name),
                "neighbor_mac": neighbor.get("mac") or neighbor.get("lladdr"),
                "neighbor_state": neighbor.get("state"), "last_observed_at": telemetry.get("captured_at"),
                "throughput_mbps": round(float(source.get("net_sent_mbps") or 0) + float(source.get("net_recv_mbps") or 0), 3),
            })
        for gateway in (telemetry.get("gateways") or [])[:16]:
            if not isinstance(gateway, dict):
                continue
            target_ip = str(gateway.get("ip") or gateway.get("gateway") or gateway.get("via") or "").strip()
            target = node_by_ip.get(target_ip) or endpoint_by_ip.get(target_ip)
            if target:
                add_discovered(source, "node" if target_ip in node_by_ip else "endpoint", target, {
                    "link_type": "ethernet", "label": "Default gateway", "discovery_protocol": "route",
                    "interface_name": gateway.get("dev") or gateway.get("interface_index"),
                    "link_speed": interface_speed(interface_name=gateway.get("dev"), interface_index=gateway.get("interface_index")),
                    "latency_ms": gateway.get("latency_ms"), "packet_loss_pct": gateway.get("packet_loss_pct"),
                    "last_observed_at": telemetry.get("captured_at"),
                })
        lldp_cdp = telemetry.get("lldp_cdp")
        stack = [lldp_cdp] if isinstance(lldp_cdp, (dict, list)) else []
        while stack:
            item = stack.pop()
            if isinstance(item, list):
                stack.extend(item[:256]); continue
            if not isinstance(item, dict):
                continue
            stack.extend(value for value in item.values() if isinstance(value, (dict, list)))
            text_values = {str(value).strip() for value in item.values() if isinstance(value, (str, int, float))}
            target_ip = next((value for value in text_values if value in node_by_ip or value in endpoint_by_ip), None)
            if target_ip:
                target = node_by_ip.get(target_ip) or endpoint_by_ip.get(target_ip)
                protocol = "cdp" if "cdp" in str(item).lower() else "lldp"
                port = next((str(value) for key, value in item.items() if "port" in str(key).lower() and isinstance(value, (str, int))), None)
                add_discovered(source, "node" if target_ip in node_by_ip else "endpoint", target, {
                    "link_type": "ethernet", "label": protocol.upper(), "discovery_protocol": protocol,
                    "remote_port": port, "last_observed_at": telemetry.get("captured_at"),
                })

    for flow in flows:
        source = next((item for item in placed_endpoints if str(item.get("id")) == str(flow.get("endpoint_id"))), None)
        source = source or endpoint_by_ip.get(str(flow.get("local_address") or flow.get("source_ip") or "").strip())
        target_ip = str(flow.get("remote_address") or flow.get("destination_ip") or "").strip()
        target_endpoint = endpoint_by_ip.get(target_ip)
        target_node = node_by_ip.get(target_ip)
        if not source or (not target_endpoint and not target_node):
            continue
        add_discovered(source, "endpoint" if target_endpoint else "node", target_endpoint or target_node, {
            "link_type": "logical", "label": "Observed traffic", "discovery_protocol": "flow",
            "protocol": flow.get("protocol"), "remote_port": flow.get("remote_port"),
            "last_observed_at": flow.get("observed_at"),
            "throughput_mbps": round(float(source.get("net_sent_mbps") or 0) + float(source.get("net_recv_mbps") or 0), 3),
        })
    for item in discovered:
        item.pop("pair", None)

    try:
        alerts = db.get_alerts(company_id, resolved=False, branch_id=branch_id, limit=200)
    except Exception:
        alerts = []
    alert_summary = {}
    for alert in alerts:
        endpoint_id = str(alert.get("endpoint_id") or "")
        if endpoint_id not in placed_ids:
            continue
        entry = alert_summary.setdefault(endpoint_id, {"count": 0, "severity": "info", "titles": []})
        entry["count"] += 1
        if alert.get("title") and len(entry["titles"]) < 3:
            entry["titles"].append(str(alert["title"]))
        if {"critical": 3, "high": 2, "warning": 1}.get(str(alert.get("severity")), 0) > \
                {"critical": 3, "high": 2, "warning": 1}.get(entry["severity"], 0):
            entry["severity"] = str(alert.get("severity"))

    try:
        audit_rows = db.get_audit_log(company_id, limit=80)
    except Exception:
        audit_rows = []
    history = [{
        "id": item.get("id"), "action": item.get("action"), "detail": item.get("detail") or {},
        "endpoint_id": item.get("endpoint_id"), "created_at": item.get("created_at"),
    } for item in audit_rows if str(item.get("action") or "").startswith("topology_")
       and (str((item.get("detail") or {}).get("floor_id") or "") == str(floor_id)
            or str(item.get("endpoint_id") or "") in placed_ids)][:30]
    return discovered, alert_summary, history, len(flows)


@bp.get("/topology")
@login_required
@company_required
def index():
    branch_id = _selected_branch_id()
    floors = db.get_topology_floors(g.company["id"], branch_id=branch_id)
    branches = db.get_branches(g.company["id"])
    if _branch_id():
        branches = [item for item in branches if str(item.get("id")) == branch_id]
    return render_template("topology/index.html", floors=floors, branches=branches,
                           selected_branch_id=branch_id or "", branch_locked=bool(_branch_id()),
                           active_page="topology")


@bp.get("/topology/state")
@login_required
@company_required
def state():
    branch_id = _selected_branch_id()
    floors = db.get_topology_floors(g.company["id"], branch_id=branch_id)
    if branch_id:
        floors = [item for item in floors if str(item.get("branch_id") or "") == branch_id]
    allowed = {str(item["id"]): item for item in floors}
    floor_id = str(request.args.get("floor_id") or "")
    if floor_id and floor_id not in allowed:
        abort(404)
    floor = allowed.get(floor_id) if floor_id else (floors[0] if floors else None)
    snapshots = []
    if floor:
        try:
            snapshots = db.get_topology_snapshots(g.company["id"], floor["id"], limit=100)
            for item in snapshots:
                item["label"] = _snapshot_label(item.get("captured_at"))
        except Exception:
            snapshots = []
        snapshot_id = str(request.args.get("snapshot_id") or "")
        if snapshot_id:
            snapshot = db.get_topology_snapshot(snapshot_id, g.company["id"], floor["id"])
            if not snapshot:
                abort(404)
            replay = dict(snapshot.get("state") or {})
            replay_branch = branch_id or floor.get("branch_id")
            if replay_branch:
                replay["endpoints"] = [item for item in replay.get("endpoints", [])
                                       if str(item.get("branch_id") or "") == str(replay_branch)]
                visible_ids = {str(item["id"]) for item in replay["endpoints"]}
                replay["placements"] = [item for item in replay.get("placements", [])
                                        if str(item.get("endpoint_id")) in visible_ids]
                replay["placed_endpoint_ids"] = [item for item in replay.get("placed_endpoint_ids", [])
                                                if str(item) in visible_ids]
                replay["alert_summary"] = {key: value for key, value in replay.get("alert_summary", {}).items()
                                           if str(key) in visible_ids}
                for key in ("links", "discovered_links"):
                    replay[key] = [item for item in replay.get(key, []) if all(
                        item.get(kind + "_type") != "endpoint"
                        or str(item.get(kind + "_id")) in visible_ids
                        for kind in ("source", "target")
                    )]
                replay["history"] = [item for item in replay.get("history", []) if
                    str((item.get("detail") or {}).get("floor_id") or "") == str(floor["id"])
                    or str(item.get("endpoint_id") or "") in visible_ids]
            replay.update({
                "floors": floors, "floor": floor, "snapshots": snapshots,
                "replay": {"id": snapshot["id"], "captured_at": snapshot["captured_at"],
                           "label": _snapshot_label(snapshot.get("captured_at"))},
                "server_time": datetime.now(timezone.utc).isoformat(),
            })
            return jsonify(replay)
    endpoint_branch = branch_id or (floor.get("branch_id") if floor else None)
    endpoints = db.get_endpoints(g.company["id"], branch_id=endpoint_branch)
    if endpoint_branch:
        endpoints = [item for item in endpoints if str(item.get("branch_id") or "") == str(endpoint_branch)]
    endpoint_ids = {str(item["id"]) for item in endpoints}
    all_placements = db.get_topology_placements(g.company["id"])
    all_placements = [item for item in all_placements if str(item.get("endpoint_id")) in endpoint_ids]
    placements = [item for item in all_placements if floor and str(item["floor_id"]) == str(floor["id"])]
    rooms = db.get_topology_rooms(g.company["id"], floor["id"]) if floor else []
    nodes = db.get_topology_nodes(g.company["id"], floor["id"]) if floor else []
    links = db.get_topology_links(g.company["id"], floor["id"]) if floor else []
    links = [item for item in links if all(
        item.get(kind + "_type") != "endpoint" or str(item.get(kind + "_id")) in endpoint_ids
        for kind in ("source", "target")
    )]
    discovered_links, alert_summary, history, observation_count = _topology_context(
        g.company["id"], endpoints, nodes, links, placements,
        floor_id=floor["id"] if floor else None, branch_id=endpoint_branch,
    )
    payload = {
        "floors": floors, "floor": floor, "rooms": rooms, "placements": placements,
        "nodes": nodes, "links": links,
        "discovered_links": discovered_links, "alert_summary": alert_summary, "history": history,
        "discovery": {"observation_count": observation_count, "matched_links": len(discovered_links)},
        "endpoints": [_endpoint_payload(item) for item in endpoints],
        "placed_endpoint_ids": [str(item["endpoint_id"]) for item in all_placements],
        "snapshots": snapshots, "replay": None,
        "server_time": datetime.now(timezone.utc).isoformat(),
    }
    if floor:
        try:
            newest = snapshots[0].get("captured_at") if snapshots else None
            newest_at = datetime.fromisoformat(str(newest).replace("Z", "+00:00")) if newest else None
            if not newest_at or datetime.now(timezone.utc) - newest_at >= timedelta(minutes=1):
                state_copy = {key: value for key, value in payload.items() if key not in {"snapshots", "floors", "server_time"}}
                db.create_topology_snapshot(g.company["id"], floor["id"], state_copy)
                db.prune_topology_snapshots(
                    g.company["id"], floor["id"],
                    (datetime.now(timezone.utc) - timedelta(days=30)).isoformat(),
                )
        except Exception:
            pass
    return jsonify(payload)


@bp.post("/topology/floors")
@login_required
@company_required
@role_required("company_admin", "branch_admin")
def create_floor():
    body = request.get_json(silent=True) or {}
    name = str(body.get("name") or "").strip()[:120]
    building = str(body.get("building") or "Office").strip()[:120]
    requested_branch = str(body.get("branch_id") or "").strip() or None
    assigned_branch = _branch_id()
    if assigned_branch and requested_branch and requested_branch != assigned_branch:
        abort(403)
    branch_id = assigned_branch or requested_branch
    if not name or not building:
        return jsonify({"error": "name_and_building_required"}), 400
    if branch_id:
        branch = db.get_branch(branch_id)
        if not branch or str(branch.get("company_id")) != str(g.company["id"]):
            return jsonify({"error": "invalid_branch"}), 400
        require_branch_scope(branch_id)
    try:
        order = int(body.get("level_order") or 0)
        ratio = _number(body.get("aspect_ratio", 1.778), 0.5, 4)
        floor = db.create_topology_floor(
            g.company["id"], branch_id, building, name, order, ratio, g.admin["id"],
        )
    except Exception as exc:
        if "duplicate" in str(exc).lower() or "unique" in str(exc).lower():
            return jsonify({"error": "floor_already_exists"}), 409
        raise
    db.audit(g.company["id"], g.admin["id"], "topology_floor_created", {
        "floor_id": floor["id"], "name": name, "building": building,
    })
    return jsonify({"ok": True, "floor": floor}), 201


@bp.patch("/topology/floors/<floor_id>")
@login_required
@company_required
@role_required("company_admin", "branch_admin")
def update_floor(floor_id):
    floor = _floor(floor_id)
    body = request.get_json(silent=True) or {}
    values = {}
    if "name" in body:
        values["name"] = str(body["name"] or "").strip()[:120]
    if "building" in body:
        values["building"] = str(body["building"] or "").strip()[:120]
    if "level_order" in body:
        values["level_order"] = int(body["level_order"])
    if "aspect_ratio" in body:
        values["aspect_ratio"] = _number(body["aspect_ratio"], 0.5, 4)
    if "layout_locked" in body:
        values["layout_locked"] = bool(body["layout_locked"])
    if not values or values.get("name") == "" or values.get("building") == "":
        return jsonify({"error": "invalid_floor_update"}), 400
    updated = db.update_topology_floor(floor_id, g.company["id"], values)
    db.audit(g.company["id"], g.admin["id"], "topology_floor_updated", {
        "floor_id": floor_id, "changes": list(values),
    })
    return jsonify({"ok": True, "floor": updated})


@bp.delete("/topology/floors/<floor_id>")
@login_required
@company_required
@role_required("company_admin", "branch_admin")
def delete_floor(floor_id):
    floor = _floor(floor_id)
    db.delete_topology_floor(floor_id, g.company["id"])
    db.audit(g.company["id"], g.admin["id"], "topology_floor_deleted", {
        "floor_id": floor_id, "name": floor["name"],
    })
    return jsonify({"ok": True})


@bp.post("/topology/floors/<floor_id>/rooms")
@login_required
@company_required
@role_required("company_admin", "branch_admin")
def create_room(floor_id):
    floor = _floor(floor_id)
    if floor.get("layout_locked"):
        return jsonify({"error": "layout_locked"}), 409
    body = request.get_json(silent=True) or {}
    name = str(body.get("name") or "").strip()[:120]
    if not name:
        return jsonify({"error": "room_name_required"}), 400
    try:
        values = {
            "name": name,
            "x": _number(body.get("x", 5), -_COORD_LIMIT, _COORD_LIMIT),
            "y": _number(body.get("y", 5), -_COORD_LIMIT, _COORD_LIMIT),
            "width": _number(body.get("width", 25), 3, _COORD_LIMIT),
            "height": _number(body.get("height", 25), 3, _COORD_LIMIT),
            "color": str(body.get("color") or "#DCE9FF"),
            "capacity": int(body["capacity"]) if body.get("capacity") not in (None, "") else None,
        }
    except (ValueError, TypeError):
        return jsonify({"error": "invalid_room_geometry"}), 400
    if not _COLOR.fullmatch(values["color"]) or (values["capacity"] is not None and values["capacity"] < 0):
        return jsonify({"error": "invalid_room_style"}), 400
    if values["x"] + values["width"] > _COORD_LIMIT or values["y"] + values["height"] > _COORD_LIMIT:
        return jsonify({"error": "room_outside_floor"}), 400
    room = db.create_topology_room(g.company["id"], floor_id, values)
    db.audit(g.company["id"], g.admin["id"], "topology_room_created", {
        "floor_id": floor_id, "room_id": room["id"], "name": name,
    })
    return jsonify({"ok": True, "room": room}), 201


@bp.patch("/topology/rooms/<room_id>")
@login_required
@company_required
@role_required("company_admin", "branch_admin")
def update_room(room_id):
    room = db.get_topology_room(room_id)
    if not room or str(room.get("company_id")) != str(g.company["id"]):
        abort(404)
    floor = _floor(room["floor_id"])
    if floor.get("layout_locked"):
        return jsonify({"error": "layout_locked"}), 409
    body = request.get_json(silent=True) or {}
    values = {}
    try:
        for key, bounds in {"x": (-_COORD_LIMIT, _COORD_LIMIT), "y": (-_COORD_LIMIT, _COORD_LIMIT), "width": (3, _COORD_LIMIT), "height": (3, _COORD_LIMIT)}.items():
            if key in body:
                values[key] = _number(body[key], *bounds)
        if "capacity" in body:
            values["capacity"] = int(body["capacity"]) if body["capacity"] not in (None, "") else None
    except (ValueError, TypeError):
        return jsonify({"error": "invalid_room_geometry"}), 400
    if "name" in body:
        values["name"] = str(body["name"] or "").strip()[:120]
    if "color" in body:
        values["color"] = str(body["color"] or "")
    if not values or values.get("name") == "" or ("color" in values and not _COLOR.fullmatch(values["color"])):
        return jsonify({"error": "invalid_room_update"}), 400
    if values.get("capacity") is not None and values["capacity"] < 0:
        return jsonify({"error": "invalid_room_update"}), 400
    proposed_x = values.get("x", float(room["x"]))
    proposed_y = values.get("y", float(room["y"]))
    proposed_width = values.get("width", float(room["width"]))
    proposed_height = values.get("height", float(room["height"]))
    if proposed_x + proposed_width > _COORD_LIMIT or proposed_y + proposed_height > _COORD_LIMIT:
        return jsonify({"error": "room_outside_floor"}), 400
    updated = db.update_topology_room(room_id, g.company["id"], values)
    return jsonify({"ok": True, "room": updated})


@bp.delete("/topology/rooms/<room_id>")
@login_required
@company_required
@role_required("company_admin", "branch_admin")
def delete_room(room_id):
    room = db.get_topology_room(room_id)
    if not room or str(room.get("company_id")) != str(g.company["id"]):
        abort(404)
    floor = _floor(room["floor_id"])
    if floor.get("layout_locked"):
        return jsonify({"error": "layout_locked"}), 409
    db.delete_topology_room(room_id, g.company["id"])
    return jsonify({"ok": True})


@bp.put("/topology/placements/<endpoint_id>")
@login_required
@company_required
@role_required("company_admin", "branch_admin")
def place_endpoint(endpoint_id):
    body = request.get_json(silent=True) or {}
    floor = _floor(str(body.get("floor_id") or ""))
    if floor.get("layout_locked"):
        return jsonify({"error": "layout_locked"}), 409
    endpoint = db.get_endpoint(endpoint_id)
    if not endpoint or str(endpoint.get("company_id")) != str(g.company["id"]) or not endpoint.get("is_active", True):
        abort(404)
    require_branch_scope(endpoint.get("branch_id"))
    if floor.get("branch_id") and str(endpoint.get("branch_id") or "") != str(floor["branch_id"]):
        return jsonify({"error": "endpoint_outside_floor_branch"}), 409
    try:
        x = _number(body.get("x"), -_COORD_LIMIT, _COORD_LIMIT)
        y = _number(body.get("y"), -_COORD_LIMIT, _COORD_LIMIT)
    except ValueError:
        return jsonify({"error": "invalid_position"}), 400
    room_id = str(body.get("room_id") or "") or None
    if room_id:
        room = db.get_topology_room(room_id)
        if not room or str(room.get("floor_id")) != str(floor["id"]):
            return jsonify({"error": "invalid_room"}), 400
    placement = db.upsert_topology_placement(
        g.company["id"], floor["id"], room_id, endpoint_id, x, y, g.admin["id"],
    )
    db.audit(g.company["id"], g.admin["id"], "topology_endpoint_moved", {
        "endpoint_id": endpoint_id, "floor_id": floor["id"], "room_id": room_id,
        "x": x, "y": y,
    }, endpoint_id=endpoint_id)
    return jsonify({"ok": True, "placement": placement})


@bp.delete("/topology/placements/<endpoint_id>")
@login_required
@company_required
@role_required("company_admin", "branch_admin")
def unplace_endpoint(endpoint_id):
    endpoint = db.get_endpoint(endpoint_id)
    if not endpoint or str(endpoint.get("company_id")) != str(g.company["id"]):
        abort(404)
    require_branch_scope(endpoint.get("branch_id"))
    db.delete_topology_links_for_object(g.company["id"], "endpoint", endpoint_id)
    db.delete_topology_placement(g.company["id"], endpoint_id)
    db.audit(g.company["id"], g.admin["id"], "topology_endpoint_unplaced", {
        "endpoint_id": endpoint_id,
    }, endpoint_id=endpoint_id)
    return jsonify({"ok": True})


@bp.post("/topology/floors/<floor_id>/nodes")
@login_required
@company_required
@role_required("company_admin", "branch_admin")
def create_node(floor_id):
    floor = _floor(floor_id)
    if floor.get("layout_locked"):
        return jsonify({"error": "layout_locked"}), 409
    body = request.get_json(silent=True) or {}
    node_type = str(body.get("node_type") or "asset")
    name = str(body.get("name") or "").strip()[:120]
    if node_type not in _NODE_TYPES or not name:
        return jsonify({"error": "invalid_asset"}), 400
    try:
        x = _number(body.get("x", 50), -_COORD_LIMIT, _COORD_LIMIT)
        y = _number(body.get("y", 50), -_COORD_LIMIT, _COORD_LIMIT)
    except ValueError:
        return jsonify({"error": "invalid_position"}), 400
    ip_address = str(body.get("ip_address") or "").strip()[:255] or None
    details = str(body.get("details") or "").strip()[:1000] or None
    room_id = str(body.get("room_id") or "") or None
    if room_id:
        room = db.get_topology_room(room_id)
        if not room or str(room.get("floor_id")) != str(floor_id):
            return jsonify({"error": "invalid_room"}), 400
    node = db.create_topology_node(g.company["id"], floor_id, {
        "node_type": node_type, "name": name, "ip_address": ip_address,
        "details": details, "room_id": room_id, "x": x, "y": y,
        "created_by": g.admin["id"],
    })
    db.audit(g.company["id"], g.admin["id"], "topology_asset_created", {
        "floor_id": floor_id, "node_id": node["id"], "node_type": node_type,
    })
    return jsonify({"ok": True, "node": node}), 201


@bp.patch("/topology/nodes/<node_id>")
@login_required
@company_required
@role_required("company_admin", "branch_admin")
def update_node(node_id):
    node = db.get_topology_node(node_id)
    if not node or str(node.get("company_id")) != str(g.company["id"]):
        abort(404)
    floor = _floor(node["floor_id"])
    if floor.get("layout_locked"):
        return jsonify({"error": "layout_locked"}), 409
    body = request.get_json(silent=True) or {}
    values = {}
    try:
        if "x" in body: values["x"] = _number(body["x"], -_COORD_LIMIT, _COORD_LIMIT)
        if "y" in body: values["y"] = _number(body["y"], -_COORD_LIMIT, _COORD_LIMIT)
    except ValueError:
        return jsonify({"error": "invalid_position"}), 400
    if "name" in body: values["name"] = str(body.get("name") or "").strip()[:120]
    if "ip_address" in body: values["ip_address"] = str(body.get("ip_address") or "").strip()[:255] or None
    if "details" in body: values["details"] = str(body.get("details") or "").strip()[:1000] or None
    if "room_id" in body:
        room_id = str(body.get("room_id") or "") or None
        if room_id:
            room = db.get_topology_room(room_id)
            if not room or str(room.get("floor_id")) != str(floor["id"]):
                return jsonify({"error": "invalid_room"}), 400
        values["room_id"] = room_id
    if not values or values.get("name") == "":
        return jsonify({"error": "invalid_asset_update"}), 400
    return jsonify({"ok": True, "node": db.update_topology_node(node_id, g.company["id"], values)})


@bp.delete("/topology/nodes/<node_id>")
@login_required
@company_required
@role_required("company_admin", "branch_admin")
def delete_node(node_id):
    node = db.get_topology_node(node_id)
    if not node or str(node.get("company_id")) != str(g.company["id"]): abort(404)
    floor = _floor(node["floor_id"])
    if floor.get("layout_locked"): return jsonify({"error": "layout_locked"}), 409
    db.delete_topology_links_for_object(g.company["id"], "node", node_id)
    db.delete_topology_node(node_id, g.company["id"])
    return jsonify({"ok": True})


def _topology_object_exists(kind, object_id, floor_id):
    if kind == "node":
        item = db.get_topology_node(object_id)
        return bool(item and str(item.get("company_id")) == str(g.company["id"]) and str(item.get("floor_id")) == str(floor_id))
    if kind == "endpoint":
        return any(str(item.get("endpoint_id")) == str(object_id) and str(item.get("floor_id")) == str(floor_id)
                   for item in db.get_topology_placements(g.company["id"], floor_id))
    return False


@bp.post("/topology/floors/<floor_id>/links")
@login_required
@company_required
@role_required("company_admin", "branch_admin")
def create_link(floor_id):
    floor = _floor(floor_id)
    if floor.get("layout_locked"): return jsonify({"error": "layout_locked"}), 409
    body = request.get_json(silent=True) or {}
    source_type, source_id = str(body.get("source_type") or ""), str(body.get("source_id") or "")
    target_type, target_id = str(body.get("target_type") or ""), str(body.get("target_id") or "")
    link_type = str(body.get("link_type") or "ethernet")
    if link_type not in _LINK_TYPES or (source_type, source_id) == (target_type, target_id):
        return jsonify({"error": "invalid_link"}), 400
    if not _topology_object_exists(source_type, source_id, floor_id) or not _topology_object_exists(target_type, target_id, floor_id):
        return jsonify({"error": "invalid_link_target"}), 400
    if (source_type, source_id) > (target_type, target_id):
        source_type, target_type, source_id, target_id = target_type, source_type, target_id, source_id
    try:
        link = db.create_topology_link(g.company["id"], floor_id, {
            "source_type": source_type, "source_id": source_id, "target_type": target_type,
            "target_id": target_id, "link_type": link_type,
            "label": str(body.get("label") or "").strip()[:120] or None,
            "status": "active", "created_by": g.admin["id"],
        })
    except Exception as exc:
        if "duplicate" in str(exc).lower() or "unique" in str(exc).lower():
            return jsonify({"error": "objects_already_connected"}), 409
        raise
    return jsonify({"ok": True, "link": link}), 201


@bp.delete("/topology/links/<link_id>")
@login_required
@company_required
@role_required("company_admin", "branch_admin")
def delete_link(link_id):
    link = db.get_topology_link(link_id)
    if not link or str(link.get("company_id")) != str(g.company["id"]): abort(404)
    floor = _floor(link["floor_id"])
    if floor.get("layout_locked"): return jsonify({"error": "layout_locked"}), 409
    db.delete_topology_link(link_id, g.company["id"])
    return jsonify({"ok": True})
