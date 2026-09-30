"""Organization controls and storage-node API for Warden Home."""

import base64
import hashlib
import io
import json
import re
import secrets
import tarfile
import threading
import time
import zipfile
from functools import lru_cache
from urllib.parse import urlparse

from cryptography import x509

from flask import Blueprint, abort, current_app, flash, g, jsonify, make_response, redirect, render_template, request, send_file, url_for

import config
import db
from middleware.auth import company_required, login_required, role_required
from middleware.security import check_rate_limit
from services.signing import get_server_pubkey_b64, sign_canonical_payload
from services.home_grants import replication_config_for
from services.home_grants import home_config_for
from services.home_sync import resolve_home_access_context, short_windows_username


bp = Blueprint("home", __name__)
node_api_bp = Blueprint("home_node_api", __name__)
_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")
_SAFE_MAPPING = {"Desktop", "Documents", "Downloads", "Pictures", "Music", "Videos"}
_BOOTSTRAP_HANDOFFS = {}
_BOOTSTRAP_HANDOFF_LOCK = threading.Lock()
_BOOTSTRAP_HANDOFF_TTL_SECONDS = 10 * 60


def _parse_version(value):
    parts = str(value or "").strip().split(".")
    if len(parts) != 3 or not all(part.isdigit() for part in parts):
        return None
    return tuple(int(part) for part in parts)


@lru_cache(maxsize=8)
def _home_artifact_digest(path, mtime_ns, size):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _home_update_for(node, reported_capabilities):
    platform = str(reported_capabilities.get("os") or "").lower()
    arch = str(reported_capabilities.get("arch") or "amd64").lower()
    current = _parse_version(reported_capabilities.get("version"))
    target = _parse_version(config.HOME_NODE_VERSION)
    if current is None or target is None or current >= target or arch != "amd64":
        return None
    filenames = {
        "windows": "warden-home-node-windows-amd64.exe",
        "linux": "warden-home-node-linux-amd64",
    }
    filename = filenames.get(platform)
    artifact = config.HOME_NODE_DIST_DIR / filename if filename else None
    if not artifact or not artifact.is_file():
        return None
    stat = artifact.stat()
    now = int(time.time())
    payload = {
        "node_id": str(node["id"]),
        "version": config.HOME_NODE_VERSION,
        "platform": f"{platform}-amd64",
        "download_url": (
            f"{config.SERVER_URL.rstrip('/')}/api/home-node/update/{platform}-amd64"
        ),
        "sha256": _home_artifact_digest(artifact, stat.st_mtime_ns, stat.st_size),
        "issued_at": now - 300,
        "expires_at": now + 24 * 60 * 60,
    }
    payload["signature"] = base64.b64encode(
        sign_canonical_payload(payload)
    ).decode()
    return payload


def _bootstrap_redirect(payload):
    """Use POST/Redirect/GET so Refresh can never repeat key generation."""
    token = secrets.token_urlsafe(32)
    now = time.monotonic()
    entry = {
        "expires": now + _BOOTSTRAP_HANDOFF_TTL_SECONDS,
        "company_id": str(g.company["id"]),
        "admin_id": str(g.admin["id"]),
        "payload": payload,
    }
    with _BOOTSTRAP_HANDOFF_LOCK:
        for key in [key for key, item in _BOOTSTRAP_HANDOFFS.items()
                    if item["expires"] <= now]:
            _BOOTSTRAP_HANDOFFS.pop(key, None)
        if len(_BOOTSTRAP_HANDOFFS) >= 1000:
            oldest = min(_BOOTSTRAP_HANDOFFS,
                         key=lambda key: _BOOTSTRAP_HANDOFFS[key]["expires"])
            _BOOTSTRAP_HANDOFFS.pop(oldest, None)
        _BOOTSTRAP_HANDOFFS[token] = entry
    response = redirect(url_for("home.index", bootstrap=token), code=303)
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


def _consume_bootstrap_handoff():
    token = request.args.get("bootstrap", "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,64}", token):
        return None
    with _BOOTSTRAP_HANDOFF_LOCK:
        entry = _BOOTSTRAP_HANDOFFS.pop(token, None)
    if (not entry or entry["expires"] <= time.monotonic()
            or entry["company_id"] != str(g.company["id"])
            or entry["admin_id"] != str(g.admin["id"])):
        return None
    return entry["payload"]


def _storage_root(platform, value):
    """Validate an operator-selected data root; never choose a system drive."""
    value = str(value or "").strip()
    if not value or len(value) > 512 or "\x00" in value:
        abort(400, "A storage root is required")
    parts = [part for part in re.split(r"[\\/]", value) if part]
    if ".." in parts:
        abort(400, "The storage root cannot contain parent traversal")
    if platform == "windows":
        normalized = value.replace("\\", "/").rstrip("/")
        if (not re.match(r"^[D-Zd-z]:/", normalized + "/")
                or len(normalized) <= 3
                or any(character in normalized[2:] for character in '<>"|?*')):
            abort(400, "Choose an absolute folder on a Windows data drive other than C:, for example D:/WardenHome")
        return normalized
    if platform == "linux":
        normalized = value.rstrip("/")
        if not normalized.startswith("/") or normalized == "":
            abort(400, "Choose an absolute Linux storage folder, for example /srv/warden-home")
        return normalized
    abort(404)


def _home_transfer_view(job, endpoints):
    """Distinguish a file receipt from older agents' generic completed text."""
    item = dict(job)
    item["endpoint_name"] = endpoints.get(str(job.get("endpoint_id")), {}).get("hostname") or "Removed endpoint"
    report = None
    try:
        candidate = json.loads(job.get("log_output") or "")
        counters = ("uploaded", "downloaded", "unchanged", "skipped", "failed", "uploaded_bytes", "downloaded_bytes")
        if (isinstance(candidate, dict) and candidate.get("kind") == "warden_home_sync"
                and candidate.get("version") == 1
                and all(type(candidate.get(key)) is int and candidate[key] >= 0 for key in counters)):
            report = {key: candidate[key] for key in counters}
            folders = candidate.get("folders_created", 0)
            report["folders_created"] = folders if type(folders) is int and folders >= 0 else 0
            report["files"] = [entry for entry in candidate.get("files", [])[:100] if isinstance(entry, dict)] if isinstance(candidate.get("files"), list) else []
            report["omitted_details"] = candidate.get("omitted_details", 0)
            report["username"] = candidate.get("username") or ""
            report["status"] = candidate.get("status")
    except (TypeError, ValueError):
        pass
    item["report"] = report
    status = job.get("status")
    item["tone"] = "badge-pending"
    if status == "completed":
        if not report:
            item["label"] = "Completed · unverified"
        elif report["failed"] or report["skipped"] or report["status"] != "completed":
            item["label"] = "Incomplete"
            item["tone"] = "badge-offline"
        else:
            item["label"] = "Succeeded" if report["uploaded"] + report["downloaded"] + report["folders_created"] else ("Up to date" if report["unchanged"] else "No files found")
            item["tone"] = "badge-online"
    elif status == "failed":
        item["label"] = "Failed"
        item["tone"] = "badge-offline"
    else:
        item["label"] = {"running": "Transferring", "pending": "Queued", "approved": "Queued", "cancelled": "Cancelled"}.get(status, str(status or "Unknown").title())
    return item


def _render_home(bootstrap_token=None):
    endpoints = db.get_endpoints(g.company["id"])
    endpoint_lookup = {str(endpoint["id"]): endpoint for endpoint in endpoints}
    branch_id = g.admin.get("branch_id") if g.admin.get("role") == "branch_admin" else None
    if g.admin.get("role") == "branch_admin" and not branch_id:
        abort(403)
    transfers = [_home_transfer_view(job, endpoint_lookup) for job in db.get_home_sync_jobs(g.company["id"], branch_id=branch_id)]
    completed = db.get_home_sync_jobs(g.company["id"], status="completed", branch_id=branch_id, limit=1)
    last_completed = _home_transfer_view(completed[0], endpoint_lookup) if completed else None
    response = make_response(render_template(
        "home/index.html", nodes=db.get_home_nodes(g.company["id"]),
        spaces=db.get_home_spaces(g.company["id"]),
        assignments=db.get_home_assignments(g.company["id"]),
        branches=db.get_branches(g.company["id"]),
        identities=db.get_warden_identities(g.company["id"]),
        endpoints=endpoints, transfers=transfers, last_completed=last_completed,
        server_public_key=get_server_pubkey_b64(), bootstrap_token=bootstrap_token,
        active_page="home",
    ))
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@bp.get("/storage")
@login_required
@company_required
def index():
    return _render_home(_consume_bootstrap_handoff())


@bp.get("/storage/download/<platform>")
@login_required
@company_required
@role_required("company_admin")
def download_home_node(platform):
    filenames = {
        "windows": "warden-home-node-windows-amd64.exe",
        "linux": "warden-home-node-linux-amd64",
    }
    filename = filenames.get(platform)
    if not filename:
        abort(404)
    artifact = config.HOME_NODE_DIST_DIR / filename
    if not artifact.is_file():
        abort(503, "The Warden Home Node build is not available")

    if platform == "windows":
        example_config = {
            "node_id": "REPLACE_WITH_NODE_ID",
            "node_key": "REPLACE_WITH_ONE_TIME_NODE_KEY",
            "warden_url": config.SERVER_URL.rstrip("/"),
            "server_public_key": get_server_pubkey_b64(),
            "listen": ":9443",
            "root": "REPLACE_WITH_STORAGE_ROOT",
            "tls_cert": "", "tls_key": "", "client_ca": "",
            "client_cert": "", "client_key": "",
            "encryption_key": "REPLACE_WITH_NODE_ENCRYPTION_KEY",
            "public_mode": False,
            "replication": True,
            "storage_cluster_id": "",
        }
        instructions = (
            "WARDEN HOME NODE - WINDOWS DOWNLOAD\n\n"
            "For a ready-to-install package, create a node in Warden Home and download "
            "the configured Windows ZIP shown immediately after creation.\n\n"
            "This generic ZIP contains the executable and an example configuration only. "
            "Do not install the example until its REPLACE_WITH values have been replaced "
            "with credentials issued by Warden.\n\n"
            "UPGRADE AN EXISTING WINDOWS NODE\n"
            "1. Extract this ZIP on the Home Node server.\n"
            "2. Open PowerShell as Administrator in the extracted folder.\n"
            "3. Run: .\\warden-home-node-windows-amd64.exe upgrade\n"
            "The installed configuration, keys, encrypted data root, and node identity are preserved.\n"
        )
        package = io.BytesIO()
        with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.write(artifact, filename)
            archive.writestr(
                "warden-home.example.json",
                json.dumps(example_config, indent=2) + "\n",
            )
            archive.writestr("INSTALL.txt", instructions)
        package.seek(0)
        response = send_file(
            package, as_attachment=True,
            download_name="warden-home-node-windows-amd64.zip",
            mimetype="application/zip", conditional=False,
        )
        response.headers["Cache-Control"] = "private, no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    response = send_file(
        artifact, as_attachment=True, download_name=filename,
        mimetype="application/octet-stream", conditional=True,
    )
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@bp.post("/storage/nodes/<node_id>/bootstrap-package/<platform>")
@login_required
@company_required
@role_required("company_admin")
def download_home_node_bootstrap_package(node_id, platform):
    """Build a one-time package without persisting its plaintext secrets."""
    node = next((item for item in db.get_home_nodes(g.company["id"])
                 if str(item.get("id")) == str(node_id)), None)
    if not node:
        abort(404)
    filename = {
        "windows": "warden-home-node-windows-amd64.exe",
        "linux": "warden-home-node-linux-amd64",
    }.get(platform)
    if not filename:
        abort(404)
    artifact = config.HOME_NODE_DIST_DIR / filename
    if not artifact.is_file():
        abort(503, "The Warden Home Node build is not available")

    node_key = request.form.get("node_key", "")
    encryption_key = request.form.get("encryption_key", "")
    submitted_hash = hashlib.sha256(node_key.encode()).hexdigest()
    if not node_key or not secrets.compare_digest(
            submitted_hash, str(node.get("node_key_hash") or "")):
        abort(403, "The one-time node credentials are no longer valid")
    try:
        decoded_key = base64.b64decode(encryption_key, validate=True)
    except (ValueError, TypeError):
        abort(400, "The encryption key is invalid")
    if len(decoded_key) != 32:
        abort(400, "The encryption key must contain 32 bytes")
    storage_root = _storage_root(platform, request.form.get("storage_root"))

    node_config = {
        "node_id": str(node["id"]),
        "node_key": node_key,
        # Use the configured canonical origin, never the request Host header.
        "warden_url": config.SERVER_URL.rstrip("/"),
        "server_public_key": get_server_pubkey_b64(),
        "listen": ":9443",
        "root": storage_root,
        "tls_cert": "", "tls_key": "", "client_ca": "",
        "client_cert": "", "client_key": "",
        "encryption_key": encryption_key,
        "public_mode": node.get("deployment_mode") in {"public", "hybrid"},
        "replication": True,
        "storage_cluster_id": node.get("storage_cluster_id") or "",
    }
    config_bytes = (json.dumps(node_config, indent=2) + "\n").encode()
    instructions = (
        "WARDEN HOME NODE - ONE-TIME INSTALL PACKAGE\n\n"
        "This package is already configured. Keep warden-home.json beside the executable during installation.\n"
        "The JSON contains the node key and encryption key. Do not email or publicly share it.\n\n"
        + ("WINDOWS INSTALLATION\n"
           "1. Right-click the ZIP, choose Extract All, and open the extracted folder.\n"
           "2. Confirm warden-home-node-windows-amd64.exe and warden-home.json are together.\n"
           "3. Open PowerShell as Administrator in that folder.\n"
           "4. Run these commands:\n"
           "   Unblock-File .\\warden-home-node-windows-amd64.exe\n"
           "   .\\warden-home-node-windows-amd64.exe install -config .\\warden-home.json\n"
           "   For an existing node, preserve its installed config and run: .\\warden-home-node-windows-amd64.exe upgrade\n"
           "5. Verify the automatic service:\n"
           "   Get-Service WardenHomeNode\n"
           "   It must show Running. The service starts automatically after reboot.\n\n"
           "Installed program: C:\\Program Files\\WardenHome\\warden-home-node.exe\n"
           "Installed config:  C:\\ProgramData\\WardenHome\\warden-home.json\n"
           if platform == "windows" else
           "LINUX INSTALLATION\n"
           "1. Extract the TAR.GZ and enter the extracted directory.\n"
           "2. Confirm warden-home-node-linux-amd64 and warden-home.json are together.\n"
           "3. Run:\n"
           "   chmod +x ./warden-home-node-linux-amd64\n"
           "   sudo ./warden-home-node-linux-amd64 install -config ./warden-home.json\n"
           "   For an existing node, preserve its installed config and run: sudo ./warden-home-node-linux-amd64 upgrade\n"
           "4. Verify the automatic service:\n"
           "   sudo systemctl status warden-home\n\n"
           "Installed config: /etc/warden-home/warden-home.json\n")
        + "\nFINAL STEPS\n"
        "1. Return to Warden Home and wait for the node to show Online.\n"
        "2. Back up the encryption_key value in an offline password manager. Warden cannot recover it.\n"
        "3. After verifying the backup and service, securely delete the downloaded and extracted setup package.\n"
    ).encode()

    package = io.BytesIO()
    if platform == "windows":
        with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.write(artifact, filename)
            archive.writestr("warden-home.json", config_bytes)
            archive.writestr("INSTALL.txt", instructions)
        download_name = f"warden-home-{node_id}-windows.zip"
        mimetype = "application/zip"
    else:
        with tarfile.open(fileobj=package, mode="w:gz") as archive:
            for name, content, mode in (
                (filename, artifact.read_bytes(), 0o755),
                ("warden-home.json", config_bytes, 0o600),
                ("INSTALL.txt", instructions, 0o600),
            ):
                member = tarfile.TarInfo(name)
                member.size = len(content)
                member.mode = mode
                archive.addfile(member, io.BytesIO(content))
        download_name = f"warden-home-{node_id}-linux.tar.gz"
        mimetype = "application/gzip"
    package.seek(0)
    response = send_file(package, as_attachment=True, download_name=download_name,
                         mimetype=mimetype, conditional=False)
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@bp.post("/storage/nodes")
@login_required
@company_required
@role_required("company_admin")
def create_node():
    name = request.form.get("name", "").strip()[:120]
    mode = request.form.get("deployment_mode", "local").strip()
    local_url = request.form.get("local_url", "").strip().rstrip("/") or None
    public_url = request.form.get("public_url", "").strip().rstrip("/") or None
    fingerprint = request.form.get("tls_fingerprint", "").lower().replace(":", "").strip() or None
    ca_certificate_pem = request.form.get("ca_certificate_pem", "").strip() or None
    if not name or mode not in {"local", "public", "hybrid", "p2p"}:
        abort(400)
    if mode in {"local", "hybrid"} and not local_url:
        abort(400)
    if mode in {"public", "hybrid"} and not public_url:
        abort(400)
    if mode == "p2p":
        local_url = public_url = None
    for value in (local_url, public_url):
        if value and (urlparse(value).scheme != "https" or not urlparse(value).hostname):
            abort(400, "Warden Home nodes must use HTTPS")
    if fingerprint and not _FINGERPRINT.fullmatch(fingerprint):
        abort(400, "The optional SHA-256 TLS certificate fingerprint is invalid")
    if ca_certificate_pem:
        if len(ca_certificate_pem) > 20000:
            abort(400)
        try:
            certificate = x509.load_pem_x509_certificate(ca_certificate_pem.encode())
            if certificate.subject != certificate.issuer:
                abort(400, "The private trust certificate must be a CA root")
            basic = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
            if not basic.ca:
                abort(400, "The private trust certificate must be a CA root")
        except (ValueError, x509.ExtensionNotFound):
            abort(400, "The private CA certificate is not valid PEM")
    raw_key = secrets.token_urlsafe(48)
    node = db.create_home_node({
        "company_id": g.company["id"], "name": name, "deployment_mode": mode,
        "local_url": local_url, "public_url": public_url,
        "region": request.form.get("region", "").strip()[:80] or None,
        "tls_fingerprint": fingerprint, "ca_certificate_pem": ca_certificate_pem,
        "failure_domain": request.form.get("failure_domain", "").strip()[:80] or None,
        "storage_cluster_id": request.form.get("storage_cluster_id", "").strip()[:120] or None,
        "node_key_hash": hashlib.sha256(raw_key.encode()).hexdigest(),
        "require_mtls": True, "encrypted_at_rest": True, "created_by": g.admin["id"],
    })
    db.audit(g.company["id"], g.admin["id"], "home_node_created", {"node_id": node["id"], "mode": mode})
    # The data-encryption key is generated for the organization and shown once. It
    # is never persisted by the control plane; losing it makes the encrypted
    # node data unrecoverable, so the setup guide tells the operator to place
    # it in their secret manager before starting the node.
    encryption_key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    return _bootstrap_redirect({
        "node": node, "key": raw_key, "encryption_key": encryption_key,
    })


@bp.post("/storage/nodes/<node_id>/connection")
@login_required
@company_required
@role_required("company_admin")
def update_node_connection(node_id):
    node = next((item for item in db.get_home_nodes(g.company["id"])
                 if str(item.get("id")) == str(node_id)), None)
    if not node:
        abort(404)
    mode = request.form.get("deployment_mode", "local").strip()
    local_url = request.form.get("local_url", "").strip().rstrip("/") or None
    public_url = request.form.get("public_url", "").strip().rstrip("/") or None
    if mode not in {"local", "public", "hybrid", "p2p"}:
        abort(400)
    if mode in {"local", "hybrid"} and not local_url:
        abort(400, "A private HTTPS address is required")
    if mode in {"public", "hybrid"} and not public_url:
        abort(400, "A public HTTPS address is required")
    if mode == "p2p":
        local_url = public_url = None
    for value in (local_url, public_url):
        if value and (urlparse(value).scheme != "https" or not urlparse(value).hostname):
            abort(400, "Warden Home nodes must use HTTPS")
    cluster_id = request.form.get("storage_cluster_id", "").strip()[:120] or None
    db.update_home_node(node_id, g.company["id"], {
        "deployment_mode": mode, "local_url": local_url, "public_url": public_url,
        "region": request.form.get("region", "").strip()[:80] or None,
        "failure_domain": request.form.get("failure_domain", "").strip()[:80] or None,
        "storage_cluster_id": cluster_id,
    })
    db.audit(g.company["id"], g.admin["id"], "home_node_connection_updated",
             {"node_id": node_id, "mode": mode, "migration": True})
    flash("Node connection updated. Keep the existing Node ID, keys, and encrypted data root on the recovered or migrated server.", "success")
    return _render_home()


@bp.post("/storage/nodes/<node_id>/rotate-key")
@login_required
@company_required
@role_required("company_admin")
def rotate_node_key(node_id):
    node = next((item for item in db.get_home_nodes(g.company["id"])
                 if str(item.get("id")) == str(node_id)), None)
    if not node:
        abort(404)
    raw_key = secrets.token_urlsafe(48)
    # Before the first heartbeat there cannot be encrypted node data. Make
    # the existing recovery action issue a complete install package instead
    # of another node key that still leaves the operator without a data key.
    if not node.get("last_seen"):
        encryption_key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        db.update_home_node(node_id, g.company["id"], {
            "node_key_hash": hashlib.sha256(raw_key.encode()).hexdigest(),
            "status": "pending",
        })
        db.audit(g.company["id"], g.admin["id"], "home_node_bootstrap_reset", {
            "node_id": node_id, "never_connected": True,
        })
        flash("A complete one-time installation package is ready. The previous setup credentials are invalid.", "success")
        return _bootstrap_redirect({
            "node": node, "key": raw_key, "encryption_key": encryption_key,
        })
    db.update_home_node(node_id, g.company["id"], {
        "node_key_hash": hashlib.sha256(raw_key.encode()).hexdigest(),
        "status": "pending",
    })
    db.audit(g.company["id"], g.admin["id"], "home_node_key_rotated",
             {"node_id": node_id, "recovery": True})
    flash("Node authentication key rotated. Copy it now and replace node_key in the recovered configuration.", "success")
    return _bootstrap_redirect({"node": node, "key": raw_key, "recovery": True})


@bp.post("/storage/nodes/<node_id>/reset-bootstrap")
@login_required
@company_required
@role_required("company_admin")
def reset_node_bootstrap(node_id):
    """Reissue a full setup package only before a node has ever connected."""
    node = next((item for item in db.get_home_nodes(g.company["id"])
                 if str(item.get("id")) == str(node_id)), None)
    if not node:
        abort(404)
    if node.get("last_seen"):
        abort(409, "A connected node's encryption key cannot be replaced")
    raw_key = secrets.token_urlsafe(48)
    encryption_key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    db.update_home_node(node_id, g.company["id"], {
        "node_key_hash": hashlib.sha256(raw_key.encode()).hexdigest(),
        "status": "pending",
    })
    db.audit(g.company["id"], g.admin["id"], "home_node_bootstrap_reset", {
        "node_id": node_id, "never_connected": True,
    })
    flash("A new one-time installation package is ready. The previous node key and encryption key are now invalid.", "success")
    return _bootstrap_redirect({
        "node": node, "key": raw_key, "encryption_key": encryption_key,
    })


@bp.post("/storage/spaces")
@login_required
@company_required
@role_required("company_admin")
def create_space():
    name = request.form.get("name", "").strip()[:120]
    space_type = request.form.get("space_type")
    space_type = space_type if space_type in {"home", "shared"} else "home"
    # Shared spaces always use their dedicated Warden Shares folder; a
    # Windows profile-folder choice is meaningful only for per-user homes.
    source = (request.form.get("source", "Documents").strip()
              if space_type == "home" else "Documents")
    target = request.form.get("target", source).strip().strip("/\\")
    primary_node_id = request.form.get("primary_node_id", "").strip()
    writer_ids = list(dict.fromkeys([primary_node_id] + request.form.getlist("writer_node_ids")))
    replica_ids = [value for value in dict.fromkeys(request.form.getlist("replica_node_ids")) if value not in writer_ids]
    owned_nodes = {str(row["id"]): row for row in db.get_home_nodes(g.company["id"])}
    selected_ids = [value for value in writer_ids + replica_ids if value]
    if not name or source not in _SAFE_MAPPING or not target or ".." in target or not writer_ids or not set(selected_ids) <= set(owned_nodes):
        abort(400)
    availability_mode = request.form.get("availability_mode", "single")
    if availability_mode not in {"single", "failover", "shared_active_active"}:
        abort(400)
    if availability_mode == "single" and len(writer_ids) != 1:
        abort(400, "Single-primary spaces permit one writer")
    if availability_mode == "shared_active_active":
        cluster_ids = {owned_nodes[node_id].get("storage_cluster_id") for node_id in writer_ids}
        if len(writer_ids) < 2 or len(cluster_ids) != 1 or not next(iter(cluster_ids), None):
            abort(400, "Active-active writers must share one non-empty storage identity")
        key_ids = {
            str((owned_nodes[node_id].get("capabilities") or {}).get("encryption_key_id") or "")
            for node_id in writer_ids
        }
        if len(key_ids) != 1 or not next(iter(key_ids), None):
            abort(400, "Start every writer with the same encryption key before enabling active-active")
        key_ids = {
            str((owned_nodes[node_id].get("capabilities") or {}).get("encryption_key_id") or "")
            for node_id in writer_ids
        }
        if len(key_ids) != 1 or not next(iter(key_ids), None):
            abort(400, "Start every writer with the same encryption key before enabling active-active")
    sync_mode = request.form.get("sync_mode", "two_way")
    conflict = request.form.get("conflict_policy", "newest_wins")
    if sync_mode not in {"download", "upload", "two_way"} or conflict not in {"newest_wins", "server_wins", "keep_both"}:
        abort(400)
    try:
        quota_gb = float(request.form.get("quota_gb") or 0)
        max_file_mb = int(request.form.get("max_file_mb") or 512)
    except (TypeError, ValueError):
        abort(400, "Storage limits must be numeric")
    if quota_gb < 0 or quota_gb > 10240 or max_file_mb < 1 or max_file_mb > 5120:
        abort(400, "Quota must be 0-10240 GB and maximum file size 1-5120 MB")
    space = db.create_home_space({
        "company_id": g.company["id"], "name": name,
        "space_type": space_type,
        "remote_prefix_template": "spaces/{space_id}/homes/{identity_id}" if space_type == "home" else f"shared/{re.sub(r'[^a-z0-9_-]+', '-', name.lower()).strip('-')}-{secrets.token_hex(6)}",
        "mappings": [{"source": source, "target": target}], "sync_mode": sync_mode,
        "conflict_policy": conflict, "offline_cache": True,
        "availability_mode": availability_mode,
        "active_writer_state": primary_node_id,
        "quota_bytes": int(quota_gb * 1024 * 1024 * 1024) if quota_gb else None,
        "max_file_bytes": max_file_mb * 1024 * 1024,
        "created_by": g.admin["id"],
    }, [
        {"node_id": node_id, "priority": 10 + index * 10,
         "writable": availability_mode == "shared_active_active" or index == 0,
         "role": "primary" if index == 0 else "failover"}
        for index, node_id in enumerate(writer_ids)
    ] + [
        {"node_id": node_id, "priority": 500 + index * 10, "writable": False, "role": "replica"}
        for index, node_id in enumerate(replica_ids)
    ])
    db.audit(g.company["id"], g.admin["id"], "home_space_created", {"space_id": space["id"], "nodes": selected_ids, "mode": availability_mode})
    flash("Storage space created. Assign it to users or devices next.", "success")
    return _render_home()


@bp.post("/storage/assignments")
@login_required
@company_required
@role_required("company_admin")
def create_assignment():
    space_id = request.form.get("space_id", "")
    space = db.get_home_space(space_id)
    scope_type = request.form.get("scope_type", "tenant")
    if not space or str(space.get("company_id")) != str(g.company["id"]) or scope_type not in {"tenant", "branch", "tag", "endpoint", "identity"}:
        abort(400)
    scope_value = None if scope_type == "tenant" else request.form.get("scope_value", "").strip()
    if scope_type != "tenant" and not scope_value:
        abort(400)
    if scope_type == "branch":
        target = db.get_branch(scope_value)
        if not target or str(target.get("company_id")) != str(g.company["id"]):
            abort(400, "Branch is not part of this organization")
    elif scope_type == "endpoint":
        target = db.get_endpoint(scope_value)
        if not target or str(target.get("company_id")) != str(g.company["id"]):
            abort(400, "Endpoint is not part of this organization")
    elif scope_type == "identity":
        owned_identities = {str(item["id"]) for item in db.get_warden_identities(g.company["id"])}
        if scope_value not in owned_identities:
            abort(400, "Identity is not part of this organization")
    access_mode = request.form.get("access_mode", "write")
    if access_mode not in {"read", "write"}:
        abort(400)
    preferred_node_id = request.form.get("preferred_node_id", "").strip() or None
    space_nodes = {str(item.get("home_storage_nodes", {}).get("id")) for item in space.get("home_space_nodes") or []}
    if preferred_node_id and preferred_node_id not in space_nodes:
        abort(400)
    # Re-submitting the same scope is an intentional permission/node update,
    # not a duplicate assignment that should turn into a database error.
    existing = next((item for item in db.get_home_assignments(g.company["id"])
                     if str(item.get("space_id")) == str(space_id)
                     and item.get("scope_type") == scope_type
                     and str(item.get("scope_value") or "") == str(scope_value or "")), None)
    values = {"preferred_node_id": preferred_node_id, "access_mode": access_mode}
    if existing:
        db.update_home_assignment(existing["id"], g.company["id"], values)
    else:
        db.create_home_assignment({
            "company_id": g.company["id"], "space_id": space_id, "scope_type": scope_type,
            "scope_value": scope_value, "created_by": g.admin["id"], **values,
        })
    queued = _queue_assigned_home_syncs(space_id)
    db.audit(g.company["id"], g.admin["id"], "home_assignment_created", {"space_id": space_id, "scope_type": scope_type})
    flash(f"Warden Home assignment saved; queued {queued} active endpoint sync(s).", "success")
    return _render_home()


@bp.post("/storage/assignments/<assignment_id>/delete")
@login_required
@company_required
@role_required("company_admin")
def delete_assignment(assignment_id):
    assignment = next((item for item in db.get_home_assignments(g.company["id"])
                       if str(item.get("id")) == str(assignment_id)), None)
    if not assignment:
        abort(404)
    db.delete_home_assignment(assignment_id, g.company["id"])
    db.audit(g.company["id"], g.admin["id"], "home_assignment_deleted",
             {"assignment_id": assignment_id, "space_id": assignment.get("space_id")})
    flash("Storage access removed. Existing grants expire within 15 minutes; cached local copies are retained.", "success")
    return _render_home()


@bp.post("/storage/spaces/<space_id>/sync")
@login_required
@company_required
@role_required("superadmin", "company_admin")
def sync_space(space_id):
    space = db.get_home_space(space_id)
    if not space or str(space.get("company_id")) != str(g.company["id"]):
        abort(404)
    queued = _queue_assigned_home_syncs(space_id)
    db.audit(g.company["id"], g.admin["id"], "home_sync_requested", {"space_id": space_id, "queued": queued})
    if queued:
        flash(f"Queued {queued} endpoint sync(s). Results appear in Transfer activity.", "success")
    else:
        flash("No new sync was queued. Sign in to an assigned Windows endpoint, or check Transfer activity for an already queued or running sync.", "info")
    return redirect(url_for("home.index", _anchor="home-transfers"), code=303)


def _queue_assigned_home_syncs(space_id):
    spaces = db.get_home_spaces(g.company["id"])
    queued = 0
    for endpoint in db.get_endpoints(g.company["id"]):
        if not endpoint.get("is_active", True) or str(endpoint.get("platform") or "").lower() != "windows":
            continue
        username = short_windows_username(endpoint.get("interactive_user"))
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,20}", username):
            continue
        if db.has_inflight_job(endpoint["id"], "SYNC_WARDEN_HOME"):
            continue
        principal, assignments, _ = resolve_home_access_context(endpoint, username)
        if not principal:
            continue
        home = home_config_for(endpoint, principal, spaces, assignments)
        if not any(str(item.get("id")) == str(space_id) for item in home):
            continue
        job = db.create_system_job_once(
            g.company["id"], endpoint.get("branch_id"), endpoint["id"],
            "SYNC_WARDEN_HOME", {"username": principal["username"], "refresh": True},
        )
        if job:
            queued += 1
    return queued


def _node_auth():
    raw = request.headers.get("X-Warden-Home-Key", "")
    if not raw:
        abort(401)
    node = db.get_home_node_by_key_hash(hashlib.sha256(raw.encode()).hexdigest())
    if not node or node.get("status") == "disabled":
        abort(401)
    capabilities = node.get("capabilities") or {}
    expected_fp = str(capabilities.get("certificate_fingerprint") or "").lower().replace(":", "")
    # Bootstrap is bearer-key authenticated because no certificate exists
    # yet. Once one has been issued, deployments that enforce client
    # certificates require both factors on every Home control-plane call.
    if config.REQUIRE_CLIENT_CERT and expected_fp:
        if not config.TRUST_CLOUDFLARE:
            abort(500)
        presented_fp = request.headers.get(
            "Cf-Client-Cert-Sha256", ""
        ).lower().replace(":", "")
        if not presented_fp or not secrets.compare_digest(presented_fp, expected_fp):
            abort(401)
    return node


@node_api_bp.post("/api/home-node/heartbeat")
def node_heartbeat():
    node = _node_auth()
    body = request.get_json(silent=True) or {}
    try:
        capacity = max(0, int(body.get("capacity_bytes") or 0))
        used = max(0, int(body.get("used_bytes") or 0))
    except (TypeError, ValueError, OverflowError):
        abort(400)
    if used > capacity and capacity > 0:
        abort(400)
    reported_capabilities = body.get("capabilities") if isinstance(body.get("capabilities"), dict) else {}
    fields = {
        "capacity_bytes": capacity,
        "used_bytes": used,
        "capabilities": {**(node.get("capabilities") or {}), **reported_capabilities},
    }
    reported_cluster = str(fields["capabilities"].get("storage_cluster_id") or "").strip()
    expected_cluster = str(node.get("storage_cluster_id") or "").strip()
    if expected_cluster and reported_cluster != expected_cluster:
        abort(409, "Storage cluster identity does not match the registered node")
    db.update_home_node_heartbeat(node["id"], fields)
    spaces = db.get_home_spaces(node["company_id"])
    from services.home_grants import reconcile_home_topology
    reconcile_home_topology(node["company_id"], spaces=spaces)
    spaces = db.get_home_spaces(node["company_id"])
    peers = replication_config_for(node, spaces)
    return jsonify({"ok": True, "node_id": node["id"], "company_id": node["company_id"],
                    "server_public_key": get_server_pubkey_b64(), "replication_peers": peers,
                    "update": _home_update_for(node, reported_capabilities)})


@node_api_bp.get("/api/home-node/update/<platform>")
def node_update_artifact(platform):
    _node_auth()
    filenames = {
        "windows-amd64": "warden-home-node-windows-amd64.exe",
        "linux-amd64": "warden-home-node-linux-amd64",
    }
    filename = filenames.get(platform)
    if not filename:
        abort(404)
    artifact = config.HOME_NODE_DIST_DIR / filename
    if not artifact.is_file():
        abort(503, "The Warden Home Node build is not available")
    response = send_file(
        artifact, as_attachment=True, download_name=filename,
        mimetype="application/octet-stream", conditional=False,
    )
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@node_api_bp.post("/api/home-node/certificate")
def node_certificate():
    """Bootstrap or renew a Home Node's server/client identity certificate."""
    node = _node_auth()
    if not check_rate_limit(f"home-node-cert:{node['id']}", 4):
        return jsonify({"error": "rate_limited"}), 429
    body = request.get_json(silent=True) or {}
    csr_pem = str(body.get("csr_pem") or "").strip()
    reported_node_id = str(body.get("node_id") or "")
    if reported_node_id != str(node["id"]) or not csr_pem:
        abort(400)
    try:
        from services.agent_ca import ca_bundle_pem, sign_home_node_csr
        cert_pem, fingerprint, reference, expires_at = sign_home_node_csr(csr_pem, node)
        bundle = ca_bundle_pem()
    except (ValueError, RuntimeError) as exc:
        current_app.logger.warning("Home Node certificate issuance rejected for %s: %s", node["id"], exc)
        return jsonify({"error": "certificate_issuance_failed"}), 400
    db.update_home_node(node["id"], node["company_id"], {
        "tls_fingerprint": None,
        "ca_certificate_pem": bundle,
        "capabilities": {**(node.get("capabilities") or {}),
                         "device_certificate": True,
                         "certificate_fingerprint": fingerprint,
                         "certificate_expires_at": expires_at.isoformat(),
                         "certificate_reference": reference},
    })
    db.audit(node["company_id"], None, "home_node_certificate_issued", {
        "node_id": node["id"], "fingerprint": fingerprint,
        "expires_at": expires_at.isoformat(),
    })
    return jsonify({"certificate_pem": cert_pem, "ca_bundle_pem": bundle,
                    "expires_at": expires_at.isoformat()})


def _valid_webrtc_sdp(value, expected_type):
    return (isinstance(value, str) and 32 <= len(value) <= 131072
            and value.startswith("v=0") and "a=fingerprint:" in value
            and "a=ice-ufrag:" in value and f"a=setup:{'actpass' if expected_type == 'offer' else 'active'}" in value)


@node_api_bp.post("/api/home-node/p2p/offers")
def node_p2p_offers():
    """Return short-lived endpoint or peer offers; no file bytes cross here."""
    node = _node_auth()
    if node.get("deployment_mode") != "p2p":
        return jsonify({"offers": [], "stun_urls": []})
    if not check_rate_limit(f"home-p2p-poll:{node['id']}", 180):
        return jsonify({"error": "rate_limited"}), 429
    return jsonify({"offers": db.get_home_p2p_offers(node["id"]),
                    "stun_urls": config.HOME_P2P_STUN_URLS})


@node_api_bp.post("/api/home-node/p2p/offer")
def create_node_p2p_offer():
    """Create a direct-only session from an assigned replica to its writer."""
    source = _node_auth()
    body = request.get_json(silent=True) or {}
    target_node_id = str(body.get("target_node_id") or "")
    offer_sdp = body.get("offer_sdp")
    if not _valid_webrtc_sdp(offer_sdp, "offer") or target_node_id == str(source["id"]):
        abort(400)
    if not check_rate_limit(f"home-p2p-peer:{source['id']}", 60):
        return jsonify({"error": "rate_limited"}), 429
    peers = replication_config_for(
        source, db.get_home_spaces(source["company_id"]),
    )
    allowed = any(
        str(peer.get("target_node_id")) == target_node_id
        and peer.get("connection_mode") == "p2p"
        for peer in peers
    )
    if not allowed:
        abort(403)
    session = db.create_home_node_p2p_session(
        source["company_id"], source["id"], target_node_id, offer_sdp,
    )
    if not session:
        abort(503)
    db.log_home_access(source["company_id"], None, None, None, target_node_id,
                       "p2p_peer_offered", {"source_node_id": source["id"],
                                             "direct_only": True})
    response = jsonify({"ok": True, "session_id": session["id"]})
    response.headers["Cache-Control"] = "no-store"
    return response


@node_api_bp.post("/api/home-node/p2p/result")
def get_node_p2p_result():
    source = _node_auth()
    session_id = str((request.get_json(silent=True) or {}).get("session_id") or "")
    session = db.get_home_p2p_session(
        session_id, initiator_node_id=source["id"],
    )
    if not session or str(session.get("company_id")) != str(source["company_id"]):
        abort(404)
    response = jsonify({
        "status": session.get("status"), "answer_sdp": session.get("answer_sdp"),
        "error": session.get("error_message"),
    })
    response.headers["Cache-Control"] = "no-store"
    return response


@node_api_bp.post("/api/home-node/p2p/answer")
def node_p2p_answer():
    node = _node_auth()
    body = request.get_json(silent=True) or {}
    session_id = str(body.get("session_id") or "")
    answer_sdp = body.get("answer_sdp")
    error_message = str(body.get("error") or "").strip()
    session = db.get_home_p2p_session(session_id, node_id=node["id"])
    if not session or session.get("status") != "offered":
        abort(404)
    if error_message:
        db.fail_home_p2p_session(session_id, node["id"], error_message)
        return jsonify({"ok": True})
    if not _valid_webrtc_sdp(answer_sdp, "answer"):
        abort(400, "Invalid WebRTC answer")
    if not db.answer_home_p2p_session(session_id, node["id"], answer_sdp):
        abort(409)
    action = "p2p_peer_answered" if session.get("initiator_node_id") else "p2p_answered"
    db.log_home_access(node["company_id"], session.get("endpoint_id"), None,
                       None, node["id"], action,
                       {"source_node_id": session.get("initiator_node_id"),
                        "direct_only": True})
    return jsonify({"ok": True})
