"""Closed optional-agent catalog. Tenants cannot supply code, URLs or commands."""
import base64
import functools
import hashlib
import json
import re
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit
import config
import db
from services.signing import sign_canonical_payload

CAPABILITIES = ["helpdesk.tickets.read", "helpdesk.tickets.write"]
MAX_PACKAGE = 64 * 1024 * 1024


def policy(company_id):
    rows = db._get(f"agent_module_policies?company_id=eq.{db._q(company_id)}&module_id=eq.helpdesk&limit=1")
    return rows[0] if rows else None


def entitled(company_id):
    # Community has organization permission, never hosted subscriptions.
    return True


def allowed(company_id):
    row = policy(company_id)
    return bool(row and row.get("enabled") is True and entitled(company_id))


def legacy_allowed(company_id):
    # Existing bundled agents stay functional until an admin saves a choice.
    row = policy(company_id)
    return row is None or (row.get("enabled") is True and entitled(company_id))


def helpdesk_access(function):
    @functools.wraps(function)
    def checked(*args, **kwargs):
        from flask import g, jsonify
        if not legacy_allowed(g.endpoint['company_id']):
            return jsonify(error='module_not_allowed'), 403
        return function(*args, **kwargs)
    return checked


def release():
    root = Path(config.AGENT_MODULE_PACKAGE_DIR)
    manifest = root / "helpdesk.json"
    if manifest.is_symlink() or not manifest.is_file() or manifest.stat().st_size > 4096:
        raise ValueError("Module release unavailable")
    value = json.loads(manifest.read_text(encoding="utf-8"))
    required = {"release_id", "release_sequence", "version", "min_core_version", "sha256", "size_bytes"}
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("Invalid module release")
    if str(uuid.UUID(str(value["release_id"]))) != value["release_id"]:
        raise ValueError("Invalid module release identifier")
    if type(value["release_sequence"]) is not int or not 0 < value["release_sequence"] <= 2**53-1:
        raise ValueError("Invalid module release sequence")
    for name in ("version", "min_core_version"):
        if not isinstance(value[name], str) or not re.fullmatch(r"(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})", value[name]):
            raise ValueError("Invalid module version")
    if type(value["size_bytes"]) is not int or not 0 < value["size_bytes"] <= MAX_PACKAGE:
        raise ValueError("Invalid module package size")
    if not isinstance(value["sha256"], str) or not re.fullmatch("[0-9a-f]{64}", value["sha256"]):
        raise ValueError("Invalid module package hash")
    path = root / (value["release_id"] + ".exe")
    if path.is_symlink() or not path.is_file() or path.stat().st_size != value["size_bytes"]:
        raise ValueError("Module package unavailable")
    with path.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != value["sha256"]:
            raise ValueError("Module package verification failed")
    return value, path


def grant(endpoint, value):
    origin = config.SERVER_URL.rstrip("/")
    parsed = urlsplit(origin)
    if parsed.scheme != "https" or not parsed.netloc or parsed.path or parsed.query or parsed.fragment or parsed.username:
        raise ValueError("Module server origin must be HTTPS")
    now = int(time.time())
    payload = dict(schema=1, module_id="helpdesk", tenant_id=str(endpoint["company_id"]),
                   endpoint_id=str(endpoint["id"]), **value, issued_at=now, expires_at=now+300,
                   download_url=f"{origin}/api/agent/modules/helpdesk/package/{value['release_id']}",
                   entitled=True, admin_enabled=True, capabilities=CAPABILITIES)
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return dict(payload_b64=base64.b64encode(raw).decode(),
                signature_b64=base64.b64encode(sign_canonical_payload(payload)).decode())


def verify_request_proof(endpoint, request):
    from services.device_proof import verify_device_signature
    timestamp = request.headers.get("X-Warden-Module-Time", "")
    nonce = request.headers.get("X-Warden-Module-Nonce", "")
    if not re.fullmatch(r"[0-9]{10}", timestamp) or abs(int(timestamp)-int(time.time())) > 60 or not re.fullmatch("[0-9a-f]{32}", nonce):
        raise ValueError("Invalid module device proof")
    message = f"warden-module-v1|{endpoint['id']}|{request.method}|{request.path}|{timestamp}|{nonce}".encode()
    certificate = base64.b64decode(request.headers.get("X-Warden-Module-Certificate", ""), validate=True).decode()
    verify_device_signature(endpoint, certificate, request.headers.get("X-Warden-Module-Signature", ""), message)
    if not db.consume_rate_limit(f"module-proof:{endpoint['id']}:{nonce}", 1, 600):
        raise ValueError("Replayed module proof")
