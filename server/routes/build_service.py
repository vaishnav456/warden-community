"""
Warden — Build service routes
Windows build machine polls here for pending build requests
and uploads completed agent installers.
"""
import pathlib
import json
import re
import secrets
from flask import Blueprint, request, jsonify, send_from_directory, abort, g, current_app

import config
import db
from middleware.auth import build_service_auth_required, login_required, company_required

bp = Blueprint("build_service", __name__)
_MAX_INSTALLER_BYTES = 100 * 1024 * 1024
_CLAIM_RE = re.compile(r"^[0-9a-fA-F-]{36}$")


def _valid_claim(req):
    supplied = (request.headers.get("X-Build-Claim") or "").strip()
    expected = str(req.get("claim_token") or "")
    return bool(_CLAIM_RE.fullmatch(supplied) and expected and secrets.compare_digest(supplied, expected))


@bp.route("/api/build/pending", methods=["GET"])
@build_service_auth_required
def pending():
    """Build service polls this to get pending build requests."""
    requests_list = db.get_pending_build_requests()
    return jsonify([
        {
            "id": str(r["id"]),
            "company_id": str(r["company_id"]),
            "branch_id": str(r["branch_id"]) if r.get("branch_id") else None,
            "config_json": r["config_json"],
            "target_platform": r.get("target_platform") or "windows-amd64",
        }
        for r in requests_list
    ])


@bp.route("/api/build/<req_id>/complete", methods=["POST"])
@build_service_auth_required
def complete(req_id):
    """Build service uploads the completed installer ZIP."""
    req = db.get_build_request(req_id)
    if not req:
        abort(404)
    if req.get("status") != "building" or not _valid_claim(req):
        return jsonify({"error": "stale_build_claim"}), 409
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    f = request.files["file"]
    data = f.read(_MAX_INSTALLER_BYTES + 1)
    if len(data) > _MAX_INSTALLER_BYTES:
        return jsonify({"error": "installer_too_large"}), 413

    # sha256/agent_version describe the warden-agent.exe INSIDE the zip
    # (computed by build-service before packaging) — stored so a later
    # UPDATE_AGENT job can point at this exact build. Both optional so an
    # older build-service still uploads successfully without them.
    sha256 = (request.form.get("sha256") or "").strip().lower()
    agent_version = (request.form.get("agent_version") or "").strip()
    if sha256 and (len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256)):
        return jsonify({"error": "invalid_sha256"}), 400
    if len(agent_version) > 64:
        return jsonify({"error": "invalid_agent_version"}), 400

    artifact_url = f"/downloads/{req_id}/agent-installer.zip"
    dest_dir = config.AGENT_DIST_DIR / req_id
    staged_path = dest_dir / f"agent-installer.{req['claim_token']}.part"
    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
        staged_path.write_bytes(data)
    except OSError:
        current_app.logger.exception("Could not store generated agent archive")
        return jsonify({"error": "Agent artifact storage is temporarily unavailable."}), 503
    if not db.complete_claimed_build(
        req_id, req["claim_token"], artifact_url,
        sha256=sha256 or None, agent_version=agent_version or None,
    ):
        staged_path.unlink(missing_ok=True)
        return jsonify({"error": "stale_build_claim"}), 409
    staged_path.replace(dest_dir / "agent-installer.zip")
    return jsonify({"ok": True, "url": artifact_url})


@bp.route("/api/build/<req_id>/complete-msi", methods=["POST"])
@build_service_auth_required
def complete_msi(req_id):
    """Build service uploads the best-effort-packaged MSI (see
    build-service/builder.py's build_msi()) — separate from complete()
    since MSI packaging can fail independently without failing the
    underlying zip/install.bat build."""
    req = db.get_build_request(req_id)
    if not req:
        abort(404)
    if req.get("status") != "completed" or not _valid_claim(req):
        return jsonify({"error": "stale_build_claim"}), 409
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    f = request.files["file"]
    data = f.read(_MAX_INSTALLER_BYTES + 1)
    if len(data) > _MAX_INSTALLER_BYTES:
        return jsonify({"error": "installer_too_large"}), 413

    dest_dir = config.AGENT_DIST_DIR / req_id
    dest_path = dest_dir / "agent-installer.msi"
    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_path.write_bytes(data)
    except OSError:
        current_app.logger.exception("Could not store generated agent MSI")
        return jsonify({"error": "Agent artifact storage is temporarily unavailable."}), 503

    if not db.mark_claimed_build_msi_ready(req_id, req["claim_token"]):
        dest_path.unlink(missing_ok=True)
        return jsonify({"error": "stale_build_claim"}), 409
    return jsonify({"ok": True, "url": f"/downloads/{req_id}/agent-installer.msi"})


@bp.route("/api/build/<req_id>/fail", methods=["POST"])
@build_service_auth_required
def fail(req_id):
    body = request.get_json(silent=True) or {}
    db.update_build_request(req_id, "failed", error=body.get("error", "Build failed"))
    return jsonify({"ok": True})


@bp.route("/downloads/<req_id>/agent-installer.zip")
@login_required
@company_required
def download_installer(req_id):
    """Download a completed agent installer — the ZIP bundles config.json
    with a live, single-use enrollment token, so this must be gated behind
    the same login+company session as everything else, not just an
    unguessable req_id. (Previously had no auth at all beyond a `token`
    query param that was read but never actually validated against
    anything — anyone who obtained a build-request UUID, e.g. from a
    shared link, could download and consume another tenant's enrollment
    token.)"""
    req = db.get_build_request(req_id)
    if not req or str(req.get("company_id")) != str(g.company["id"]):
        abort(404)
    dest_dir = config.AGENT_DIST_DIR / req_id
    if not dest_dir.exists():
        abort(404)
    return send_from_directory(str(dest_dir), "agent-installer.zip", as_attachment=True)


@bp.route("/downloads/<req_id>/agent-installer.msi")
@login_required
@company_required
def download_msi(req_id):
    """Download a completed agent MSI — for GPO Software Installation,
    SCCM, or an Intune Win32 app. Same auth gating as download_installer():
    the MSI embeds a live enrollment token in config.json (see
    build-service/builder.py's build_msi()), so this must require the same
    login+company session as everything else."""
    req = db.get_build_request(req_id)
    if not req or str(req.get("company_id")) != str(g.company["id"]):
        abort(404)
    if not req.get("msi_ready"):
        abort(404)
    dest_dir = config.AGENT_DIST_DIR / req_id
    if not dest_dir.exists():
        abort(404)
    return send_from_directory(str(dest_dir), "agent-installer.msi", as_attachment=True)
