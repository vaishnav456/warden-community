"""
Warden — App Library routes
Upload, manage, and deploy software packages.
"""
import os
import hashlib
import pathlib
from flask import Blueprint, render_template, request, jsonify, g, abort, send_from_directory, current_app

import config
import db
from middleware.auth import login_required, company_required, role_required, require_branch_scope

bp = Blueprint("apps", __name__)

# Every accepted format must be executable by at least one shipping agent.
ALLOWED_EXTENSIONS = {".exe", ".msi", ".deb", ".rpm", ".pkg"}
MAX_FILE_SIZE = 500 * 1024 * 1024  # 500 MB


@bp.route("/apps")
@login_required
@company_required
def library():
    company_id = g.company["id"]
    apps = db.get_app_library(company_id, include_global=True)
    endpoints = db.get_endpoints(company_id)
    if g.admin.get("role") == "branch_admin":
        endpoints = [ep for ep in endpoints if str(ep.get("branch_id")) == str(g.admin.get("branch_id"))]
    return render_template("apps/library.html", apps=apps, endpoints=endpoints)


@bp.route("/apps/upload", methods=["POST"])
@login_required
@company_required
@role_required("company_admin", "branch_admin")
def upload():
    from services.entitlements import check_job
    entitlement = check_job(g.company["id"], "INSTALL_APP")
    if not entitlement.allowed:
        return jsonify({"error": entitlement.code, "message": entitlement.message}), 403
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    f = request.files["file"]
    name = request.form.get("name", "").strip()
    version = request.form.get("version", "").strip()
    description = request.form.get("description", "").strip()
    install_args = request.form.get("install_args", "").strip()
    self_service = request.form.get("self_service") == "1"
    scope = request.form.get("scope", "company")  # "company" or "global"

    if not name or not version:
        return jsonify({"error": "Name and version required"}), 400
    if len(name) > 160 or len(version) > 80 or len(description) > 1000 or len(install_args) > 500:
        return jsonify({"error": "App metadata is too long"}), 400

    filename = f.filename or ""
    ext = pathlib.Path(filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        return jsonify({"error": f"File type {ext} not allowed"}), 400

    # Read and hash
    data = f.read(MAX_FILE_SIZE + 1)
    if len(data) > MAX_FILE_SIZE:
        return jsonify({"error": "File too large (max 500 MB)"}), 413

    sha256 = hashlib.sha256(data).hexdigest()

    # Store file
    dest_dir = config.UPLOAD_DIR / "apps" / sha256[:2]
    dest_path = dest_dir / f"{sha256}{ext}"
    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_path.write_bytes(data)
    except OSError:
        current_app.logger.exception("Could not store application package")
        return jsonify({"error": "Application storage is temporarily unavailable. Please retry."}), 503

    company_id = g.company["id"]

    app = db.create_app(
        name=name,
        version=version,
        sha256=sha256,
        file_path=str(dest_path.relative_to(config.UPLOAD_DIR)),
        size_bytes=len(data),
        company_id=company_id,
        description=description,
        install_args=install_args,
        self_service=self_service,
    )
    db.audit(g.company["id"], g.admin["id"], "app_uploaded",
             {"name": name, "version": version, "sha256": sha256})

    return jsonify({"ok": True, "app_id": str(app["id"]) if app else None})


def _managed_app(app_id):
    app = db.get_app(app_id)
    if not app:
        abort(404)
    if not app.get("company_id") or str(app["company_id"]) != str(g.company["id"]):
        abort(404)
    return app


@bp.route("/apps/<app_id>/update", methods=["POST"])
@login_required
@company_required
@role_required("company_admin")
def update(app_id):
    from services.entitlements import check_mutation
    decision = check_mutation(g.company["id"])
    if not decision.allowed:
        return jsonify({"error": decision.code, "message": decision.message}), 403
    app = _managed_app(app_id)
    body = request.get_json(silent=True) or request.form
    values = {
        "name": str(body.get("name") or "").strip(),
        "version": str(body.get("version") or "").strip(),
        "description": str(body.get("description") or "").strip(),
        "install_args": str(body.get("install_args") or "").strip(),
        "self_service": str(body.get("self_service") or "").lower() in {"1", "true", "on"},
    }
    if not values["name"] or not values["version"]:
        return jsonify({"error": "Name and version required"}), 400
    if len(values["name"]) > 160 or len(values["version"]) > 80 or len(values["description"]) > 1000 or len(values["install_args"]) > 500:
        return jsonify({"error": "App metadata is too long"}), 400
    db.update_app(app_id, values)
    db.audit(g.company["id"], g.admin["id"], "app_updated", {
        "app_id": app_id, "name": values["name"], "version": values["version"],
    })
    return jsonify({"ok": True})


@bp.route("/apps/<app_id>/delete", methods=["POST"])
@login_required
@company_required
@role_required("company_admin")
def delete(app_id):
    from services.entitlements import check_mutation
    decision = check_mutation(g.company["id"])
    if not decision.allowed:
        return jsonify({"error": decision.code, "message": decision.message}), 403
    app = _managed_app(app_id)
    db.delete_app(app_id)
    db.audit(g.company["id"], g.admin["id"], "app_deleted", {
        "app_id": app_id, "name": app.get("name"), "sha256": app.get("sha256"),
    })
    return jsonify({"ok": True})


@bp.route("/apps/<app_id>/deploy", methods=["POST"])
@login_required
@company_required
@role_required("company_admin", "branch_admin", "technician")
def deploy(app_id):
    app = db.get_app(app_id)
    if not app or (app.get("company_id") and str(app["company_id"]) != str(g.company["id"])):
        abort(404)
    body = request.get_json(silent=True) or {}
    endpoint_ids = body.get("endpoint_ids")
    if not isinstance(endpoint_ids, list) or not 1 <= len(endpoint_ids) <= 500:
        return jsonify({"error": "Select between 1 and 500 endpoints"}), 400
    endpoint_ids = list(dict.fromkeys(str(value) for value in endpoint_ids))
    from services.entitlements import check_job
    decision = check_job(g.company["id"], "INSTALL_APP")
    if not decision.allowed:
        return jsonify({"error": decision.code, "message": decision.message}), 403
    ext = pathlib.Path(app.get("file_path") or "").suffix.lower()
    compatible = {
        "windows": {".exe", ".msi"}, "linux": {".deb", ".rpm"}, "darwin": {".pkg"},
    }
    dispatched = 0
    skipped = 0
    for endpoint_id in endpoint_ids:
        endpoint = db.get_endpoint(endpoint_id)
        if not endpoint or str(endpoint.get("company_id")) != str(g.company["id"]):
            skipped += 1
            continue
        require_branch_scope(endpoint.get("branch_id"))
        platform = str(endpoint.get("platform") or "windows").lower()
        capabilities = set(endpoint.get("capabilities") or [])
        if ext not in compatible.get(platform, set()) or (capabilities and "INSTALL_APP" not in capabilities):
            skipped += 1
            continue
        job = db.create_job(
            g.company["id"], endpoint.get("branch_id"), endpoint_id, "INSTALL_APP",
            {
                "app_url": f"{config.SERVER_URL}/api/agent/apps/{app_id}/download",
                "sha256": app["sha256"], "ext": ext,
                "install_args": app.get("install_args") or "",
                "require_authenticode": bool(
                    config.REQUIRE_SIGNED_WINDOWS_APPS and platform == "windows"
                ),
            },
            g.admin["id"],
        )
        if job:
            dispatched += 1
        else:
            skipped += 1
    db.audit(g.company["id"], g.admin["id"], "app_bulk_deployed", {
        "app_id": app_id, "name": app.get("name"), "dispatched": dispatched, "skipped": skipped,
    })
    return jsonify({"ok": True, "dispatched": dispatched, "skipped": skipped})


@bp.route("/apps/<app_id>/download")
@login_required
@company_required
def download(app_id):
    """Serve installer file for agent download (over VPN)."""
    app = db.get_app(app_id)
    if not app:
        abort(404)
    # Verify app belongs to this company or is global
    if app.get("company_id") and str(app["company_id"]) != str(g.company["id"]):
        abort(403)

    file_path = config.UPLOAD_DIR / app["file_path"]
    if not file_path.exists():
        abort(404)

    return send_from_directory(
        str(file_path.parent),
        file_path.name,
        as_attachment=True,
    )
