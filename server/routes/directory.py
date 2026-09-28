"""Organization-scoped centralized Windows account directory."""
import base64
import binascii
import csv
import hashlib
import io
import math
import re
import secrets
import struct
import string
import urllib.error
from datetime import datetime, timedelta, timezone

from flask import Blueprint, Response, abort, g, jsonify, make_response, render_template, request, url_for

import db
from middleware.auth import company_required, login_required, role_required
from middleware.security import check_rate_limit

bp = Blueprint("directory", __name__)
ACCOUNT_TYPES = {"", "local", "domain", "entra", "microsoft", "unknown"}
ACCESS_FILTERS = {"", "admin", "standard", "disabled"}
SORT_OPTIONS = {"name", "endpoints", "access", "recent"}
PAGE_SIZE = 50
WINDOWS_USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,20}$")
LOGIN_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$"
)
WINDOWS_RESERVED_NAMES = {
    "con", "prn", "aux", "nul", "clock$",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}
PROFILE_PHOTO_PREFIX = "data:image/png;base64,"
MAX_PROFILE_PHOTO_BYTES = 512 * 1024
MAX_PROFILE_PHOTO_SIDE = 512


def _normalize_profile_photo(value):
    """Validate and canonicalize the browser-generated square PNG avatar."""
    if value in (None, ""):
        return "", "", None
    if not isinstance(value, str) or not value.startswith(PROFILE_PHOTO_PREFIX):
        return None, None, "Profile picture must be a PNG image."
    encoded = value[len(PROFILE_PHOTO_PREFIX):]
    if len(encoded) > ((MAX_PROFILE_PHOTO_BYTES + 2) // 3) * 4 + 4:
        return None, None, "Profile picture is too large."
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        return None, None, "Profile picture is not valid base64 data."
    if not 24 <= len(raw) <= MAX_PROFILE_PHOTO_BYTES:
        return None, None, "Profile picture must be 512 KB or smaller."
    if raw[:8] != b"\x89PNG\r\n\x1a\n" or raw[12:16] != b"IHDR":
        return None, None, "Profile picture must be a valid PNG image."
    width, height = struct.unpack(">II", raw[16:24])
    if not (1 <= width <= MAX_PROFILE_PHOTO_SIDE and 1 <= height <= MAX_PROFILE_PHOTO_SIDE):
        return None, None, "Profile picture dimensions must be at most 512 × 512 pixels."
    canonical = PROFILE_PHOTO_PREFIX + base64.b64encode(raw).decode("ascii")
    return canonical, "image/png", None


def _profile_photo_response(data_url, mime):
    if not data_url or mime != "image/png" or not data_url.startswith(PROFILE_PHOTO_PREFIX):
        abort(404)
    try:
        raw = base64.b64decode(data_url[len(PROFILE_PHOTO_PREFIX):], validate=True)
    except (ValueError, binascii.Error):
        abort(404)
    response = Response(raw, mimetype="image/png")
    response.headers["Cache-Control"] = "private, max-age=300"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


def _password_error(password, username=""):
    if len(password) < 12 or len(password) > 128:
        return "Password must be between 12 and 128 characters."
    checks = (
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password),
    )
    if not all(checks):
        return "Password must include uppercase, lowercase, number, and symbol."
    if username and username.casefold() in password.casefold():
        return "Password must not contain the username."
    return None


def generate_endpoint_password(length=20):
    """Return a cryptographically-random, policy-friendly one-time password.

    Directory assignment deliberately generates a different credential for
    every local account.  A caller-supplied shared password would turn one
    compromised workstation into a credential for every assigned endpoint.
    """
    groups = (
        string.ascii_uppercase.replace("I", "").replace("O", ""),
        string.ascii_lowercase.replace("l", "").replace("o", ""),
        "23456789",
        "!@#$%&*_-",
    )
    chars = [secrets.choice(group) for group in groups]
    alphabet = "".join(groups)
    chars.extend(secrets.choice(alphabet) for _ in range(max(0, length - len(chars))))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def group_directory_accounts(rows):
    """Collapse the same stable SID across endpoints into one identity."""
    grouped = {}
    for row in rows:
        endpoint = row.get("endpoints") or {}
        sid = str(row.get("sid") or "").strip()
        account_type = str(row.get("account_type") or "unknown").lower()
        domain = str(row.get("domain_name") or "").strip()
        username = str(row.get("username") or "").strip()
        # Local accounts without a SID must never merge merely because two
        # computers both have an account called Administrator or Guest.
        if sid:
            identity_key = "sid:" + sid.casefold()
        elif account_type == "local":
            identity_key = f"local:{endpoint.get('id')}:{username.casefold()}"
        else:
            identity_key = f"name:{account_type}:{domain.casefold()}:{username.casefold()}"

        identity = grouped.setdefault(identity_key, {
            "key": identity_key,
            "sid": sid,
            "username": username,
            "display_name": row.get("display_name") or "",
            "principal_name": row.get("principal_name") or username,
            "account_type": account_type,
            "domain_name": domain,
            "is_admin": False,
            "all_enabled": True,
            "accounts": [],
            "last_synced": None,
            "profile_photo_endpoint_id": None,
            "profile_photo_user_id": None,
        })
        if not identity["display_name"] and row.get("display_name"):
            identity["display_name"] = row["display_name"]
        if not identity["principal_name"] and row.get("principal_name"):
            identity["principal_name"] = row["principal_name"]
        identity["is_admin"] = identity["is_admin"] or bool(row.get("is_admin"))
        identity["all_enabled"] = identity["all_enabled"] and bool(row.get("is_enabled", True))
        identity["accounts"].append({
            "id": row.get("id"),
            "endpoint_id": row.get("endpoint_id"),
            "hostname": endpoint.get("hostname") or "Unknown endpoint",
            "endpoint_status": endpoint.get("status") or "unknown",
            "branch_id": endpoint.get("branch_id"),
            "username": username,
            "is_admin": bool(row.get("is_admin")),
            "is_enabled": bool(row.get("is_enabled", True)),
            "last_synced": row.get("last_synced"),
            "profile_photo_mime": row.get("profile_photo_mime"),
        })
        if row.get("profile_photo_mime") and not identity["profile_photo_user_id"]:
            identity["profile_photo_endpoint_id"] = row.get("endpoint_id")
            identity["profile_photo_user_id"] = row.get("id")
        synced = row.get("last_synced")
        if synced and (not identity["last_synced"] or synced > identity["last_synced"]):
            identity["last_synced"] = synced

    identities = list(grouped.values())
    for identity in identities:
        identity["accounts"].sort(key=lambda x: x["hostname"].casefold())
    identities.sort(key=lambda x: (
        (x["display_name"] or x["principal_name"] or x["username"]).casefold(),
        x["sid"],
    ))
    return identities


def filter_directory_accounts(identities, query="", account_type="", access="", sort="name"):
    if account_type:
        identities = [item for item in identities if item["account_type"] == account_type]
    if access == "admin":
        identities = [item for item in identities if item["is_admin"]]
    elif access == "standard":
        identities = [item for item in identities if not item["is_admin"]]
    elif access == "disabled":
        identities = [item for item in identities if not item["all_enabled"]]
    if query:
        needle = query.casefold()
        identities = [
            item for item in identities
            if needle in " ".join([
                item.get("display_name") or "", item.get("username") or "",
                item.get("principal_name") or "", item.get("sid") or "",
                item.get("domain_name") or "",
                " ".join(account["hostname"] for account in item["accounts"]),
            ]).casefold()
        ]

    name_key = lambda item: (
        (item["display_name"] or item["principal_name"] or item["username"]).casefold(),
        item["sid"],
    )
    if sort == "endpoints":
        identities.sort(key=lambda item: (-len(item["accounts"]), name_key(item)))
    elif sort == "access":
        identities.sort(key=lambda item: (not item["is_admin"], item["all_enabled"], name_key(item)))
    elif sort == "recent":
        identities.sort(key=lambda item: (item["last_synced"] or "", name_key(item)), reverse=True)
    else:
        identities.sort(key=name_key)
    return identities


def _directory_request():
    company_id = g.company["id"]
    requested_branch = request.args.get("branch_id", "").strip() or None
    if g.admin.get("role") == "branch_admin":
        branch_id = g.admin.get("branch_id")
        if not branch_id:
            abort(403)
    else:
        branch_id = requested_branch

    branches = db.get_branches(company_id)
    branch_ids = {str(branch["id"]) for branch in branches}
    if branch_id and str(branch_id) not in branch_ids:
        abort(404)
    if g.admin.get("role") == "branch_admin":
        branches = [b for b in branches if str(b["id"]) == str(branch_id)]

    account_type = request.args.get("type", "").strip().lower()
    access = request.args.get("access", "").strip().lower()
    sort = request.args.get("sort", "name").strip().lower()
    account_type = account_type if account_type in ACCOUNT_TYPES else ""
    access = access if access in ACCESS_FILTERS else ""
    sort = sort if sort in SORT_OPTIONS else "name"
    query = request.args.get("q", "").strip()[:200]

    rows = db.get_company_windows_users(company_id, branch_id=branch_id)
    identities = filter_directory_accounts(
        group_directory_accounts(rows), query, account_type, access, sort,
    )
    return identities, branches, str(branch_id or ""), account_type, access, sort, query


def _csv_cell(value):
    """Prevent spreadsheet formula execution when an exported CSV is opened."""
    text = str(value or "")
    if text.startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def _scoped_endpoints():
    """Return active endpoints the current admin may operate on."""
    branch_id = g.admin.get("branch_id") if g.admin.get("role") == "branch_admin" else None
    if g.admin.get("role") == "branch_admin" and not branch_id:
        abort(403)
    endpoints = db.get_endpoints(g.company["id"], branch_id=branch_id)
    branch_names = {str(branch["id"]): branch["name"] for branch in db.get_branches(g.company["id"])}
    for endpoint in endpoints:
        endpoint["branch_name"] = branch_names.get(str(endpoint.get("branch_id") or ""), "Unassigned")
        endpoint["warden_identity_ready"] = (
            (endpoint.get("platform") or "windows") == "windows"
            and "PROVISION_WARDEN_IDENTITY" in (endpoint.get("capabilities") or [])
            and "WARDEN_SHADOW_CREDENTIAL" in (endpoint.get("capabilities") or [])
        )
        endpoint["warden_signin_ready"] = (
            "WARDEN_SIGNIN" in (endpoint.get("capabilities") or [])
        )
    return endpoints


@bp.route("/directory")
@login_required
@company_required
def index():
    identities, branches, branch_id, account_type, access, sort, query = _directory_request()

    summary = {
        "identities": len(identities),
        "accounts": sum(len(item["accounts"]) for item in identities),
        "privileged": sum(1 for item in identities if item["is_admin"]),
        "disabled": sum(1 for item in identities if not item["all_enabled"]),
    }
    total = len(identities)
    try:
        requested_page = int(request.args.get("page", "1"))
    except (TypeError, ValueError):
        requested_page = 1
    pages = max(1, math.ceil(total / PAGE_SIZE))
    page = min(max(1, requested_page), pages)
    start = (page - 1) * PAGE_SIZE
    page_identities = identities[start:start + PAGE_SIZE]
    filter_args = {
        key: value for key, value in {
            "q": query, "type": account_type, "access": access,
            "sort": sort if sort != "name" else "", "branch_id": branch_id,
        }.items() if value
    }
    endpoints = _scoped_endpoints()
    allowed_endpoint_ids = {str(endpoint["id"]) for endpoint in endpoints}
    warden_identities = []
    for identity in db.get_warden_identities(g.company["id"]):
        assignments = []
        for assignment in identity.pop("warden_identity_assignments", []) or []:
            endpoint = assignment.get("endpoints") or {}
            if str(assignment.get("endpoint_id")) not in allowed_endpoint_ids:
                continue
            if not endpoint.get("is_active", True):
                continue
            assignment["endpoint"] = endpoint
            assignments.append(assignment)
        identity["assignments"] = assignments
        if g.admin.get("role") != "branch_admin" or assignments:
            warden_identities.append(identity)
    return render_template(
        "directory/index.html",
        company=g.company,
        active_page="directory",
        identities=page_identities,
        summary=summary,
        branches=branches,
        selected_branch=str(branch_id or ""),
        selected_type=account_type,
        selected_access=access,
        selected_sort=sort,
        query=query,
        total=total,
        result_start=start + 1 if total else 0,
        result_end=min(start + PAGE_SIZE, total),
        page=page,
        pages=pages,
        prev_url=url_for("directory.index", **filter_args, page=page - 1) if page > 1 else None,
        next_url=url_for("directory.index", **filter_args, page=page + 1) if page < pages else None,
        export_url=url_for("directory.export_csv", **filter_args),
        directory_endpoints=endpoints,
        warden_identities=warden_identities,
        identity_login_events=db.get_warden_identity_login_events(g.company["id"], 20),
    )


@bp.route("/directory/identities/<identity_id>/photo")
@login_required
@company_required
def warden_identity_photo(identity_id):
    identity = db.get_warden_identity(identity_id, g.company["id"])
    if not identity:
        abort(404)
    return _profile_photo_response(
        identity.get("profile_photo"), identity.get("profile_photo_mime")
    )


def _validate_identity_request(body, require_password=True):
    login_email = str(body.get("login_email") or "").strip().lower()
    username = str(body.get("username") or "").strip()
    if login_email:
        local_part = re.sub(r"[^A-Za-z0-9._-]+", "-", login_email.split("@", 1)[0]).strip(".-_")
        local_part = local_part or "warden"
        suffix = hashlib.sha256(login_email.encode()).hexdigest()[:6]
        username = f"{local_part[:13]}-{suffix}"
    display_name = str(body.get("display_name") or "").strip()
    password = str(body.get("password") or "")
    endpoint_ids = body.get("endpoint_ids")
    is_admin = body.get("is_admin", False)
    profile_photo, profile_photo_mime, photo_error = _normalize_profile_photo(
        body.get("profile_photo")
    )
    if login_email and (len(login_email) > 254 or not LOGIN_EMAIL_RE.fullmatch(login_email)
                        or "." not in login_email.rsplit("@", 1)[1]):
        return None, (jsonify({"error": "invalid_login_email", "message":
                               "Enter a valid organization email address."}), 400)
    if (not WINDOWS_USERNAME_RE.fullmatch(username)
            or username.casefold() in WINDOWS_RESERVED_NAMES
            or username.endswith(".")):
        return None, (jsonify({"error": "invalid_username", "message":
                               "Use 1–20 letters, numbers, dots, underscores, or hyphens."}), 400)
    if not display_name or len(display_name) > 256:
        return None, (jsonify({"error": "invalid_display_name", "message": "Display name is too long."}), 400)
    if require_password:
        error = _password_error(password, username)
        if error:
            return None, (jsonify({"error": "weak_password", "message": error}), 400)
    if not isinstance(endpoint_ids, list) or not 1 <= len(endpoint_ids) <= 100:
        return None, (jsonify({"error": "invalid_endpoints", "message": "Select between 1 and 100 endpoints."}), 400)
    if not isinstance(is_admin, bool):
        return None, (jsonify({"error": "invalid_options", "message": "Invalid account options."}), 400)
    if photo_error:
        return None, (jsonify({"error": "invalid_profile_photo", "message": photo_error}), 400)
    return {
        "username": username, "login_email": login_email or None,
        "display_name": display_name, "password": password,
        "endpoint_ids": list(dict.fromkeys(str(value) for value in endpoint_ids)),
        "is_admin": is_admin, "profile_photo": profile_photo,
        "profile_photo_mime": profile_photo_mime,
    }, None


def _identity_targets(endpoint_ids):
    allowed = {str(endpoint["id"]): endpoint for endpoint in _scoped_endpoints()}
    if any(endpoint_id not in allowed for endpoint_id in endpoint_ids):
        return None
    if any((allowed[endpoint_id].get("platform") or "windows") != "windows"
           for endpoint_id in endpoint_ids):
        return None
    if any(not {"PROVISION_WARDEN_IDENTITY", "WARDEN_SHADOW_CREDENTIAL"}.issubset(
        set(allowed[endpoint_id].get("capabilities") or [])
    ) for endpoint_id in endpoint_ids):
        return None
    return allowed


@bp.route("/directory/identities", methods=["POST"])
@login_required
@company_required
@role_required("company_admin")
def create_warden_identity():
    """Create a Warden identity and provision device-only shadow accounts.

    The reusable password is retained only as a bcrypt verifier and is never
    placed in an endpoint job. Each agent creates its own random DPAPI-bound
    local credential for the Windows shadow account.
    """
    body, error_response = _validate_identity_request(
        request.get_json(silent=True) or {}, require_password=False,
    )
    if error_response:
        return error_response
    allowed = _identity_targets(body["endpoint_ids"])
    if allowed is None:
        return jsonify({"error": "endpoint_not_found", "message": "One or more Windows endpoints are unavailable."}), 404

    inventory = db.get_company_windows_users(
        g.company["id"],
        branch_id=g.admin.get("branch_id") if g.admin.get("role") == "branch_admin" else None,
    )
    conflicts = [row for row in inventory
                 if str(row.get("endpoint_id")) in body["endpoint_ids"]
                 and str(row.get("username") or "").casefold() == body["username"].casefold()]
    if conflicts:
        return jsonify({
            "error": "local_account_conflict",
            "message": "That username already exists locally on a selected endpoint. Choose another username; Warden will not take over an unmanaged account.",
        }), 409

    from routes.auth import _hash_password
    setup_token = secrets.token_urlsafe(32)
    setup_hash = hashlib.sha256(setup_token.encode()).hexdigest()
    setup_expires = datetime.now(timezone.utc) + timedelta(hours=24)
    # The placeholder is random and never disclosed, so the identity cannot
    # authenticate before its owner completes the one-time setup link.
    placeholder_hash = _hash_password(secrets.token_urlsafe(48))
    try:
        result = db.create_warden_identity_with_setup_and_jobs(
            g.company, body["username"], body["login_email"], body["display_name"],
            placeholder_hash, body["is_admin"], g.admin["id"],
            body["endpoint_ids"],
            {"username": body["username"], "credential_mode": "managed_shadow_v1",
             "full_name": body["display_name"], "is_admin": body["is_admin"],
             "must_change_password": False, "password_version": 1,
             "profile_photo": body["profile_photo"]},
            setup_hash, setup_expires.isoformat(),
            profile_photo=body["profile_photo"],
            profile_photo_mime=body["profile_photo_mime"],
        )
    except urllib.error.HTTPError as exc:
        if exc.code == 409:
            return jsonify({"error": "identity_exists", "message": "A Warden identity with that username already exists."}), 409
        raise
    if not result:
        return jsonify({"error": "create_failed", "message": "Could not create the Warden identity."}), 500

    db.audit(g.company["id"], g.admin["id"], "warden_identity_created", {
        "identity_id": str(result["identity_id"]), "username": body["username"],
        "login_email": body["login_email"],
        "endpoint_ids": body["endpoint_ids"], "is_admin": body["is_admin"],
    })
    queued = int(result.get("queued") or 0)
    setup_url = url_for("directory.setup_warden_identity_password",
                        token=setup_token, _external=True)
    response = jsonify({"ok": True, "identity_id": result["identity_id"], "queued_count": queued,
                        "setup_url": setup_url,
                        "message": f"Identity assigned to {queued} endpoint(s). The user signs in with {body['login_email'] or body['username']}."})
    response.headers["Cache-Control"] = "no-store"
    return response, 201


@bp.route("/directory/identities/<identity_id>/password", methods=["POST"])
@login_required
@company_required
@role_required("company_admin")
def reset_warden_identity_password(identity_id):
    identity = db.get_warden_identity(identity_id, g.company["id"])
    if not identity:
        abort(404)
    setup_token = secrets.token_urlsafe(32)
    setup_hash = hashlib.sha256(setup_token.encode()).hexdigest()
    setup_expires = datetime.now(timezone.utc) + timedelta(hours=24)
    db.update_warden_identity(identity_id, g.company["id"], {
        # This is a reset for an already-active identity. Keep the existing
        # password usable until the owner consumes the one-time link.
        "password_setup_required": False,
        "password_setup_token_hash": setup_hash,
        "password_setup_expires_at": setup_expires.isoformat(),
    })
    setup_url = url_for("directory.setup_warden_identity_password",
                        token=setup_token, _external=True)
    db.audit(g.company["id"], g.admin["id"], "warden_identity_password_reset", {
        "identity_id": identity_id, "setup_expires_at": setup_expires.isoformat(),
    })
    response = jsonify({"ok": True, "queued_count": 0, "setup_url": setup_url,
                        "message": "A one-time password setup link was created. The current password remains valid until the user completes it."})
    response.headers["Cache-Control"] = "no-store"
    return response


@bp.route("/identity/setup/<token>", methods=["GET", "POST"])
def setup_warden_identity_password(token):
    """One-time, user-operated Warden password setup/reset flow."""
    if not re.fullmatch(r"[A-Za-z0-9_-]{40,64}", token):
        abort(404)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    identity = db.get_warden_identity_for_password_setup(token_hash)
    expired = True
    if identity:
        try:
            expires = datetime.fromisoformat(
                str(identity.get("password_setup_expires_at") or "").replace("Z", "+00:00")
            )
            expired = expires <= datetime.now(timezone.utc)
        except ValueError:
            expired = True
    if not identity or expired:
        response = render_template("identity_password_setup.html", expired=True)
        return response, 410

    error = None
    completed = False
    if request.method == "POST":
        if not check_rate_limit(f"identity-setup:{token_hash}", 10, fail_closed=True):
            error = "Too many attempts. Try again shortly."
        else:
            password = str(request.form.get("password") or "")
            confirmation = str(request.form.get("password_confirm") or "")
            error = _password_error(password, identity["username"])
            if not error and password != confirmation:
                error = "Passwords do not match."
            if not error:
                from routes.auth import _hash_password
                result = db.complete_warden_identity_password_setup(
                    token_hash, _hash_password(password),
                )
                completed = bool(result)
                if not completed:
                    error = "This setup link has expired or was already used."

    response = make_response(render_template(
        "identity_password_setup.html", identity=identity,
        expired=False, error=error, completed=completed,
    ))
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@bp.route("/directory/identities/<identity_id>/assignments", methods=["POST"])
@login_required
@company_required
@role_required("company_admin")
def reassign_warden_identity(identity_id):
    identity = db.get_warden_identity(identity_id, g.company["id"])
    if not identity:
        abort(404)
    body = request.get_json(silent=True) or {}
    endpoint_ids = body.get("endpoint_ids")
    if not isinstance(endpoint_ids, list) or not 1 <= len(endpoint_ids) <= 100:
        return jsonify({"error": "invalid_endpoints", "message": "Select between 1 and 100 endpoints."}), 400
    endpoint_ids = list(dict.fromkeys(str(value) for value in endpoint_ids))
    if _identity_targets(endpoint_ids) is None:
        return jsonify({"error": "endpoint_not_ready", "message": "Every selected PC must be a scoped Windows endpoint that supports Warden identity provisioning."}), 409
    result = db.reassign_warden_identity(
        g.company, identity_id, endpoint_ids, g.admin["id"],
        {"username": identity["username"], "credential_mode": "managed_shadow_v1",
         "full_name": identity.get("display_name") or "", "is_admin": identity["is_admin"],
         "must_change_password": False, "password_version": identity["password_version"],
         "profile_photo": identity.get("profile_photo") or ""},
        {"username": identity["username"]},
    )
    if not result:
        return jsonify({"error": "assignment_failed", "message": "Could not update endpoint assignments."}), 500
    provisioned = int(result.get("provisioned") or 0)
    revoked = int(result.get("revoked") or 0)
    db.audit(g.company["id"], g.admin["id"], "warden_identity_reassigned", {
        "identity_id": identity_id, "endpoint_ids": endpoint_ids,
        "provisioned": provisioned, "revoked": revoked,
    })
    return jsonify({"ok": True, "provisioned": provisioned, "revoked": revoked,
                    "message": f"Assignment updated: {provisioned} added, {revoked} removed."})


@bp.route("/directory/identities/<identity_id>/repair", methods=["POST"])
@login_required
@company_required
@role_required("company_admin")
def repair_warden_identity(identity_id):
    """Rotate missing/drifted device-only shadow credentials.

    Recovery is deliberately an explicit organization-admin action. The signed job
    may adopt an existing local account only when it is already represented by
    an active Warden assignment for this organization and endpoint.
    """
    identity = db.get_warden_identity(identity_id, g.company["id"])
    if not identity:
        abort(404)
    expanded = next((item for item in db.get_warden_identities(g.company["id"])
                     if str(item["id"]) == str(identity_id)), None)
    allowed = {str(endpoint["id"]): endpoint for endpoint in _scoped_endpoints()}
    assignments = [item for item in (expanded or {}).get("warden_identity_assignments", [])
                   if item.get("status") != "revoked" and str(item.get("endpoint_id")) in allowed]
    if not assignments:
        return jsonify({"error": "no_assignments", "message": "This identity has no repairable endpoint assignments."}), 409

    queued = 0
    for assignment in assignments:
        endpoint = allowed[str(assignment["endpoint_id"])]
        payload = {
            "username": identity["username"], "credential_mode": "managed_shadow_v1",
            "full_name": identity.get("display_name") or "", "is_admin": bool(identity["is_admin"]),
            "must_change_password": False, "password_version": identity["password_version"],
            "profile_photo": identity.get("profile_photo") or "", "recover_existing": True,
        }
        job = db.create_job(
            g.company["id"], endpoint.get("branch_id"), endpoint["id"],
            "PROVISION_WARDEN_IDENTITY", payload, g.admin["id"],
        )
        if not job:
            continue
        db.upsert_warden_identity_assignment(
            identity_id, endpoint["id"], "pending", identity["password_version"], job["id"],
        )
        queued += 1
    if not queued:
        return jsonify({"error": "repair_failed", "message": "No identity repair jobs could be queued."}), 500
    db.audit(g.company["id"], g.admin["id"], "warden_identity_repair_queued", {
        "identity_id": identity_id, "endpoint_count": queued,
    })
    return jsonify({"ok": True, "queued_count": queued,
                    "message": f"Identity repair queued on {queued} endpoint(s)."})


@bp.route("/directory/identities/<identity_id>/state", methods=["POST"])
@login_required
@company_required
@role_required("company_admin")
def set_warden_identity_state(identity_id):
    identity = db.get_warden_identity(identity_id, g.company["id"])
    if not identity:
        abort(404)
    enabled = (request.get_json(silent=True) or {}).get("enabled")
    if not isinstance(enabled, bool):
        return jsonify({"error": "invalid_state", "message": "enabled must be true or false."}), 400
    operation = "ENABLE_USER" if enabled else "DISABLE_USER"
    queued = int(db.set_warden_identity_enabled(
        g.company, identity_id, enabled, g.admin["id"],
        {"username": identity["username"]},
    ) or 0)
    db.audit(g.company["id"], g.admin["id"], "warden_identity_state_changed", {
        "identity_id": identity_id, "enabled": enabled, "endpoint_count": queued,
    })
    return jsonify({"ok": True, "queued_count": queued,
                    "message": f"Identity {'enable' if enabled else 'disable'} queued on {queued} endpoint(s)."})


@bp.route("/directory/identities/<identity_id>/security", methods=["POST"])
@login_required
@company_required
@role_required("company_admin")
def set_warden_identity_security(identity_id):
    identity = db.get_warden_identity(identity_id, g.company["id"])
    if not identity:
        abort(404)
    body = request.get_json(silent=True) or {}
    offline_hours = body.get("offline_access_hours")
    start_hour = body.get("utc_start_hour")
    end_hour = body.get("utc_end_hour")
    require_compliant = body.get("require_compliant", False)
    if not isinstance(offline_hours, int) or not 0 <= offline_hours <= 720:
        return jsonify({"error": "invalid_offline_hours", "message": "Offline access must be between 0 and 720 hours."}), 400
    if (start_hour is None) != (end_hour is None):
        return jsonify({"error": "invalid_hours", "message": "Provide both UTC start and end hours, or neither."}), 400
    if start_hour is not None and (not isinstance(start_hour, int) or not isinstance(end_hour, int)
                                   or not 0 <= start_hour <= 23 or not 0 <= end_hour <= 23
                                   or start_hour == end_hour):
        return jsonify({"error": "invalid_hours", "message": "UTC hours must be different values from 0 to 23."}), 400
    if not isinstance(require_compliant, bool):
        return jsonify({"error": "invalid_policy"}), 400
    policy = {"require_compliant": require_compliant}
    if start_hour is not None:
        policy.update({"utc_start_hour": start_hour, "utc_end_hour": end_hour})
    db.update_warden_identity(identity_id, g.company["id"], {
        "offline_access_hours": offline_hours,
        "conditional_access": policy,
    })
    db.audit(g.company["id"], g.admin["id"], "warden_identity_security_updated", {
        "identity_id": identity_id, "offline_access_hours": offline_hours,
        "conditional_access": policy,
    })
    return jsonify({"ok": True, "message": "Identity security policy updated; cached sessions were revoked."})


@bp.route("/directory/users", methods=["POST"])
@login_required
@company_required
@role_required("company_admin", "branch_admin")
def create_local_user():
    """Provision independently secured local accounts on selected endpoints.

    Each newly-created or explicitly rotated account receives a unique
    server-generated password.  Credentials are returned once in the response,
    are excluded from audit records, and remain encrypted only inside the
    queued job until the agent consumes it.
    """
    body = request.get_json(silent=True) or {}
    username = str(body.get("username") or "").strip()
    full_name = str(body.get("full_name") or "").strip()
    endpoint_ids = body.get("endpoint_ids")
    is_admin = body.get("is_admin", False)
    delete_unselected = body.get("delete_unselected", False)
    rotate_passwords = body.get("rotate_passwords", False)
    profile_photo, _, photo_error = _normalize_profile_photo(body.get("profile_photo"))

    if (not WINDOWS_USERNAME_RE.fullmatch(username)
            or username.casefold() in WINDOWS_RESERVED_NAMES
            or username.endswith(".")):
        return jsonify({
            "error": "invalid_username",
            "message": "Use 1–20 letters, numbers, dots, underscores, or hyphens.",
        }), 400
    if len(full_name) > 256:
        return jsonify({"error": "invalid_full_name", "message": "Full name is too long."}), 400
    if not isinstance(endpoint_ids, list) or not 1 <= len(endpoint_ids) <= 100:
        return jsonify({
            "error": "invalid_endpoints",
            "message": "Select between 1 and 100 endpoints.",
        }), 400
    if (not isinstance(is_admin, bool) or not isinstance(delete_unselected, bool)
            or not isinstance(rotate_passwords, bool)):
        return jsonify({"error": "invalid_options", "message": "Invalid account options."}), 400
    if photo_error:
        return jsonify({"error": "invalid_profile_photo", "message": photo_error}), 400

    requested_ids = list(dict.fromkeys(str(value) for value in endpoint_ids))
    allowed = {str(endpoint["id"]): endpoint for endpoint in _scoped_endpoints()}
    if any(endpoint_id not in allowed for endpoint_id in requested_ids):
        # Do not reveal whether an out-of-scope endpoint exists.
        return jsonify({"error": "endpoint_not_found", "message": "One or more endpoints are unavailable."}), 404

    from services.entitlements import check_job
    entitlement = check_job(g.company["id"], "CREATE_USER")
    if not entitlement.allowed:
        return jsonify({"error": entitlement.code, "message": entitlement.message}), 403

    inventory = db.get_company_windows_users(
        g.company["id"],
        branch_id=g.admin.get("branch_id") if g.admin.get("role") == "branch_admin" else None,
    )
    existing = {
        str(row.get("endpoint_id")): row for row in inventory
        if str(row.get("account_type") or "unknown").lower() == "local"
        and str(row.get("username") or "").casefold() == username.casefold()
    }
    jobs = []
    escalations = []
    affected_endpoints = set()
    assigned_endpoints = set()
    unchanged_endpoints = set()
    one_time_credentials = []

    def queue(endpoint, job_type, payload):
        job = db.create_job(
            g.company["id"], endpoint.get("branch_id"), str(endpoint["id"]),
            job_type, payload, g.admin["id"],
        )
        if job:
            endpoint_id = str(endpoint["id"])
            affected_endpoints.add(endpoint_id)
            jobs.append({
                "job_id": str(job["id"]), "endpoint_id": endpoint_id,
                "hostname": endpoint.get("hostname") or "Unknown endpoint",
                "operation": job_type, "status": endpoint.get("status") or "unknown",
            })
            return True
        return False

    for endpoint_id in requested_ids:
        endpoint = allowed[endpoint_id]
        if endpoint_id in existing:
            assigned_endpoints.add(endpoint_id)
            if rotate_passwords:
                password = generate_endpoint_password()
                if queue(endpoint, "RESET_PASSWORD", {
                    "username": username, "new_password": password,
                }):
                    one_time_credentials.append({
                        "endpoint_id": endpoint_id,
                        "hostname": endpoint.get("hostname") or "Unknown endpoint",
                        "username": username,
                        "password": password,
                    })
            else:
                unchanged_endpoints.add(endpoint_id)
            if not bool(existing[endpoint_id].get("is_enabled", True)):
                queue(endpoint, "ENABLE_USER", {"username": username})
        else:
            password = generate_endpoint_password()
            if queue(endpoint, "CREATE_USER", {
                "username": username, "password": password,
                "full_name": full_name, "is_admin": is_admin,
                "must_change_password": True, "profile_photo": profile_photo,
            }):
                assigned_endpoints.add(endpoint_id)
                one_time_credentials.append({
                    "endpoint_id": endpoint_id,
                    "hostname": endpoint.get("hostname") or "Unknown endpoint",
                    "username": username,
                    "password": password,
                })

    removal_targets = sorted(set(existing) - set(requested_ids)) if delete_unselected else []
    if delete_unselected:
        for endpoint_id in removal_targets:
            if endpoint_id not in allowed:
                continue
            endpoint = allowed[endpoint_id]
            escalation = db.create_escalation_request(
                company_id=g.company["id"],
                branch_id=endpoint.get("branch_id"),
                endpoint_id=endpoint_id,
                windows_user=username,
                operation="DELETE_USER",
                payload={"username": username},
                reason="Account removed from centralized directory assignment",
                requires_dual=g.company.get("require_dual_approval", True),
                requested_by=g.admin["id"],
            )
            if escalation:
                affected_endpoints.add(endpoint_id)
                escalations.append({
                    "escalation_id": str(escalation["id"]),
                    "endpoint_id": endpoint_id,
                    "hostname": endpoint.get("hostname") or "Unknown endpoint",
                    "status": "pending_approval",
                })

    if not jobs and not escalations and len(assigned_endpoints) != len(requested_ids):
        return jsonify({"error": "assignment_failed", "message": "No assignment or removal work could be queued."}), 500

    db.audit(g.company["id"], g.admin["id"], "directory_user_assignment_queued", {
        "username": username,
        "endpoint_ids": sorted(affected_endpoints),
        "requested_count": len(requested_ids),
        "queued_count": len(jobs), "delete_unselected": delete_unselected,
        "rotate_passwords": rotate_passwords,
        "escalation_ids": [item["escalation_id"] for item in escalations],
        "is_admin": is_admin,
    })
    complete = (
        len(assigned_endpoints) == len(requested_ids)
        and len(escalations) == len([target for target in removal_targets if target in allowed])
    )
    status = 201 if complete else 207
    removal_text = ""
    if escalations:
        removal_text = f" {len(escalations)} old-endpoint deletion approval{'s' if len(escalations) != 1 else ''} created."
    response = jsonify({
        "ok": True,
        "queued_count": len(jobs),
        "requested_count": len(requested_ids),
        "affected_count": len(affected_endpoints),
        "assigned_count": len(assigned_endpoints),
        "jobs": jobs,
        "escalations": escalations,
        "unchanged_count": len(unchanged_endpoints),
        "one_time_credentials": one_time_credentials,
        "message": f"Account assignment prepared for {len(assigned_endpoints)} endpoint{'s' if len(assigned_endpoints) != 1 else ''}. Each new or rotated account has its own password.{removal_text}",
    })
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response, status


@bp.route("/directory/export.csv")
@login_required
@company_required
def export_csv():
    identities, _, branch_id, account_type, access, sort, query = _directory_request()
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer)
    writer.writerow([
        "Display name", "Principal", "Username", "SID", "Account type",
        "Domain", "Access", "Enabled", "Endpoints", "Last synchronized",
    ])
    for identity in identities:
        writer.writerow([
            _csv_cell(identity["display_name"] or identity["username"]),
            _csv_cell(identity["principal_name"]),
            _csv_cell(identity["username"]),
            _csv_cell(identity["sid"]),
            identity["account_type"],
            _csv_cell(identity["domain_name"]),
            "Administrator" if identity["is_admin"] else "Standard",
            "Yes" if identity["all_enabled"] else "No",
            _csv_cell(", ".join(account["hostname"] for account in identity["accounts"])),
            identity["last_synced"] or "",
        ])
    db.audit(g.company["id"], g.admin["id"], "directory_exported", {
        "count": len(identities), "branch_id": branch_id or None,
        "type": account_type or None, "access": access or None,
        "query_used": bool(query), "sort": sort,
    })
    slug = "".join(c for c in str(g.company.get("slug") or "organization") if c.isalnum() or c in "-_")
    return Response(
        buffer.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="warden-directory-{slug}.csv"'},
    )
