"""Fail-closed HTTP responses for a locked tenant vault."""
from flask import g, jsonify, make_response, redirect, render_template, request, url_for


def can_unlock_vault():
    return bool(g.get("admin") and g.admin.get("role") in {"company_admin", "superadmin"})


def locked_vault_response(_error=None):
    unlock_url = url_for("settings.vault")
    wants_json = (
        request.path.startswith("/api/") or request.is_json
        or request.accept_mimetypes.best == "application/json"
        or bool(request.headers.get("X-CSRFToken"))
        or request.headers.get("Sec-Fetch-Dest") == "empty"
    )
    if wants_json or request.headers.get("HX-Request"):
        response = make_response(jsonify(
            error="tenant_vault_locked",
            message="Your organization vault is locked. An administrator must unlock it before protected operations can continue.",
            unlock_url=unlock_url,
        ), 423)
        if request.headers.get("HX-Request"):
            response.headers["HX-Redirect"] = unlock_url
    elif request.method in {"GET", "HEAD"} and request.endpoint != "settings.vault":
        response = redirect(unlock_url)
    else:
        response = make_response(render_template(
            "settings/vault_locked.html", can_unlock=can_unlock_vault(), error=None,
        ), 423)
    response.headers["Cache-Control"] = "no-store"
    return response
