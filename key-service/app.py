"""Warden key custody application. No key export or arbitrary execution API."""
import hmac
import inspect
import json
import logging

from cryptography.exceptions import InvalidTag
from flask import Flask, jsonify, request
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge

import config
from services import platform_secrets, tenant_crypto

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
log = logging.getLogger("key_service.audit")
log.setLevel(logging.INFO)
log.addHandler(logging.StreamHandler())
log.propagate = False

OPERATIONS = {
    **{"tenant." + name: getattr(tenant_crypto, name) for name in (
        "provision_managed", "provision_byok", "rewrap_to_byok", "rewrap_to_managed",
        "unlock_byok", "lock_company", "is_unlocked", "vault_status", "encrypt_value", "decrypt_value",
        "blind_index_value",
    )},
    **{"platform." + name: getattr(platform_secrets, name) for name in (
        "encrypt_mfa_secret", "decrypt_mfa_secret", "encrypt_platform_field",
        "decrypt_platform_field", "hash_backup_code", "backup_code_matches",
    )},
}


@app.after_request
def no_cache(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.post("/v1/operate")
def operate():
    authorization = request.headers.get("Authorization", "")
    expected = "Bearer " + config.CLIENT_TOKEN
    if not authorization.isascii() or not hmac.compare_digest(authorization, expected):
        log.warning("key_operation status=unauthorized")
        return jsonify(error="unauthorized"), 401
    operation = "invalid"
    try:
        payload = request.get_json()
        if not isinstance(payload, dict) or set(payload) != {"operation", "arguments"}:
            raise ValueError()
        operation = payload["operation"]
        if not isinstance(operation, str) or operation not in OPERATIONS:
            operation = "invalid"
            raise ValueError()
        arguments = payload["arguments"]
        if not isinstance(arguments, dict):
            raise ValueError()
        function = OPERATIONS[operation]
        bound = inspect.signature(function).bind(**arguments)
        bound.apply_defaults()
        # Crypto engines accept arbitrary JSON values for data, but identifiers,
        # purposes and wrapping material must be bounded strings.
        for name in ("company_id", "purpose", "mode", "current_mode", "wrapped_dek",
                     "current_wrapped_dek", "byok_salt_b64", "passphrase"):
            if name in bound.arguments:
                value = bound.arguments[name]
                if not isinstance(value, str) or not value or len(value) > 4096:
                    raise ValueError()
        for name in ("mode", "current_mode"):
            if name in bound.arguments and bound.arguments[name] not in {"managed", "byok"}:
                raise ValueError()
        result = function(**bound.arguments)
        # Check the response bound without logging or retaining sensitive content.
        if len(json.dumps({"result": result}, allow_nan=False).encode()) > app.config["MAX_CONTENT_LENGTH"]:
            raise ValueError()
        log.info("key_operation operation=%s status=ok", operation)
        return jsonify(result=result)
    except tenant_crypto.VaultLocked:
        log.info("key_operation operation=%s status=locked", operation)
        return jsonify(error="vault_locked"), 423
    except (ValueError, TypeError, InvalidTag, BadRequest, RequestEntityTooLarge):
        log.warning("key_operation operation=%s status=invalid", operation)
        return jsonify(error="invalid_operation"), 400
    except Exception:
        # Exception messages/tracebacks can contain supplied keys or plaintext.
        log.error("key_operation operation=%s status=failed", operation)
        return jsonify(error="key_service_failure"), 503


@app.errorhandler(413)
def too_large(_error):
    return jsonify(error="invalid_operation"), 400
