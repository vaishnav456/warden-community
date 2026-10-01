"""Reject malformed JSON envelopes before route handlers consume them."""

from flask import jsonify, request


def validate_json_body():
    # All Warden JSON endpoints accept an object envelope. Keep body-less
    # requests and non-JSON (forms, uploads, binary artifacts) unchanged.
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return None
    if request.is_json and request.get_data(cache=True):
        try:
            body = request.get_json(silent=True)
        except RecursionError:
            body = None
        if not isinstance(body, dict):
            return jsonify({"error": "request body must be a valid JSON object"}), 400
    return None
