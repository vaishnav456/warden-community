"""Development-gated heartbeat message encryption, layered over HTTPS.

X25519 ephemeral key agreement + HKDF-SHA256 + separate AES-256-GCM request/
response keys. The server encryption public key is Ed25519-signed and bound to
the requesting endpoint and a fresh challenge. This is not server-blind E2EE.
"""
import base64
import functools
import hashlib
import json
import os
import time

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from flask import g, jsonify, make_response, request

import config
import db
from services import signing

PATH = "/api/agent/heartbeat"
MAX_MESSAGE = 2 * 1024 * 1024


def _decode(value, size=None):
    if not isinstance(value, str) or len(value) > MAX_MESSAGE * 2:
        raise ValueError("invalid encoding")
    raw = base64.b64decode(value, validate=True)
    if size is not None and len(raw) != size:
        raise ValueError("invalid size")
    return raw


def _private_key():
    # Domain-separated key derivation: no direct conversion or reuse of the
    # Ed25519 scalar as an encryption key. Stable across restarts/workers.
    seed = signing._get_private_key().private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                   info=b"warden-heartbeat-server-x25519-v1").derive(seed)
    return X25519PrivateKey.from_private_bytes(derived)


def descriptor(endpoint_id, challenge):
    _decode(challenge, 32)
    public = _private_key().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    proof = dict(version="1", endpoint_id=str(endpoint_id), challenge=challenge,
                 public_key=base64.b64encode(public).decode(), server_time=str(int(time.time())))
    return dict(**proof, signature=base64.b64encode(signing.sign_canonical_payload(proof)).decode())


def aad(endpoint_id, api_key):
    digest = hashlib.sha256(api_key.encode()).hexdigest()
    return f"warden-heartbeat-v1|POST|{PATH}|{endpoint_id}|{digest}".encode()


def open_request(envelope, endpoint_id, api_key):
    if not isinstance(envelope, dict) or envelope.get("version") != 1:
        raise ValueError("invalid message")
    ephemeral = _decode(envelope.get("ephemeral_key"), 32)
    nonce = _decode(envelope.get("nonce"), 12)
    ciphertext = _decode(envelope.get("ciphertext"))
    if len(ciphertext) > MAX_MESSAGE or len(ciphertext) < 16:
        raise ValueError("invalid message size")
    context = aad(endpoint_id, api_key)
    shared = _private_key().exchange(X25519PublicKey.from_public_bytes(ephemeral))
    keys = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=context).derive(shared)
    content = json.loads(AESGCM(keys[:32]).decrypt(nonce, ciphertext, context + b"|request"))
    if not isinstance(content, dict) or not isinstance(content.get("body"), dict):
        raise ValueError("invalid content")
    issued = content.get("issued_at")
    if not isinstance(issued, int) or isinstance(issued, bool) or abs(time.time() - issued) > 300:
        raise ValueError("expired message")
    replay_id = hashlib.sha256(ephemeral + nonce).hexdigest()
    return content["body"], keys[32:], envelope["nonce"], context, replay_id


def seal_response(raw, key, request_nonce, context, status):
    nonce = os.urandom(12)
    response_aad = context + f"|response|{request_nonce}|{status}".encode()
    ciphertext = AESGCM(key).encrypt(nonce, raw, response_aad)
    return dict(version=1, request_nonce=request_nonce,
                nonce=base64.b64encode(nonce).decode(),
                ciphertext=base64.b64encode(ciphertext).decode())


def heartbeat_messages(function):
    @functools.wraps(function)
    def wrapped(*args, **kwargs):
        body = request.get_json(silent=True)
        encrypted = request.headers.get("X-Warden-Heartbeat-Encryption") == "1"
        if not encrypted:
            if g.endpoint.get("heartbeat_encryption_required"):
                return jsonify(error="heartbeat_encryption_required"), 426
            # Old enrolled agents retain TLS during the staged rollout.
            return function(*args, **kwargs)
        if not config.HEARTBEAT_MESSAGE_ENCRYPTION:
            return jsonify(error="heartbeat_encryption_unavailable"), 503
        try:
            plain, response_key, request_nonce, context, replay_id = open_request(
                body, g.endpoint["id"], request.headers.get("X-Agent-Key", ""))
            proof_required = bool(g.endpoint.get("heartbeat_device_proof_required"))
            proof_supplied = isinstance(body, dict) and bool(body.get("device_signature") or body.get("device_certificate"))
            # Upgrade per endpoint after its first verified proof. Enabling the
            # rollout must not strand older encrypted clients before updating.
            if proof_required or proof_supplied:
                from services.device_proof import verify_device_signature, heartbeat_proof_message
                verify_device_signature(g.endpoint, body.get("device_certificate"),
                                        body.get("device_signature"), heartbeat_proof_message(body, context))
        except Exception:
            return jsonify(error="invalid_encrypted_heartbeat"), 400
        try:
            accepted = db._rpc("claim_heartbeat_nonce", dict(p_endpoint=g.endpoint["id"], p_nonce=replay_id))
        except Exception:
            return jsonify(error="heartbeat_replay_store_unavailable"), 503
        if accepted is not True:
            return jsonify(error="heartbeat_replay"), 409
        upgrade = {}
        if not g.endpoint.get("heartbeat_encryption_required"):
            upgrade["heartbeat_encryption_required"] = True
        if proof_supplied and config.HEARTBEAT_DEVICE_PROOF_REQUIRED and not proof_required:
            upgrade["heartbeat_device_proof_required"] = True
        if upgrade:
            db._patch(f"endpoints?id=eq.{db._q(g.endpoint['id'])}",
                      upgrade)
        g.heartbeat_body = plain
        response = make_response(function(*args, **kwargs))
        sealed = seal_response(response.get_data(), response_key, request_nonce, context, response.status_code)
        return jsonify(sealed), response.status_code
    return wrapped
