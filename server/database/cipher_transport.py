"""Ciphertext-only private database interface; decryption is application-side.

The SQL runtime and this client belong to Warden's trusted application boundary.
No business fields, queries or readable responses cross the database interface.
Key custody failures never fall back to PostgREST or unencrypted values.
"""
import base64
import io
import json
import os
import pathlib
import re
import time
import uuid
from urllib.error import HTTPError

from services.key_service_client import UnixConnection, call

CHUNK = 1024 * 1024
MAX_DOCUMENT = 64 * CHUNK


def _seal(identifier, purpose, text):
    raw = text.encode("utf-8")
    if not 0 < len(raw) <= MAX_DOCUMENT:
        raise ValueError("Invalid encrypted database message size")
    count = (len(raw) + CHUNK - 1) // CHUNK
    parts = [call("platform.encrypt_platform_field", {
        "record_id": f"{identifier}:{index}:{count}", "purpose": purpose,
        "value": base64.b64encode(raw[index * CHUNK:(index + 1) * CHUNK]).decode("ascii"),
    }) for index in range(count)]
    encoded = base64.urlsafe_b64encode(json.dumps(parts, separators=(",", ":")).encode()).decode().rstrip("=")
    return "wdb1:" + encoded


def _unseal(identifier, purpose, value):
    if not isinstance(value, str) or len(value) > MAX_DOCUMENT * 3 or not re.fullmatch(r"wdb1:[A-Za-z0-9_-]+", value):
        raise ValueError("Ciphertext database response required")
    encoded = value[5:]
    parts = json.loads(base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True))
    if not isinstance(parts, list) or not 1 <= len(parts) <= 64:
        raise ValueError("Invalid encrypted database response")
    chunks = []
    for index, part in enumerate(parts):
        if not isinstance(part, str) or not re.fullmatch(r"enc:v1:[A-Za-z0-9_=-]+", part) or not 46 <= len(part) <= CHUNK * 2:
            raise ValueError("Invalid encrypted database response")
        clear = call("platform.decrypt_platform_field", {
            "record_id": f"{identifier}:{index}:{len(parts)}", "purpose": purpose, "value": part,
        })
        raw = base64.b64decode(clear, validate=True)
        if not 0 < len(raw) <= CHUNK or index < len(parts) - 1 and len(raw) != CHUNK:
            raise ValueError("Invalid encrypted database response")
        chunks.append(raw)
    return b"".join(chunks).decode("utf-8")


class Response(io.BytesIO):
    def __init__(self, document):
        super().__init__(document["body"].encode("utf-8"))
        self.headers = document["headers"]
        self.status = document["status"]


def open_request(path, method, schema, data=None, *, has_data=False, prefer=None):
    socket_path = os.environ["CIPHER_SOCKET"]
    token_path = os.environ["CIPHER_TOKEN_FILE"]
    dataset = os.environ["CIPHER_DATASET"]
    if not socket_path.startswith("/") or not token_path.startswith("/") or str(uuid.UUID(dataset)) != dataset:
        raise ValueError("Invalid encrypted database configuration")
    token = pathlib.Path(token_path).read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", token):
        raise ValueError("Invalid encrypted database credential")
    identifier = str(uuid.uuid4())
    issued = int(time.time() * 1000)
    request = {"path": path, "method": method, "schema": schema, "prefer": prefer}
    if has_data:
        request["data_json"] = json.dumps(data, allow_nan=False, separators=(",", ":"))
    document = json.dumps({"id": identifier, "time": issued, "request": request}, allow_nan=False)
    envelope = {"id": identifier, "payload": _seal(identifier, "database.request.v1:" + dataset, document)}
    connection = UnixConnection(socket_path, timeout=90)
    try:
        connection.request("POST", "/v1/query", json.dumps(envelope).encode(), {
            "Authorization": "Bearer " + token, "Content-Type": "application/json",
        })
        response = connection.getresponse()
        raw = response.read(MAX_DOCUMENT * 3 + 1)
        if response.status != 200 or len(raw) > MAX_DOCUMENT * 3:
            raise RuntimeError("Encrypted database rejected request")
        encrypted = json.loads(raw)
        if set(encrypted) != {"id", "payload"} or encrypted["id"] != identifier:
            raise RuntimeError("Encrypted database response mismatch")
        result = json.loads(_unseal(identifier, "database.response.v1:" + dataset, encrypted["payload"]))
        if result.get("id") != identifier or result.get("time") != issued or not isinstance(result.get("status"), int):
            raise RuntimeError("Encrypted database response mismatch")
        if not isinstance(result.get("body"), str) or not isinstance(result.get("headers"), dict):
            raise RuntimeError("Invalid encrypted database response")
        if result["status"] >= 400:
            raise HTTPError("cipher-database", result["status"], "Application query rejected", result["headers"], io.BytesIO(result["body"].encode()))
        return Response(result)
    finally:
        connection.close()
