"""Authenticated key operations over a private Unix socket; never export keys."""
import functools
import http.client
import inspect
import json
import pathlib
import socket

import config

MAX_MESSAGE_BYTES = 16 * 1024 * 1024


class KeyServiceUnavailable(RuntimeError):
    """Key custody is unavailable. Callers must not use a plaintext fallback."""


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout=5):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def call(operation, arguments):
    """One request, without retries: provisioning/unlock must not be replayed."""
    connection = None
    try:
        token = pathlib.Path(config.KEY_SERVICE_TOKEN_FILE).read_text().strip()
        if len(token) < 32 or not token.isascii() or any(c.isspace() for c in token):
            raise KeyServiceUnavailable("Invalid key service credential")
        body = json.dumps({"operation": operation, "arguments": arguments},
                          allow_nan=False).encode()
        if len(body) > MAX_MESSAGE_BYTES:
            raise ValueError("Key operation exceeds the message limit")
        connection = UnixConnection(config.KEY_SERVICE_SOCKET, config.KEY_SERVICE_TIMEOUT)
        connection.request("POST", "/v1/operate", body, {
            "Authorization": "Bearer " + token, "Content-Type": "application/json",
        })
        response = connection.getresponse()
        raw = response.read(MAX_MESSAGE_BYTES + 1)
        if len(raw) > MAX_MESSAGE_BYTES:
            raise KeyServiceUnavailable("Invalid key service response")
        result = json.loads(raw)
        if response.status == 423 and result.get("error") == "vault_locked":
            from services.tenant_crypto import VaultLocked
            raise VaultLocked("Tenant vault is locked")
        if response.status == 400 and result.get("error") == "invalid_operation":
            raise ValueError("Invalid key operation or encrypted value")
        if response.status != 200 or "result" not in result:
            raise KeyServiceUnavailable("Key service rejected the operation")
        return result["result"]
    except (OSError, http.client.HTTPException, json.JSONDecodeError) as exc:
        raise KeyServiceUnavailable("Key service is unavailable") from exc
    finally:
        if connection is not None:
            connection.close()


def delegated(operation):
    """Use remote custody when configured; never fall back after a failure."""
    def decorate(function):
        signature = inspect.signature(function)

        @functools.wraps(function)
        def wrapped(*args, **kwargs):
            if not getattr(config, "KEY_SERVICE_SOCKET", ""):
                return function(*args, **kwargs)
            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            return call(operation, bound.arguments)

        return wrapped
    return decorate
