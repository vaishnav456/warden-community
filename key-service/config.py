"""Service-only configuration: secrets are mounted files, never environment values."""
import base64
import os
from pathlib import Path

KEY_SERVICE_SOCKET = ""  # Crypto engines execute here, rather than delegate.
TENANT_MASTER_KEK_B64 = Path(os.environ.get(
    "MASTER_KEY_FILE", "/run/secrets/master-key")).read_text().strip()
if len(base64.b64decode(TENANT_MASTER_KEK_B64, validate=True)) != 32:
    raise RuntimeError("Master key must decode to 32 bytes")
CLIENT_TOKEN = Path(os.environ.get(
    "CLIENT_TOKEN_FILE", "/run/secrets/client-token")).read_text().strip()
if len(CLIENT_TOKEN) < 32 or not CLIENT_TOKEN.isascii() or any(c.isspace() for c in CLIENT_TOKEN):
    raise RuntimeError("Client credential must have at least 32 ASCII characters")
