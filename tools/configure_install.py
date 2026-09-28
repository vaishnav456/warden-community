#!/usr/bin/env python3
"""Generate a first-install Warden Community configuration.

The command writes only gitignored local files. It refuses to overwrite an
existing installation unless --force is supplied. Run it interactively; the
administrator password is never accepted as a command-line argument.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import json
import re
import secrets
import sys
from pathlib import Path
from urllib.parse import urlparse

try:
    import bcrypt
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
except ImportError as exc:  # pragma: no cover - exercised by operators
    raise SystemExit(
        "Missing bootstrap dependencies. Run this through the warden-server "
        "container as documented in docs/INSTALLATION_AND_MIGRATION.md."
    ) from exc


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def service_role_jwt(secret: str) -> str:
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64url(json.dumps({"role": "service_role"}, separators=(",", ":")).encode())
    body = f"{header}.{payload}"
    signature = _b64url(hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest())
    return f"{body}.{signature}"


def _sql(value: str) -> str:
    return value.replace("'", "''")


def _replace_env(template: str, values: dict[str, str]) -> str:
    result = []
    found: set[str] = set()
    for line in template.splitlines():
        match = re.match(r"^(#?)([A-Z][A-Z0-9_]*)=(.*)$", line)
        if match and match.group(2) in values:
            key = match.group(2)
            result.append(f"{key}={values[key]}")
            found.add(key)
        else:
            result.append(line)
    missing = set(values) - found
    if missing:
        result.extend(f"{key}={values[key]}" for key in sorted(missing))
    return "\n".join(result) + "\n"


def _single_line(label: str, value: str, maximum: int) -> str:
    value = value.strip()
    if not value or len(value) > maximum or "\n" in value or "\r" in value:
        raise ValueError(f"{label} must be a non-empty single-line value of at most {maximum} characters")
    return value


def generate(root: Path, args: argparse.Namespace, password: str) -> list[Path]:
    args.organization_name = _single_line("--organization-name", args.organization_name, 160)
    args.admin_name = _single_line("--admin-name", args.admin_name, 160)
    args.brand_name = _single_line("--brand-name", args.brand_name, 80)
    args.admin_email = _single_line("--admin-email", args.admin_email, 254)
    parsed = urlparse(args.server_url)
    if (
        parsed.scheme != "https" or not parsed.hostname or parsed.username
        or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment
    ):
        raise ValueError("--server-url must be an HTTPS origin without a path")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", args.organization_slug):
        raise ValueError("--organization-slug must be 3-63 lowercase letters, digits, or hyphens")
    if "@" not in args.admin_email or len(password) < 12:
        raise ValueError("use a valid administrator email and a password of at least 12 characters")

    postgres_password = secrets.token_urlsafe(36)
    authenticator_password = secrets.token_urlsafe(36)
    jwt_secret = secrets.token_urlsafe(48)
    role_jwt = service_role_jwt(jwt_secret)
    build_key = secrets.token_hex(32)
    ed25519 = Ed25519PrivateKey.generate().private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )

    root_env = _replace_env((root / ".env.example").read_text(encoding="utf-8"), {
        "POSTGRES_PASSWORD": postgres_password,
        "POSTGREST_AUTHENTICATOR_PASSWORD": authenticator_password,
        "POSTGREST_JWT_SECRET": jwt_secret,
    })
    server_env = _replace_env((root / "server/.env.example").read_text(encoding="utf-8"), {
        "SUPABASE_SERVICE_KEY": role_jwt,
        "SECRET_KEY": secrets.token_hex(32),
        "TRUST_CLOUDFLARE": "false",
        "CLOUDFLARE_API_TOKEN": "",
        "CLOUDFLARE_ZONE_ID": "",
        "REQUIRE_CLIENT_CERT": "false",
        "DEVICE_CA_AUTO_BOOTSTRAP": "true",
        "TENANT_MASTER_KEK_B64": base64.b64encode(secrets.token_bytes(32)).decode(),
        "ED25519_PRIVATE_KEY_B64": base64.b64encode(ed25519).decode(),
        "BUILD_SERVICE_KEY": build_key,
        "SERVER_URL": args.server_url.rstrip("/"),
        "BRAND_NAME": args.brand_name,
    })
    build_env = _replace_env((root / "build-service/.env.example").read_text(encoding="utf-8"), {
        "SUPABASE_KEY": role_jwt,
        "BUILD_SERVICE_KEY": build_key,
        "AGENT_DISPLAY_NAME": f"{args.brand_name} Endpoint Agent",
        "AGENT_MANUFACTURER": args.organization_name,
    })
    roles = (root / "db-init/01-roles.sql.example").read_text(encoding="utf-8").replace(
        "change-me-generate-a-random-password", _sql(authenticator_password)
    )
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    bootstrap = (root / "db-init/04-bootstrap-admin.sql.example").read_text(encoding="utf-8")
    bootstrap = bootstrap.replace("'organization', 'My Organization'", (
        f"'{_sql(args.organization_slug)}', '{_sql(args.organization_name)}'"
    )).replace("'admin@example.com'", f"'{_sql(args.admin_email.lower())}'")
    bootstrap = bootstrap.replace("'$2b$12$change-me-generate-a-real-bcrypt-hash'", f"'{password_hash}'")
    bootstrap = bootstrap.replace("'Admin',", f"'{_sql(args.admin_name)}',")

    outputs = [
        (root / ".env", root_env),
        (root / "server/.env", server_env),
        (root / "build-service/.env", build_env),
        (root / "db-init/01-roles.sql", roles),
        (root / "db-init/04-bootstrap-admin.sql", bootstrap),
    ]
    existing = [path for path, _ in outputs if path.exists()]
    if existing and not args.force:
        names = ", ".join(str(path) for path in existing)
        raise FileExistsError(
            f"refusing a partial overwrite because these files exist: {names} "
            "(use --force only for an unstarted install)"
        )
    for path, content in outputs:
        path.write_text(content, encoding="utf-8", newline="\n")
    return [path for path, _ in outputs]


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a secure Warden Community first-install configuration")
    parser.add_argument("--server-url", required=True, help="Public HTTPS origin, for example https://warden.example.com")
    parser.add_argument("--organization-name", required=True)
    parser.add_argument("--organization-slug", default="organization")
    parser.add_argument("--admin-email", required=True)
    parser.add_argument("--admin-name", default="Administrator")
    parser.add_argument("--brand-name", default="Warden")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1], help=argparse.SUPPRESS)
    args = parser.parse_args()
    first = getpass.getpass("Initial administrator password (minimum 12 characters): ")
    second = getpass.getpass("Confirm administrator password: ")
    if first != second:
        print("Passwords do not match.", file=sys.stderr)
        return 2
    try:
        outputs = generate(args.root.resolve(), args, first)
    except (ValueError, FileExistsError) as exc:
        print(f"Configuration not written: {exc}", file=sys.stderr)
        return 2
    print("Generated local secret configuration:")
    for path in outputs:
        print(f"  {path}")
    print("Back up these files in an encrypted secrets store; never commit them.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
