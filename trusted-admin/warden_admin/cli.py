"""Portable native commands; unlock phrases and database URLs stay off argv."""
import argparse
import getpass
import json
import os
from pathlib import Path
import sys

from .archive import Archive, load_checkpoint, save_checkpoint
from .crypto import Vault


def _password():
    # Optional stdin is for SSH/migration tooling. Environment variable values
    # never contain the phrase, and no command line argument can contain it.
    if os.environ.get("WARDEN_ADMIN_UNLOCK_STDIN") == "1":
        value = sys.stdin.readline(4098).rstrip("\r\n")
        if not value:
            raise ValueError("Unlock phrase is required")
        return value
    return getpass.getpass("Admin unlock phrase: ")


def main():
    parser = argparse.ArgumentParser(description="Trusted Warden admin application")
    parser.add_argument("--vault", required=True, type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("create-vault")
    for name in ("capture", "verify", "install-ciphertext", "serve"):
        command = commands.add_parser(name)
        command.add_argument("--archive", required=True, type=Path)
        command.add_argument("--checkpoint", required=True, type=Path)
        if name == "serve":
            command.add_argument("--port", type=int, default=35750)
    args = parser.parse_args()
    vault = None
    try:
        if args.command == "create-vault":
            vault = Vault.create(args.vault, _password())
            report = {"vault_created": True, "backup_required": True}
        elif args.command == "serve":
            from .web import create_app
            # Start locked. Unlock happens through the independently accessed
            # loopback application, never through the public Warden website.
            app = create_app(args.vault, args.archive, args.checkpoint)
            from werkzeug.serving import run_simple
            run_simple("127.0.0.1", args.port, app, threaded=True, use_debugger=False, use_reloader=False)
            return 0
        else:
            vault = Vault.unlock(args.vault, _password())
            if args.command == "capture":
                from .postgres import capture_postgres
                import psycopg2
                if args.checkpoint.exists():
                    raise ValueError("Checkpoint already exists")
                with psycopg2.connect(os.environ["WARDEN_ADMIN_SOURCE_DSN"]) as connection:
                    report = capture_postgres(vault, args.archive, connection)
                save_checkpoint(vault, args.checkpoint, args.archive)
                report["source_changed"] = False
            else:
                digest = load_checkpoint(vault, args.checkpoint)
                if args.command == "verify":
                    archive = Archive(vault, args.archive, expected_digest=digest)
                    try:
                        report = archive.verify()
                    finally:
                        archive.close()
                else:
                    from .postgres import install_ciphertext
                    import psycopg2
                    with psycopg2.connect(os.environ["WARDEN_ADMIN_TARGET_DSN"]) as connection:
                        report = install_ciphertext(vault, args.archive, digest, connection)
        print(json.dumps(report))
        return 0
    except Exception:
        # PostgreSQL and crypto errors can contain record content or credentials.
        print("Admin operation failed; check unlock phrase, files and private connection settings.", file=sys.stderr)
        return 1
    finally:
        if vault is not None:
            vault.lock()


if __name__ == "__main__":
    sys.exit(main())
