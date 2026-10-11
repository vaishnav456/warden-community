"""All-table encrypted snapshots. SQL reads contain opaque IDs and ciphertext.

Snapshots are migration evidence, not a live database adapter. Source databases
remain unchanged. A local trusted checkpoint detects replay of an older archive.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import uuid
from contextlib import closing

from .crypto import canonical, seal, unseal


IDENTIFIER = re.compile(r"t_[0-9a-f]{32}\Z")
MAX_TABLES = 10000
MAX_ROWS = 10000000


def _identifier(value):
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError("Invalid encrypted table identifier")
    return value


def _context(dataset, table, row):
    return {"dataset": dataset, "table": table, "row": row}


def file_digest(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def capture(vault, path, tables, *, metadata=None):
    """Consume (schema, name, columns, iterable[raw JSON row bytes]) atomically.

    Raw PostgreSQL JSON is encrypted without reserialization, preserving numeric
    precision. Empty tables and every column definition live in the encrypted
    manifest. Nothing is classified as nonsensitive or skipped.
    """
    path = Path(path)
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(descriptor)
    dataset = uuid.uuid4().hex
    manifest = {"v": 1, "dataset": dataset, "tables": [], "metadata": metadata or {}}
    seen = set()
    total = 0
    try:
        with closing(sqlite3.connect(path)) as connection, connection:
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA temp_store=MEMORY")
            connection.execute("CREATE TABLE archive (id TEXT PRIMARY KEY, payload TEXT NOT NULL)")
            for schema, name, columns, rows in tables:
                if (schema, name) in seen or len(seen) >= MAX_TABLES:
                    raise ValueError("Duplicate table or table safety bound exceeded")
                seen.add((schema, name))
                table = "t_" + uuid.uuid4().hex
                connection.execute(f'CREATE TABLE "{table}" (id TEXT PRIMARY KEY, payload TEXT NOT NULL)')
                digest = hashlib.sha256()
                count = 0
                for raw in rows:
                    if total >= MAX_ROWS or not isinstance(raw, bytes):
                        raise ValueError("Invalid row or row safety bound exceeded")
                    row = uuid.uuid4().hex
                    encrypted = seal(vault.key, _context(dataset, table, row), raw)
                    connection.execute(f'INSERT INTO "{table}" VALUES (?, ?)', (row, encrypted))
                    count += 1
                    total += 1
                # Stable order binds the entire row set, including deletions.
                for row, encrypted in connection.execute(f'SELECT id, payload FROM "{table}" ORDER BY id'):
                    digest.update(canonical([row, encrypted]))
                manifest["tables"].append({"schema": schema, "name": name, "columns": columns,
                                           "id": table, "rows": count, "digest": digest.hexdigest()})
            payload = seal(vault.key, {"archive": dataset}, canonical(manifest))
            connection.execute("INSERT INTO archive VALUES (?, ?)", (dataset, payload))
        return {"tables": len(seen), "rows": total, "sha256": file_digest(path)}
    except BaseException:
        path.unlink(missing_ok=True)
        Path(str(path) + "-journal").unlink(missing_ok=True)
        raise


class Archive:
    def __init__(self, vault, path, *, expected_digest):
        self.path = Path(path)
        self.vault = vault
        # The expected digest must come from a trusted local checkpoint, never
        # from the same untrusted relay that supplied this archive.
        if not re.fullmatch(r"[0-9a-f]{64}", expected_digest or ""):
            raise ValueError("A trusted archive checkpoint is required")
        if file_digest(self.path) != expected_digest:
            raise ValueError("Archive differs from the trusted checkpoint")
        self.connection = sqlite3.connect(self.path.resolve().as_uri() + "?mode=ro", uri=True,
                                          check_same_thread=False)
        self.connection.execute("PRAGMA trusted_schema=OFF")
        self.connection.execute("PRAGMA query_only=ON")
        try:
            rows = self.connection.execute("SELECT id, payload FROM archive LIMIT 2").fetchall()
            if len(rows) != 1:
                raise ValueError("Invalid encrypted manifest")
            dataset, payload = rows[0]
            if not re.fullmatch(r"[0-9a-f]{32}", dataset):
                raise ValueError("Invalid encrypted manifest")
            self.manifest = json.loads(unseal(vault.key, {"archive": dataset}, payload))
            if self.manifest["v"] != 1 or self.manifest["dataset"] != dataset:
                raise ValueError("Invalid encrypted manifest")
            tables = self.manifest["tables"]
            if not isinstance(tables, list) or len(tables) > MAX_TABLES:
                raise ValueError("Invalid encrypted manifest")
            names = [_identifier(table["id"]) for table in tables]
            if len(set(names)) != len(names):
                raise ValueError("Duplicate encrypted tables")
            actual = {row[0] for row in self.connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            if actual != {"archive", *names}:
                raise ValueError("Unexpected or missing tables")
        except BaseException:
            self.connection.close()
            raise

    def close(self):
        self.connection.close()

    def raw_rows(self, table):
        if table not in self.manifest["tables"]:
            raise ValueError("Unknown table")
        identifier = _identifier(table["id"])
        digest = hashlib.sha256()
        count = 0
        for row, payload in self.connection.execute(f'SELECT id, payload FROM "{identifier}" ORDER BY id'):
            if not isinstance(row, str) or not re.fullmatch(r"[0-9a-f]{32}", row):
                raise ValueError("Invalid encrypted row")
            digest.update(canonical([row, payload]))
            raw = unseal(self.vault.key, _context(self.manifest["dataset"], identifier, row), payload)
            count += 1
            yield raw
        if count != table["rows"] or digest.hexdigest() != table["digest"]:
            raise ValueError("Encrypted row set was modified")

    def verify(self):
        total = 0
        for table in self.manifest["tables"]:
            total += sum(1 for _ in self.raw_rows(table))
        return {"tables": len(self.manifest["tables"]), "rows": total,
                "all_rows_authenticated": True, "empty_tables_preserved": True}


def save_checkpoint(vault, path, archive_path):
    """Store beside the vault on the trusted machine, outside the relay."""
    path = Path(path)
    payload = seal(vault.key, {"checkpoint": vault.identifier}, canonical({
        "sha256": file_digest(archive_path)})).encode("ascii")
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def load_checkpoint(vault, path):
    path = Path(path)
    if path.stat().st_size > 4096:
        raise ValueError("Invalid checkpoint")
    return json.loads(unseal(vault.key, {"checkpoint": vault.identifier},
                            path.read_text(encoding="ascii")))["sha256"]
