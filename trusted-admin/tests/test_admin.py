import base64
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.exceptions import InvalidTag
from warden_admin.archive import Archive, capture, file_digest, load_checkpoint, save_checkpoint
from warden_admin.crypto import Vault, seal, unseal
from warden_admin.web import create_app


PHRASE = "synthetic-test-only-unlock-phrase"


class AdminTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.apps = []
        self.root = Path(self.directory.name)
        self.vault_path = self.root / "vault.json"
        self.vault = Vault.create(self.vault_path, PHRASE)
        self.path = self.root / "database.sqlite"
        self.checkpoint = self.root / "checkpoint.enc"
        self.record = b'{"id":"source-private-id","name":"DO-NOT-STORE-CLEAR","cpu":1.23000000000000000000000001,"enabled":true,"note":null,"nested":{"x":[1,2]}}'
        self.report = capture(self.vault, self.path, [
            ("private_schema", "private_table", [{"name": "name", "type": "text"}], [self.record]),
            ("private_schema", "empty_table", [{"name": "secret", "type": "integer"}], []),
        ], metadata={"function": "do_not_store_clear_schema_definition"})
        save_checkpoint(self.vault, self.checkpoint, self.path)

    def tearDown(self):
        for app in self.apps:
            app.extensions["admin_shutdown"]()
        self.vault.lock()
        self.directory.cleanup()

    def open(self, digest=None):
        return Archive(self.vault, self.path, expected_digest=digest or load_checkpoint(self.vault, self.checkpoint))

    def test_every_value_and_schema_metadata_is_encrypted(self):
        raw = self.path.read_bytes()
        for marker in (b"private_schema", b"private_table", b"empty_table", b"source-private-id",
                       b"DO-NOT-STORE-CLEAR", b"1.23000000000000000000000001",
                       b"do_not_store_clear_schema_definition"):
            self.assertNotIn(marker, raw)
        with closing(sqlite3.connect(self.path)) as connection, connection:
            tables = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")]
            self.assertEqual(len(tables), 3)
            for name in tables:
                for identifier, payload in connection.execute(f'SELECT id,payload FROM "{name}"'):
                    self.assertEqual(len(identifier), 32)
                    self.assertTrue(payload.startswith("wa1:"))
        archive = self.open()
        try:
            self.assertEqual(archive.verify()["tables"], 2)
            self.assertEqual(archive.verify()["rows"], 1)
            self.assertEqual(list(archive.raw_rows(archive.manifest["tables"][0])), [self.record])
            self.assertEqual(archive.manifest["tables"][1]["rows"], 0)
        finally:
            archive.close()

    def test_vault_password_and_key_are_absent_and_no_overwrite(self):
        raw = self.vault_path.read_bytes()
        self.assertNotIn(PHRASE.encode(), raw)
        self.assertNotIn(base64.b64encode(self.vault.key), raw)
        self.assertEqual(Vault.unlock(self.vault_path, PHRASE).key, self.vault.key)
        with self.assertRaises(InvalidTag):
            Vault.unlock(self.vault_path, "incorrect-synthetic-password")
        before = raw
        with self.assertRaises(FileExistsError):
            Vault.create(self.vault_path, PHRASE)
        self.assertEqual(self.vault_path.read_bytes(), before)

    def test_encryption_binds_context_and_randomizes_nonce(self):
        value = seal(self.vault.key, {"table": "a", "row": "b"}, self.record)
        self.assertNotEqual(value, seal(self.vault.key, {"table": "a", "row": "b"}, self.record))
        with self.assertRaises(InvalidTag):
            unseal(self.vault.key, {"table": "different", "row": "b"}, value)
        with self.assertRaises(ValueError):
            unseal(self.vault.key, {}, "plain:" + value[4:])

    def test_stale_or_changed_archive_rejected_by_trusted_checkpoint(self):
        replacement = self.root / "replacement.sqlite"
        capture(self.vault, replacement, [])
        self.path.write_bytes(replacement.read_bytes())
        with self.assertRaisesRegex(ValueError, "checkpoint"):
            self.open()

    def test_missing_row_detected_even_if_file_hash_is_changed(self):
        archive = self.open()
        table = archive.manifest["tables"][0]["id"]
        archive.close()
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute(f'DELETE FROM "{table}"')
        archive = self.open(file_digest(self.path))
        try:
            with self.assertRaisesRegex(ValueError, "row set"):
                archive.verify()
        finally:
            archive.close()

    def test_row_moved_to_another_table_is_rejected(self):
        archive = self.open()
        original, other = [table["id"] for table in archive.manifest["tables"]]
        archive.close()
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute(f'INSERT INTO "{other}" SELECT * FROM "{original}"')
        archive = self.open(file_digest(self.path))
        try:
            with self.assertRaises(InvalidTag):
                archive.verify()
        finally:
            archive.close()

    def test_unexpected_plaintext_table_is_rejected(self):
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("CREATE TABLE leaked(value text)")
        with self.assertRaisesRegex(ValueError, "Unexpected"):
            self.open(file_digest(self.path))

    def test_failure_does_not_leave_partial_archive(self):
        target = self.root / "partial.sqlite"
        def failing():
            yield self.record
            raise RuntimeError("synthetic source interruption")
        with self.assertRaises(RuntimeError):
            capture(self.vault, target, [("a", "b", [], failing())])
        self.assertFalse(target.exists())
        with self.assertRaises(FileExistsError):
            capture(self.vault, self.path, [])
        self.assertEqual(file_digest(self.path), self.report["sha256"])

    def test_web_csrf_private_session_and_idle_lock(self):
        now = [1.0]
        app = create_app(self.vault_path, self.path, self.checkpoint, clock=lambda: now[0])
        self.apps.append(app)
        owner = app.test_client()
        other = app.test_client()
        self.assertEqual(owner.get("/", headers={"Host": "evil.example"}).status_code, 403)
        self.assertEqual(owner.post("/unlock", data={"phrase": PHRASE}).status_code, 403)
        owner.get("/")
        with owner.session_transaction() as session:
            csrf = session["csrf"]
        self.assertEqual(owner.post("/unlock", data={"phrase": PHRASE, "csrf": csrf},
                                    headers={"Origin": "https://evil.example"}).status_code, 403)
        self.assertEqual(owner.post("/unlock", data={"phrase": PHRASE, "csrf": csrf}).status_code, 302)
        response = owner.get("/")
        self.assertIn(b"private_table", response.data)
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(other.get("/tables/0").status_code, 302)
        self.assertNotIn(b"private_table", other.get("/").data)
        self.assertIn(b"DO-NOT-STORE-CLEAR", owner.get("/tables/0").data)
        now[0] = 602.0
        app.extensions["admin_expire"]()
        self.assertEqual(owner.get("/tables/0").status_code, 302)

    def test_web_escapes_record_content(self):
        path = self.root / "html.sqlite"
        checkpoint = self.root / "html.enc"
        capture(self.vault, path, [("schema", "table", [{"name": "name"}],
                                      [b'{"name":"<script>steal()</script>"}'])])
        save_checkpoint(self.vault, checkpoint, path)
        app = create_app(self.vault_path, path, checkpoint)
        self.apps.append(app)
        client = app.test_client()
        client.get("/")
        with client.session_transaction() as session:
            csrf = session["csrf"]
        client.post("/unlock", data={"phrase": PHRASE, "csrf": csrf})
        response = client.get("/tables/0")
        self.assertNotIn(b"<script>steal()", response.data)
        self.assertIn(b"&lt;script&gt;", response.data)


if __name__ == "__main__":
    unittest.main()
