"""Run against a disposable database only; never the live Warden schemas."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from warden_admin.archive import Archive
from warden_admin.crypto import Vault
from warden_admin.postgres import capture_postgres, install_ciphertext


@unittest.skipUnless(os.environ.get("WARDEN_ADMIN_TEST_DSN"), "Disposable PostgreSQL is required")
class PostgresTests(unittest.TestCase):
    def test_consistent_capture_all_values_empty_tables_partitions_and_verified_install(self):
        import psycopg2
        from psycopg2 import sql
        with psycopg2.connect(os.environ["WARDEN_ADMIN_TEST_DSN"]) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT current_database()")
                if cursor.fetchone()[0] != "warden_admin_test":
                    self.fail("Refusing to use a database not named warden_admin_test")
                cursor.execute("CREATE SCHEMA fixture")
                cursor.execute("CREATE TABLE fixture.records (id uuid DEFAULT gen_random_uuid(), private_text text, precise numeric, payload jsonb, at timestamptz, file_data bytea)")
                cursor.execute("INSERT INTO fixture.records VALUES (DEFAULT,'DO-NOT-STORE-CLEAR',1.2345678901234567890123456789,'{\"x\":[1,true,null]}','2026-10-11T01:00:00Z',decode('deadbeef','hex'))")
                cursor.execute("CREATE TABLE fixture.empty (secret boolean)")
                cursor.execute("CREATE TABLE fixture.partitioned (id integer, private_text text) PARTITION BY RANGE(id)")
                cursor.execute("CREATE TABLE fixture.part_a PARTITION OF fixture.partitioned FOR VALUES FROM (0) TO (10)")
                cursor.execute("INSERT INTO fixture.partitioned VALUES (1,'PARTITION-PRIVATE')")
                cursor.execute("CREATE MATERIALIZED VIEW fixture.materialized AS SELECT private_text FROM fixture.records")
            connection.commit()
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                vault = Vault.create(root / "vault.json", "synthetic-postgres-only-password")
                report = capture_postgres(vault, root / "copy.sqlite", connection)
                self.assertEqual(report["tables"], 5)
                self.assertEqual(report["rows"], 3)
                self.assertNotIn(b"DO-NOT-STORE-CLEAR", (root / "copy.sqlite").read_bytes())
                archive = Archive(vault, root / "copy.sqlite", expected_digest=report["sha256"])
                try:
                    rows = [raw for table in archive.manifest["tables"] if table["name"] == "records" for raw in archive.raw_rows(table)]
                    self.assertIn(b"1.2345678901234567890123456789", rows[0])
                    self.assertIn(b"deadbeef", rows[0])
                finally:
                    archive.close()
                installed = install_ciphertext(vault, root / "copy.sqlite", report["sha256"], connection)
                self.assertTrue(installed["all_rows_authenticated"])
                self.assertEqual(installed["target_tables"], 6)
                with connection.cursor() as cursor:
                    cursor.execute("SELECT tablename FROM pg_tables WHERE schemaname='warden_cipher'")
                    for (name,) in cursor.fetchall():
                        cursor.execute(sql.SQL("SELECT id,payload FROM warden_cipher.{}").format(sql.Identifier(name)))
                        for identifier, payload in cursor.fetchall():
                            self.assertEqual(len(identifier), 32)
                            self.assertTrue(payload.startswith("wa1:"))
                    cursor.execute("SELECT count(*) FROM fixture.records")
                    self.assertEqual(cursor.fetchone()[0], 1)
                connection.commit()
                with self.assertRaises(Exception):
                    install_ciphertext(vault, root / "copy.sqlite", report["sha256"], connection)
                with connection.cursor() as cursor:
                    cursor.execute("DROP SCHEMA warden_cipher CASCADE")
                    cursor.execute("DROP SCHEMA fixture CASCADE")
                connection.commit()
                vault.lock()


if __name__ == "__main__":
    unittest.main()
