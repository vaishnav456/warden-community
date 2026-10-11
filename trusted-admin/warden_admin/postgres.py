"""Read-only consistent source capture and ciphertext-only target installation."""
from .archive import Archive, capture, _identifier


def capture_postgres(vault, path, connection):
    """Include every non-system physical table; never export clear row values.

    Partitions are read with ONLY so each physical row is captured once. Catalog
    metadata and function/view definitions are encrypted along with the rows.
    Foreign tables fail closed: their snapshot cannot be guaranteed by PostgreSQL.
    """
    from psycopg2 import sql
    connection.set_session(isolation_level="REPEATABLE READ", readonly=True, autocommit=False)
    try:
        with connection.cursor() as cursor:
            cursor.execute("SET LOCAL statement_timeout = '60s'")
            cursor.execute("""
                SELECT n.nspname, c.relname, c.relkind
                FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                WHERE n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
                  AND n.nspname <> 'information_schema'
                  AND c.relkind IN ('r','p','m','f') ORDER BY 1,2
            """)
            names = cursor.fetchall()
            if any(kind == "f" for _, _, kind in names):
                raise ValueError("Foreign tables require a separately verified source snapshot")
            definitions = []
            for schema, name, kind in names:
                cursor.execute("""
                    SELECT a.attname, format_type(a.atttypid,a.atttypmod), a.attnotnull,
                           pg_get_expr(d.adbin,d.adrelid), a.attidentity, a.attgenerated,
                           col_description(c.oid,a.attnum)
                    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                    JOIN pg_attribute a ON a.attrelid=c.oid
                    LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum
                    WHERE n.nspname=%s AND c.relname=%s AND a.attnum>0 AND NOT a.attisdropped
                    ORDER BY a.attnum
                """, (schema, name))
                columns = [dict(zip(("name", "type", "not_null", "default", "identity",
                                     "generated", "comment"), row)) for row in cursor.fetchall()]
                definitions.append((schema, name, columns, kind))
            cursor.execute("""
                SELECT n.nspname,c.relname,pg_get_viewdef(c.oid,true)
                FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                WHERE n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
                  AND n.nspname <> 'information_schema' AND c.relkind IN ('v','m') ORDER BY 1,2
            """)
            views = cursor.fetchall()
            cursor.execute("""
                SELECT n.nspname,p.proname,pg_get_functiondef(p.oid)
                FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                WHERE n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
                  AND n.nspname <> 'information_schema' AND p.prokind IN ('f','p') ORDER BY 1,2,3
            """)
            functions = cursor.fetchall()
            cursor.execute("""
                SELECT n.nspname,c.relname,k.conname,pg_get_constraintdef(k.oid,true)
                FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid
                JOIN pg_namespace n ON n.oid=c.relnamespace
                WHERE n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
                  AND n.nspname <> 'information_schema' ORDER BY 1,2,3
            """)
            constraints = cursor.fetchall()

        def tables():
            for index, (schema, name, columns, kind) in enumerate(definitions):
                with connection.cursor(name=f"trusted_capture_{index}") as reader:
                    reader.itersize = 500
                    source = sql.SQL("{}.{}").format(sql.Identifier(schema), sql.Identifier(name))
                    # Materialized views cannot use ONLY, but contain their own
                    # independently persisted rows and must also be encrypted.
                    only = sql.SQL("") if kind == "m" else sql.SQL("ONLY ")
                    reader.execute(sql.SQL("SELECT row_to_json(r)::text FROM {}{} r").format(only, source))
                    yield schema, name, columns, (row[0].encode("utf-8") for row in reader)

        report = capture(vault, path, tables(), metadata={"views": views, "functions": functions,
                                                       "constraints": constraints,
                                                       "consistent_snapshot": True})
        connection.rollback()
        return report
    finally:
        connection.rollback()


def install_ciphertext(vault, archive_path, expected_digest, connection, *, schema="warden_cipher"):
    """Install into a NEW, empty schema, atomically; never replace the live DB.

    Source schema/table names are not sent to the target. Target columns contain
    random identifiers and complete encrypted records, including source IDs,
    timestamps, flags, numbers and nulls. This creates a staging copy, not cutover.
    """
    from psycopg2 import sql
    from psycopg2.extras import execute_values
    if schema != "warden_cipher":
        raise ValueError("The encrypted staging schema is fixed")
    archive = Archive(vault, archive_path, expected_digest=expected_digest)
    try:
        report = archive.verify()
        connection.set_session(isolation_level="READ COMMITTED", readonly=False, autocommit=False)
        with connection.cursor() as cursor:
            # No IF NOT EXISTS: an existing copy must never be overwritten.
            cursor.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
            for table in [{"id": "archive"}, *archive.manifest["tables"]]:
                name = table["id"]
                if name != "archive":
                    _identifier(name)
                target = sql.SQL("{}.{}").format(sql.Identifier(schema), sql.Identifier(name))
                cursor.execute(sql.SQL("CREATE TABLE {} (id text PRIMARY KEY, payload text NOT NULL CHECK (payload LIKE 'wa1:%'))").format(target))
                batch = []
                for row in archive.connection.execute(f'SELECT id,payload FROM "{name}" ORDER BY id'):
                    batch.append(row)
                    if len(batch) == 500:
                        execute_values(cursor, sql.SQL("INSERT INTO {} VALUES %s").format(target).as_string(connection), batch, page_size=500)
                        batch.clear()
                if batch:
                    execute_values(cursor, sql.SQL("INSERT INTO {} VALUES %s").format(target).as_string(connection), batch, page_size=500)
            # Verify every destination byte against the authenticated source
            # before committing. No decryption runs inside PostgreSQL.
            for table in [{"id": "archive"}, *archive.manifest["tables"]]:
                name = table["id"]
                target = sql.SQL("{}.{}").format(sql.Identifier(schema), sql.Identifier(name))
                with connection.cursor(name="verify_" + name) as reader:
                    reader.execute(sql.SQL("SELECT id,payload FROM {} ORDER BY id").format(target))
                    original = iter(archive.connection.execute(f'SELECT id,payload FROM "{name}" ORDER BY id'))
                    for actual in reader:
                        if actual != next(original, None):
                            raise ValueError("Ciphertext installation verification failed")
                    if next(original, None) is not None:
                        raise ValueError("Ciphertext installation is incomplete")
        connection.commit()
        return {**report, "target_tables": report["tables"] + 1,
                "ciphertext_copy_only": True, "live_database_changed": False}
    except BaseException:
        connection.rollback()
        raise
    finally:
        archive.close()
