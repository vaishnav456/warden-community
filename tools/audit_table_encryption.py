"""Read-only inventory of EVERY application table, without exporting data values.

Set DATABASE_URL privately, then run this file. Prefix counts describe storage
format, not cryptographic authentication. Unversioned values may include valid
legacy ciphertext; they must be checked using the application's proper context.
Exit 2 means populated columns are not uniformly versioned ciphertext. Empty
tables cannot establish coverage of future writes. No schemas or rows are changed.
"""
import argparse
import json
import os
import sys
import re

import psycopg2
from psycopg2 import sql


def audit(connection, schema):
    if schema == 'warden_cipher':
        return audit_cipher_store(connection)
    connection.set_session(readonly=True, autocommit=False)
    tables = []
    with connection.cursor() as cursor:
        cursor.execute("SET LOCAL statement_timeout = '30s'")
        cursor.execute("""
            SELECT c.relname FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = %s AND c.relkind IN ('r', 'p')
            ORDER BY c.relname
        """, (schema,))
        names = [row[0] for row in cursor.fetchall()]
        for name in names:
            cursor.execute("""
                SELECT a.attname, format_type(a.atttypid, a.atttypmod)
                FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = %s AND c.relname = %s
                  AND a.attnum > 0 AND NOT a.attisdropped
                ORDER BY a.attnum
            """, (schema, name))
            columns = cursor.fetchall()
            expressions = [sql.SQL('count(*)')]
            for column, datatype in columns:
                identifier = sql.Identifier(column)
                value = sql.SQL('{}::text').format(identifier)
                if datatype in {'json', 'jsonb'}:
                    value = sql.SQL("CASE WHEN jsonb_typeof({}::jsonb) = 'string' THEN {}::jsonb #>> '{{}}' ELSE {}::text END").format(identifier, identifier, identifier)
                expressions.extend([
                    sql.SQL('count({})').format(identifier),
                    sql.SQL("count(*) FILTER (WHERE ({}) LIKE 'v2:%%' OR ({}) LIKE 'enc:v1:%%')").format(value, value),
                    sql.SQL("count(*) FILTER (WHERE ({}) LIKE 'h1:%%' OR ({}) LIKE '$2a$%%' OR ({}) LIKE '$2b$%%' OR ({}) LIKE '$2y$%%')").format(value, value, value, value),
                ])
            cursor.execute(sql.SQL('SELECT {} FROM {}.{}').format(
                sql.SQL(', ').join(expressions), sql.Identifier(schema), sql.Identifier(name)))
            counts = cursor.fetchone()
            entry = {'table': name, 'rows': counts[0], 'columns': []}
            for index, (column, datatype) in enumerate(columns):
                populated, encrypted, hashed = counts[1 + index * 3:4 + index * 3]
                entry['columns'].append({
                    'column': column, 'type': datatype, 'populated': populated,
                    'versioned_ciphertext': encrypted, 'one_way_hash_format': hashed,
                    'other_format': populated - encrypted - hashed,
                })
            tables.append(entry)
    connection.rollback()
    return {'schema': schema, 'table_count': len(tables),
            'format_only': True, 'contains_record_values': False, 'tables': tables}


def audit_cipher_store(connection):
    """Opaque identifiers are structure; every stored business value is a blob.

    This is a format/schema inventory only. Runtime startup/audit additionally
    authenticate ciphertext and compare the independent trusted checkpoint.
    """
    connection.set_session(readonly=True, autocommit=False)
    tables = []
    complete = True
    with connection.cursor() as cursor:
        cursor.execute("SET LOCAL statement_timeout = '30s'")
        cursor.execute("""SELECT n.nspname,c.relname,c.relkind FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname NOT LIKE 'pg\\_%%' ESCAPE '\\' AND n.nspname<>'information_schema'
          AND c.relkind IN ('r','p','m','f') ORDER BY n.nspname,c.relname""")
        relations = cursor.fetchall()
        for schema, name, kind in relations:
            payload = 'manifest' if name == 'head' else 'payload'
            if schema != 'warden_cipher' or kind != 'r' or name != 'head' and not re.fullmatch(r'r_[0-9a-f]{32}', name):
                complete = False
                tables.append(dict(table=name, schema=schema, unexpected_relation=True))
                continue
            cursor.execute("""SELECT column_name,data_type FROM information_schema.columns
              WHERE table_schema=%s AND table_name=%s ORDER BY ordinal_position""", (schema, name))
            expected = [('id', 'uuid'), ('revision', 'uuid'), ('manifest', 'text')] if name == 'head' else [('id', 'uuid'), ('payload', 'text')]
            shape = cursor.fetchall() == expected
            cursor.execute(sql.SQL("SELECT count(*),count(*) FILTER (WHERE {} ~ '^wdb1:[A-Za-z0-9_-]+$') FROM {}.{}").format(
                sql.Identifier(payload), sql.Identifier(schema), sql.Identifier(name)))
            rows, encrypted = cursor.fetchone()
            complete = complete and shape and rows == encrypted and (name != 'head' or rows == 1)
            tables.append(dict(table=name, rows=rows, encrypted_payload_format=encrypted, opaque_schema=shape))
    connection.rollback()
    complete = complete and any(t['table'] == 'head' for t in tables)
    return dict(schema='warden_cipher', table_count=len(tables), record_table_count=sum(t['table'].startswith('r_') for t in tables),
                format_only=True, contains_record_values=False, complete_ciphertext_format=complete, tables=tables)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--schema', default='endpt')
    args = parser.parse_args()
    if not os.environ.get('DATABASE_URL'):
        parser.error('Set DATABASE_URL privately; do not pass credentials on the command line')
    try:
        with psycopg2.connect(os.environ['DATABASE_URL']) as connection:
            report = audit(connection, args.schema)
    except Exception:
        # Connection/query errors can include DSNs or record content.
        print('Database audit failed; inspect connectivity and permissions privately', file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    if 'complete_ciphertext_format' in report:
        incomplete = not report['complete_ciphertext_format']
    else:
        incomplete = not report['table_count'] or any(not table['rows'] for table in report['tables']) or any(
            column['populated'] != column['versioned_ciphertext']
            for table in report['tables'] for column in table['columns'])
    return 2 if incomplete else 0


if __name__ == '__main__':
    sys.exit(main())
