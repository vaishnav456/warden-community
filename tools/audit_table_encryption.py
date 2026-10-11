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

import psycopg2
from psycopg2 import sql


def audit(connection, schema):
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
    incomplete = not report['table_count'] or any(not table['rows'] for table in report['tables']) or any(
        column['populated'] != column['versioned_ciphertext']
        for table in report['tables'] for column in table['columns'])
    return 2 if incomplete else 0


if __name__ == '__main__':
    sys.exit(main())
