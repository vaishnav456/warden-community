"""Portable, non-mutating candidate checks. Does not deploy or run migrations."""
import ast
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = {
    '26-server-read-optimization.sql': '2026-10-04-server-read-optimization.sql',
    '27-operational-foundations.sql': '2026-10-04-operational-foundations.sql',
    '28-fleet-read-optimization.sql': '2026-10-04-fleet-read-optimization.sql',
}


def check(root=ROOT):
    results = {}
    for path in (root / 'server').rglob('*.py'):
        if '__pycache__' not in path.parts:
            ast.parse(path.read_text(encoding='utf-8-sig'), filename=str(path.relative_to(root)))
    for init, migration in MIGRATIONS.items():
        left = (root / 'db-init' / init).read_text().replace('\r\n', '\n')
        right = (root / 'migrations' / migration).read_text().replace('\r\n', '\n')
        if left != right:
            raise ValueError('Migration/init mismatch: ' + migration)
        results[migration] = hashlib.sha256(right.encode()).hexdigest()
    return dict(syntax='passed', migrations=results,
                note='Also require regression, dependency, restore and pilot evidence before release')


if __name__ == '__main__':
    print(json.dumps(check(), indent=2))
