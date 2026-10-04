"""Mechanically extract database domains, retaining the db compatibility API.

Uses symbol tables to preserve dynamic db lookups (including test/operational
patching), and verifies each moved function's AST after undoing qualification.
Run once against an unsplit checkout: python tools/refactor_database.py ROOT
"""
import ast
import pathlib
import symtable
import sys


SECTIONS = {
    "Branches": "branches",
    "Policy templates & per-endpoint policy state": "policies",
    "Admin Users": "admins",
    "Refresh Tokens": "sessions",
    "Enrollment Tokens": "enrollment_tokens",
    "Zero-touch enrollment profiles and pre-registered device claims": "enrollment_profiles",
    "Endpoints": "endpoints",
    "Firewall block list (app-level, superadmin-controlled — see middleware/security.py)": "firewall",
    "Jobs": "jobs",
    "Windows Users": "windows_users",
    "Warden identities (desired state; separate from discovered local accounts)": "identities",
    "Software Inventory": "inventory",
    "Warden Home storage control plane": "home_storage",
    "Escalation Requests": "escalations",
    "Saved Escalations (Policies)": "escalation_policies",
    "Alerts": "alerts",
    "App Library": "apps",
    "Endpoint Metrics": "metrics",
    "Endpoint Events": "events",
    "Build Requests": "builds",
    "Remote Sessions": "remote_sessions",
    "Notifications": "notifications",
    "Compliance policies": "compliance",
    "Compliance results": "compliance",
    "Scheduled jobs": "schedules",
}


def compact_facade(source):
    tree = ast.parse(source)
    protected = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            protected.update(range(node.lineno, node.end_lineno + 1))
    result, blanks = [], 0
    for number, line in enumerate(source.splitlines(keepends=True), 1):
        blanks = blanks + 1 if not line.strip() else 0
        if blanks <= 2 or number in protected:
            result.append(line)
    output = ''.join(result)
    if ast.dump(ast.parse(output)) != ast.dump(tree):
        raise ValueError('Formatting changed database AST')
    return output


def bound_names(tree):
    names = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names.update(alias.asname or alias.name.split('.')[0] for alias in node.names)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names.update(n.id for target in targets for n in ast.walk(target) if isinstance(n, ast.Name))
    return names


class Unqualify(ast.NodeTransformer):
    def visit_Attribute(self, node):
        if isinstance(node.value, ast.Name) and node.value.id == '_db':
            return ast.copy_location(ast.Name(id=node.attr, ctx=node.ctx), node)
        return self.generic_visit(node)


def refactor(root):
    path = root / 'server/db.py'
    source = path.read_text(encoding='utf-8')
    lines = source.splitlines(keepends=True)
    offsets, total = [], 0
    for line in lines:
        offsets.append(total)
        total += len(line.encode())
    raw = source.encode()
    tree = ast.parse(source)
    symbols = symtable.symtable(source, str(path), 'exec')
    bindings = bound_names(tree)
    section_by_line, current = {}, None
    for index, line in enumerate(lines, 1):
        if line.startswith('# ') and line.strip('# \n\r') in SECTIONS:
            current = SECTIONS[line.strip('# \n\r')]
        elif line.startswith('# ─'):
            pass
        elif line.startswith('# ') and index > 1 and lines[index - 2].startswith('# ─'):
            current = None
        section_by_line[index] = current
    modules, replacements = {}, []
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef):
            continue
        target = section_by_line[node.lineno]
        if not target:
            continue
        if node.decorator_list:
            raise ValueError('Decorated function requires manual review: ' + node.name)
        scope = next(s for s in symbols.get_children() if s.get_name() == node.name and s.get_lineno() == node.lineno)
        globals_used = {name for name in scope.get_identifiers()
                        if scope.lookup(name).is_global() and name in bindings}
        pending = list(scope.get_children())
        while pending:
            child = pending.pop()
            pending.extend(child.get_children())
            for name in child.get_identifiers():
                symbol = child.lookup(name)
                if name in globals_used and symbol.is_local():
                    raise ValueError('Nested shadow requires review: ' + node.name + '/' + name)
                if symbol.is_global() and name in bindings:
                    globals_used.add(name)
        start = offsets[node.lineno - 1]
        end = offsets[node.end_lineno - 1] + len(lines[node.end_lineno - 1].encode())
        edits = []
        # Only transform the body. Original signatures/defaults remain unchanged.
        for statement in node.body:
            for child in ast.walk(statement):
                if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load) and child.id in globals_used:
                    position = offsets[child.lineno - 1] + child.col_offset
                    edits.append((position - start, b'_db.'))
        has_doc = isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant) and isinstance(node.body[0].value.value, str)
        position = (offsets[node.body[0].end_lineno - 1] + len(lines[node.body[0].end_lineno - 1].encode())) if has_doc else offsets[node.body[0].lineno - 1]
        edits.append((position - start, b'    import db as _db\n'))
        content = raw[start:end]
        for position, insertion in sorted(edits, reverse=True):
            content = content[:position] + insertion + content[position:]
        moved = ast.parse(content).body[0]
        restored = Unqualify().visit(moved)
        restored.body = [statement for statement in restored.body
                         if not (isinstance(statement, ast.Import) and any(a.asname == '_db' for a in statement.names))]
        if ast.dump(restored, include_attributes=False) != ast.dump(node, include_attributes=False):
            raise ValueError('Function changed: ' + node.name)
        modules.setdefault(target, []).append((node.name, content.decode()))
        replacements.append((start, end, target))
    if not modules:
        raise ValueError('No database domains found (already split?)')
    directory = root / 'server/database'
    if directory.exists():
        raise ValueError('Refusing to overwrite database package')
    imports_inserted = set()
    output = raw
    for start, end, target in sorted(replacements, reverse=True):
        replacement = b''
        if target not in imports_inserted:
            names = ',\n    '.join(name for name, _ in modules[target])
            replacement = f'from database.{target} import (\n    {names},\n)\n'.encode()
            imports_inserted.add(target)
        output = output[:start] + replacement + output[end:]
    output = compact_facade(output.decode()).encode()
    directory.mkdir()
    (directory / '__init__.py').write_text('"""Database domain implementations; db remains the compatibility facade."""\n')
    for target, functions in modules.items():
        content = '"""' + target.replace('_', ' ').capitalize() + ' database operations."""\n\n\n' + '\n\n'.join(text.rstrip() for _, text in functions) + '\n'
        (directory / (target + '.py')).write_text(content, encoding='utf-8')
        print(target, len(functions), 'functions', len(content.splitlines()), 'lines')
    path.write_bytes(output)
    print('Verified', sum(map(len, modules.values())), 'unchanged functions;', len(output.splitlines()), 'facade lines')


if __name__ == '__main__':
    root = pathlib.Path(sys.argv[1]).resolve()
    if '--compact' in sys.argv[2:]:
        path = root / 'server/db.py'
        path.write_text(compact_facade(path.read_text(encoding='utf-8')), encoding='utf-8')
    else:
        refactor(root)
