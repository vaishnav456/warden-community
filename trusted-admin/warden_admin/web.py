"""Private, independently installed administration UI. No public decryption API."""
from collections import deque
import hmac
import json
import secrets
import threading
import time

from flask import Flask, abort, redirect, render_template_string, request, session, url_for

from .archive import Archive, load_checkpoint
from .crypto import Vault


PAGE = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Warden Admin</title>
<style nonce="{{ nonce }}">
:root{font-family:system-ui,sans-serif;color:#e8edf6;background:#101722}body{margin:0}
main{max-width:1080px;margin:40px auto;padding:0 24px}header{display:flex;align-items:center;justify-content:space-between;gap:20px}
h1{font-size:28px;margin-bottom:8px}h2{font-size:20px}p{color:#aab8ca;line-height:1.6}
a{color:#87b9ff}button{background:#87b9ff;color:#101722;font:inherit;border:0;border-radius:8px;padding:10px 18px;cursor:pointer}
input{display:block;width:min(400px,90%);padding:12px;margin:12px 0 20px;border:1px solid #526176;border-radius:8px;background:#172231;color:#e8edf6;font:inherit}
section{background:#172231;border:1px solid #304156;border-radius:14px;padding:24px;margin:24px 0}.tables{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
.tables a{padding:16px;background:#101722;border-radius:8px;text-decoration:none}.tables small{display:block;color:#aab8ca;margin-top:6px}
.scroll{overflow:auto}table{border-collapse:collapse;font-size:13px;width:100%}th,td{text-align:left;vertical-align:top;border-bottom:1px solid #304156;padding:10px;max-width:420px;overflow-wrap:anywhere}th{color:#87b9ff}form{margin:0}.notice{color:#ffd795}
</style><main><header><div><h1>Warden Admin</h1><p>Your private data workspace</p></div>
{% if unlocked %}<form method="post" action="{{ url_for('lock') }}"><input type="hidden" name="csrf" value="{{ csrf }}"><button>Lock workspace</button></form>{% endif %}</header>
{% if message %}<p class="notice" role="alert">{{ message }}</p>{% endif %}
{% if not unlocked %}<section><h2>Unlock workspace</h2><p>Enter your admin unlock phrase to view the encrypted data copy.</p>
<form method="post" action="{{ url_for('unlock') }}"><input type="hidden" name="csrf" value="{{ csrf }}">
<label for="phrase">Admin unlock phrase</label><input id="phrase" name="phrase" type="password" required autocomplete="current-password" minlength="16" maxlength="4096"><button>Unlock</button></form></section>
{% elif table %}<section><a href="{{ url_for('index') }}">All tables</a><h2>{{ table.schema }}.{{ table.name }}</h2>
<p>{{ table.rows }} records. Showing up to {{ page_size }} records on this page.</p><div class="scroll"><table><thead><tr>{% for column in columns %}<th>{{ column }}</th>{% endfor %}</tr></thead><tbody>
{% for row in rows %}<tr>{% for column in columns %}<td>{{ row.get(column) | cell }}</td>{% endfor %}</tr>{% endfor %}</tbody></table></div>
{% if previous %}<a href="{{ previous }}">Previous page</a>{% endif %} {% if next %}<a href="{{ next }}">Next page</a>{% endif %}</section>
{% else %}<section><h2>Encrypted data copy</h2><p>{{ tables | length }} tables verified. This copy is read-only; the current Warden database still serves the application.</p>
<div class="tables">{% for entry in tables %}<a href="{{ url_for('table_page', index=loop.index0) }}">{{ entry.schema }}.{{ entry.name }}<small>{{ entry.rows }} records</small></a>{% endfor %}</div></section>{% endif %}
<p>The workspace locks after ten minutes without activity. If this app shares a host with Warden, host administrators can access unlocked data. Move it to a separate trusted machine for isolation.</p></main></html>"""


def create_app(vault_path, archive_path, checkpoint_path, *, clock=time.monotonic):
    app = Flask(__name__, static_folder=None)
    app.secret_key = secrets.token_bytes(32)
    app.config.update(MAX_CONTENT_LENGTH=8192, SESSION_COOKIE_NAME="warden_admin",
                      SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict")
    mutex = threading.RLock()
    state = {"vault": None, "archive": None, "owner": None, "activity": 0, "attempts": deque()}

    def clear():
        if state["archive"] is not None:
            state["archive"].close()
        if state["vault"] is not None:
            state["vault"].lock()
        state.update(vault=None, archive=None, owner=None, activity=0)

    def authorized():
        return (state["vault"] is not None and state["owner"] is not None
                and hmac.compare_digest(session.get("owner", ""), state["owner"]))

    def expire():
        with mutex:
            if state["vault"] is not None and clock() - state["activity"] >= 600:
                clear()

    def expiration_worker():
        while not app.extensions["admin_stop"].wait(15):
            expire()

    app.extensions["admin_stop"] = threading.Event()
    app.extensions["admin_expire"] = expire
    def shutdown():
        app.extensions["admin_stop"].set()
        with mutex:
            clear()
    app.extensions["admin_shutdown"] = shutdown
    threading.Thread(target=expiration_worker, name="admin-vault-lock", daemon=True).start()

    @app.before_request
    def protect():
        # Prevent browser DNS rebinding and cross-site requests to localhost.
        if request.host.split(":", 1)[0] not in {"127.0.0.1", "localhost"}:
            abort(403)
        expire()
        session.setdefault("csrf", secrets.token_urlsafe(32))
        if request.method == "POST":
            origin = request.headers.get("Origin")
            if origin is not None and origin != request.host_url.rstrip("/"):
                abort(403)
            if not hmac.compare_digest(request.form.get("csrf", ""), session["csrf"]):
                abort(403)

    @app.after_request
    def headers(response):
        nonce = getattr(request, "admin_nonce", "")
        response.headers.update({"Cache-Control": "no-store", "Pragma": "no-cache",
            "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": "default-src 'none'; style-src 'nonce-" + nonce +
              "'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"})
        return response

    def page(**values):
        request.admin_nonce = secrets.token_urlsafe(24)
        values.update(nonce=request.admin_nonce, csrf=session["csrf"], unlocked=authorized())
        return render_template_string(PAGE, **values)

    @app.template_filter("cell")
    def cell(value):
        if isinstance(value, (dict, list)):
            return json.dumps(value, ensure_ascii=False)
        return "—" if value is None else str(value)

    @app.get("/")
    def index():
        with mutex:
            if authorized():
                state["activity"] = clock()
            return page(tables=state["archive"].manifest["tables"] if authorized() else [])

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.post("/unlock")
    def unlock():
        with mutex:
            while state["attempts"] and clock() - state["attempts"][0] >= 300:
                state["attempts"].popleft()
            if len(state["attempts"]) >= 5:
                return page(message="Please wait five minutes before trying again."), 429
            state["attempts"].append(clock())
            vault = None
            archive = None
            try:
                vault = Vault.unlock(vault_path, request.form.get("phrase", ""))
                archive = Archive(vault, archive_path,
                                  expected_digest=load_checkpoint(vault, checkpoint_path))
                archive.verify()
            except Exception:
                if archive is not None:
                    archive.close()
                if vault is not None:
                    vault.lock()
                return page(message="The workspace could not be unlocked. Check the phrase and data copy."), 400
            clear()
            session["owner"] = secrets.token_urlsafe(32)
            session["csrf"] = secrets.token_urlsafe(32)
            state.update(vault=vault, archive=archive, owner=session["owner"], activity=clock())
            state["attempts"].clear()
            return redirect(url_for("index"))

    @app.post("/lock")
    def lock():
        with mutex:
            if authorized():
                clear()
            session.clear()
            return redirect(url_for("index"))

    @app.get("/tables/<int:index>")
    def table_page(index):
        from itertools import islice
        with mutex:
            if not authorized():
                return redirect(url_for("index"))
            tables = state["archive"].manifest["tables"]
            if index >= len(tables):
                abort(404)
            offset = request.args.get("offset", "0")
            if not offset.isdecimal() or len(offset) > 10 or int(offset) > tables[index]["rows"]:
                abort(400)
            offset = int(offset)
            table = tables[index]
            size = 50
            try:
                rows = [json.loads(raw) for raw in islice(state["archive"].raw_rows(table), offset, offset + size)]
                if any(not isinstance(row, dict) for row in rows):
                    raise ValueError("Invalid archived row")
            except Exception:
                clear()
                return page(message="The data copy could not be verified. The workspace has been locked."), 400
            state["activity"] = clock()
            return page(table=table, rows=rows, columns=[column["name"] for column in table["columns"]],
                        page_size=size,
                        previous=url_for("table_page", index=index, offset=max(0, offset-size)) if offset else None,
                        next=url_for("table_page", index=index, offset=offset+size) if offset+size < table["rows"] else None)

    return app
