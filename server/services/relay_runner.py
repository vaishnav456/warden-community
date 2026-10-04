"""Dedicated relay owner with a private, minimal readiness listener."""
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from services.process_role import role
from services.lifecycle import stopping, install_signal_handlers, wait_for_workers


def main():
    os.environ['WARDEN_PROCESS_ROLE'] = 'relay'
    if role() != 'relay':
        raise RuntimeError('Invalid relay role')
    import db
    from services import ws_proxy
    install_signal_handlers()
    db.close_all_active_remote_sessions()
    ws_proxy.start()
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            healthy = self.path == '/ready' and ws_proxy.is_ready() and not stopping.is_set()
            self.send_response(200 if healthy else 503)
            self.send_header('Content-Type','application/json')
            self.send_header('Content-Length','2')
            self.end_headers()
            self.wfile.write(b'{}')
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer((os.environ.get('HOST','127.0.0.1'),35022),Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever,daemon=True,name='relay-readiness')
    thread.start()
    try:
        stopping.wait()
    finally:
        server.shutdown()
        server.server_close()
        wait_for_workers()


if __name__ == '__main__':
    main()
