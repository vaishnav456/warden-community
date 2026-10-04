"""Small control-plane request limits, before CSRF/auth parsing or JSON allocation."""
from io import BytesIO
from werkzeug.wrappers import Response


class ControlPlaneBodyLimits:
    def __init__(self, application):
        self.application=application

    def __call__(self, environ, start_response):
        path=environ.get("PATH_INFO","")
        limit=None
        if path=="/api/agent/heartbeat":
            limit=3*1024*1024
        elif path.startswith("/operations/support") or path.startswith("/api/agent/support-") or path in {
                "/api/agent/heartbeat/crypto","/api/agent/integrity/manifest","/api/agent/certificate/renew"}:
            limit=64*1024
        if limit is not None and environ.get("REQUEST_METHOD") in {"POST","PUT","PATCH"}:
            declared=environ.get("CONTENT_LENGTH","")
            try:
                if declared and (int(declared)<0 or int(declared)>limit):
                    return Response('{"error":"request_too_large"}',status=413,mimetype="application/json")(environ,start_response)
                # Do not read to EOF on a persistent, unterminated WSGI stream.
                length=int(declared) if declared else limit+1 if environ.get("wsgi.input_terminated") else 0
                raw=environ["wsgi.input"].read(length)
                if len(raw)>limit:
                    return Response('{"error":"request_too_large"}',status=413,mimetype="application/json")(environ,start_response)
            except (ValueError,OSError):
                return Response('{"error":"invalid_request"}',status=400,mimetype="application/json")(environ,start_response)
            environ["wsgi.input"]=BytesIO(raw)
            environ["CONTENT_LENGTH"]=str(len(raw))
        return self.application(environ,start_response)
