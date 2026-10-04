import io
import unittest
from werkzeug.test import Client
from werkzeug.wrappers import Response
from services.request_limits import ControlPlaneBodyLimits


class BodyLimitTests(unittest.TestCase):
    def setUp(self):
        self.calls=0
        def application(environ,start_response):
            self.calls+=1
            return Response(environ["wsgi.input"].read())(environ,start_response)
        self.wrapper=ControlPlaneBodyLimits(application)
        self.client=Client(self.wrapper,Response)

    def test_large_control_plane_request_rejected_before_application(self):
        for path in ("/operations/support/new","/api/agent/support-request","/api/agent/integrity/manifest"):
            self.assertEqual(self.client.post(path,data=b"x"*65537).status_code,413)
        self.assertEqual(self.calls,0)
    def test_upload_limit_unchanged_and_valid_body_preserved(self):
        self.assertEqual(self.client.post("/apps/upload",data=b"x"*70000).status_code,200)
        response=self.client.post("/api/agent/support-reply",json={"message":"hello"})
        self.assertEqual(response.status_code,200)
        self.assertIn(b"hello",response.data)

    def test_terminated_chunked_stream_is_bounded(self):
        result={}
        environ=dict(PATH_INFO="/api/agent/support-request",REQUEST_METHOD="POST",
                     **{"wsgi.input":io.BytesIO(b"x"*65537),"wsgi.input_terminated":True})
        body=self.wrapper(environ,lambda status,headers:result.update(status=status))
        self.assertTrue(result["status"].startswith("413"))
        self.assertEqual(self.calls,0)
