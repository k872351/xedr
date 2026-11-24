import unittest
from unittest.mock import patch

from starlette.requests import Request
from starlette.responses import Response
from backend.http_security import _origin_allowed, is_trusted_proxy, SameHostCORSMiddleware


class HttpSecurityTests(unittest.TestCase):
    def test_invalid_origin(self):
        with patch.dict("os.environ", {"FORENSIC_CORS": "", "FORENSIC_CORS_REGEX": ""}):
            self.assertTrue(_origin_allowed("http://localhost:8000", "localhost:8001"))
            for value in ("http://localhost:bad", "http://localhost:8000/path", "http://[bad"):
                self.assertFalse(_origin_allowed(value, "localhost:8001"))

    def test_proxy_configuration(self):
        request = Request({"type": "http", "client": ("127.0.0.1", 12345)})
        with patch.dict("os.environ", {"FORENSIC_TRUST_PROXY": "1", "FORENSIC_TRUSTED_PROXIES": "127.0.0.1"}):
            self.assertTrue(is_trusted_proxy(request))
        with patch.dict("os.environ", {"FORENSIC_TRUST_PROXY": "0"}):
            self.assertFalse(is_trusted_proxy(request))


class CorsResponseTests(unittest.TestCase):
    def test_allowed_origin_preserves_existing_vary_header(self):
        request = Request({"type": "http", "method": "GET", "scheme": "http", "path": "/", "headers": [(b"host", b"localhost:8001"), (b"origin", b"http://localhost:8000")]})
        async def downstream(_request):
            return Response(headers={"Vary": "Accept-Encoding", "Cache-Control": "no-store"})
        middleware = SameHostCORSMiddleware(app=None)
        with patch.dict("os.environ", {"FORENSIC_CORS": "", "FORENSIC_CORS_REGEX": ""}):
            # Both fixture coroutines complete synchronously; avoid starting an
            # event loop in environments where the async test runner stalls.
            coroutine = middleware.dispatch(request, downstream)
            with self.assertRaises(StopIteration) as completed:
                coroutine.send(None)
            response = completed.exception.value
        self.assertEqual(response.headers["access-control-allow-origin"], "http://localhost:8000")
        self.assertEqual(set(x.strip().lower() for x in response.headers["vary"].split(",")), {"accept-encoding", "origin"})
        self.assertEqual(response.headers["cache-control"], "no-store")
