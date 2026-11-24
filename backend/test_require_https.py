import os
import unittest
from unittest.mock import AsyncMock, patch

from starlette.requests import Request
from starlette.responses import PlainTextResponse

from backend.http_security import RequireHttpsMiddleware


class RequireHttpsTests(unittest.IsolatedAsyncioTestCase):
    async def test_disabled_by_default(self):
        app = AsyncMock(return_value=None)
        mw = RequireHttpsMiddleware(app)

        async def call_next(request):
            return PlainTextResponse("ok")

        scope = {"type": "http", "method": "GET", "path": "/api/x", "headers": [], "scheme": "http", "server": ("t", 80), "client": ("1.1.1.1", 1), "query_string": b""}
        request = Request(scope)
        with patch.dict(os.environ, {"EDR_REQUIRE_HTTPS": ""}, clear=False):
            resp = await mw.dispatch(request, call_next)
        self.assertEqual(resp.status_code, 200)

    async def test_blocks_http_when_enabled(self):
        mw = RequireHttpsMiddleware(AsyncMock())

        async def call_next(request):
            return PlainTextResponse("ok")

        scope = {"type": "http", "method": "GET", "path": "/api/x", "headers": [], "scheme": "http", "server": ("t", 80), "client": ("1.1.1.1", 1), "query_string": b""}
        request = Request(scope)
        with patch.dict(os.environ, {"EDR_REQUIRE_HTTPS": "1"}, clear=False):
            resp = await mw.dispatch(request, call_next)
        self.assertEqual(resp.status_code, 403)

    async def test_health_exempt(self):
        mw = RequireHttpsMiddleware(AsyncMock())

        async def call_next(request):
            return PlainTextResponse("ok")

        scope = {"type": "http", "method": "GET", "path": "/health/ready", "headers": [], "scheme": "http", "server": ("t", 80), "client": ("1.1.1.1", 1), "query_string": b""}
        request = Request(scope)
        with patch.dict(os.environ, {"EDR_REQUIRE_HTTPS": "1"}, clear=False):
            resp = await mw.dispatch(request, call_next)
        self.assertEqual(resp.status_code, 200)


if __name__ == "__main__":
    unittest.main()
