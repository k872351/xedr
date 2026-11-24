import json
import unittest
from unittest.mock import patch

from fastapi import FastAPI
from starlette.requests import Request

from backend.health_routes import health_live, health_ready, router


class HealthRoutesTests(unittest.TestCase):
    def test_public_readiness_omits_internal_error_and_connection_details(self):
        app = FastAPI()
        app.state.startup_ready = False
        app.state.startup_components = {
            "mysql": {"ok": False, "detail": {"backend": "mysql-unavailable", "enabled": True, "error": "fixture-private", "database": "fixture-db"}},
            "auth": {"ok": False, "error": "fixture-private-path"},
            "agent_state_note": {"ok": True, "shared": False, "message": "fixture-internal"},
        }
        response = health_ready(Request({"type": "http", "app": app}))
        self.assertEqual(response.status_code, 503)
        body = json.loads(response.body)
        self.assertEqual(body["components"]["mysql"], {"ok": False, "enabled": True, "backend": "mysql-unavailable"})
        self.assertEqual(body["components"]["auth"], {"ok": False})
        self.assertEqual(body["components"]["agent_state_note"], {"ok": True, "shared": False})
        self.assertNotIn("fixture-", response.body.decode())
        self.assertIn("error", app.state.startup_components["auth"])

    def test_unexpected_storage_check_failure_is_controlled_not_ready(self):
        app = FastAPI()
        app.state.startup_ready = True
        request = Request({"type": "http", "app": app})
        with patch("backend.mysql_db.strict_storage_required", return_value=True), \
             patch("backend.mysql_db.mysql_ready", side_effect=RuntimeError("fixture-private")), \
             self.assertLogs("backend.health_routes", level="WARNING"):
            response = health_ready(request)
        self.assertEqual(response.status_code, 503)
        self.assertEqual(json.loads(response.body)["components"]["mysql"], {"ok": False, "backend": "mysql-unavailable"})
        self.assertNotIn("fixture-private", response.body.decode())
        self.assertEqual(health_live().status_code, 200)

    def test_strict_mysql_outage_and_recovery(self):
        from backend.mysql_db import StorageUnavailable
        app = FastAPI()
        app.state.startup_ready = True
        app.state.startup_components = {"mysql": {"ok": True}, "other": {"ok": True}}
        request = Request({"type": "http", "app": app})
        with patch("backend.mysql_db.strict_storage_required", return_value=True), \
             patch("backend.mysql_db.mysql_ready", side_effect=[StorageUnavailable("fixture"), True]):
            down = health_ready(request)
            self.assertEqual(down.status_code, 503)
            self.assertFalse(json.loads(down.body)["components"]["mysql"]["ok"])
            up = health_ready(request)
            self.assertEqual(up.status_code, 200)
            self.assertTrue(json.loads(up.body)["components"]["mysql"]["ok"])
            self.assertEqual(json.loads(up.body)["components"]["other"], {"ok": True})
        self.assertTrue(app.state.startup_components["mysql"]["ok"])

    def test_instance_state_is_independent(self):
        first = FastAPI()
        second = FastAPI()
        first.state.startup_ready = True
        first.state.startup_degraded = True
        second.state.startup_ready = False
        ready = health_ready(Request({"type": "http", "app": first}))
        unavailable = health_ready(Request({"type": "http", "app": second}))
        self.assertEqual(ready.status_code, 200)
        self.assertTrue(json.loads(ready.body)["degraded"])
        self.assertEqual(unavailable.status_code, 503)
        self.assertIn("no-store", unavailable.headers["cache-control"])
        self.assertEqual(health_live().status_code, 200)

    def test_router_mount(self):
        app = FastAPI()
        app.include_router(router)
        self.assertEqual(set(app.openapi()["paths"]), {"/health/live", "/health/ready"})
