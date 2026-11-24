import unittest

from backend.startup_health import readiness, storage_degraded


class StartupHealthTests(unittest.TestCase):
    def test_critical_failure(self):
        self.assertEqual(readiness(False, True), ({"status": "not_ready"}, 503))

    def test_optional_failure(self):
        self.assertEqual(readiness(True, True), ({"status": "ready", "degraded": True}, 200))

    def test_components_surface(self):
        body, code = readiness(True, True, components={"mysql": {"ok": False}})
        self.assertEqual(code, 200)
        self.assertTrue(body["degraded"])
        self.assertEqual(body["components"]["mysql"]["ok"], False)

    def test_intentional_sqlite(self):
        self.assertFalse(storage_degraded({"enabled": False, "ok": False}))

    def test_mysql_fallback(self):
        self.assertTrue(storage_degraded({"enabled": True, "ok": False}))
        self.assertFalse(storage_degraded({"enabled": True, "ok": True}))
