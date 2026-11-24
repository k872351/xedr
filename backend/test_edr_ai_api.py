import unittest

from fastapi import FastAPI

from backend.edr_ai_api import router as ai_router
from backend.edr_api import router as main_router


class EdraiApiRouteTests(unittest.TestCase):
    def test_ai_routes_are_registered_and_mounted(self):
        expected = {
            ("/api/edr/ai/status", "GET"),
            ("/api/edr/ai/setup-local", "POST"),
            ("/api/edr/ai/config", "PUT"),
            ("/api/edr/ai/profiles/{profile_id}/activate", "POST"),
            ("/api/edr/ai/profiles/{profile_id}", "DELETE"),
            ("/api/edr/ai/test", "POST"),
            ("/api/edr/ai/skills", "GET"),
            ("/api/edr/ai/skills/{skill_id}", "GET"),
            ("/api/edr/ai/hosts", "GET"),
            ("/api/edr/ai/analyze-host", "POST"),
        }
        ai_routes = {
            (route.path, method)
            for route in ai_router.routes
            for method in getattr(route, "methods", set())
        }
        self.assertTrue(expected <= ai_routes, f"missing AI routes: {expected - ai_routes}")

        app = FastAPI()
        app.include_router(main_router)
        mounted = {
            (path, method.upper())
            for path, operations in app.openapi()["paths"].items()
            for method in operations
        }
        self.assertTrue(expected <= mounted, f"AI routes not mounted: {expected - mounted}")


if __name__ == "__main__":
    unittest.main()
