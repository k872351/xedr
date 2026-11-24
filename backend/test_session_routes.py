import unittest
import json
from unittest.mock import patch

from fastapi import FastAPI, HTTPException
from starlette.requests import Request
from starlette.responses import Response

from backend.edr_session_routes import router, _require_user, _require_admin, _set_cookie, edr_session, edr_users_list, edr_logout


class SessionRoutesTests(unittest.TestCase):
    def test_account_mutations_reject_ambiguous_field_types(self):
        from backend import edr_session_routes as routes
        request = self.request()
        actor = {'id': 'fixture-admin', 'role': 'admin', 'must_change': False}
        with patch.object(routes, '_require_admin', return_value=actor), \
             patch.object(routes.edr_auth, 'create_user') as create, \
             patch.object(routes.edr_auth, 'update_user') as update, \
             patch.object(routes.edr_auth, 'reset_password') as reset:
            for call in (
                lambda: routes.edr_users_create(request, {'must_change': 'false'}),
                lambda: routes.edr_users_update(actor['id'], request, {'enabled': 0}),
                lambda: routes.edr_users_update(actor['id'], request, {'role': []}),
                lambda: routes.edr_users_reset('fixture-account', request, {'password': 12345}),
            ):
                with self.assertRaises(HTTPException) as raised:
                    call()
                self.assertEqual(raised.exception.status_code, 422)
            create.assert_not_called()
            update.assert_not_called()
            reset.assert_not_called()

    def request(self, scheme="https"):
        return Request({"type": "http", "scheme": scheme, "headers": [(b"host", b"localhost")],
                        "client": ("127.0.0.1", 1234), "path": "/"})

    def test_account_routes(self):
        paths = {route.path for route in router.routes}
        self.assertIn("/api/edr/auth/session", paths)
        self.assertIn("/api/edr/users/{uid}", paths)

    def test_routes_mounted_by_main_router(self):
        from backend.edr_api import router as main_router
        app = FastAPI()
        app.include_router(main_router)
        paths = app.openapi()["paths"]
        self.assertIn("get", paths["/api/edr/auth/session"])
        self.assertIn("post", paths["/api/edr/auth/login"])

    def test_user_access(self):
        request = self.request()
        with patch("backend.edr_session_routes.edr_auth.me", return_value=None):
            with self.assertRaises(HTTPException) as raised:
                _require_user(request)
            self.assertEqual(raised.exception.status_code, 401)
        with patch("backend.edr_session_routes.edr_auth.me", return_value={"role": "analyst", "must_change": False}):
            with self.assertRaises(HTTPException) as raised:
                _require_admin(request)
            self.assertEqual(raised.exception.status_code, 403)

    def test_cookie_flags(self):
        response = Response()
        _set_cookie(response, self.request(), "test-session")
        cookie = response.headers["set-cookie"].lower()
        self.assertIn("httponly", cookie)
        self.assertIn("samesite=strict", cookie)
        self.assertIn("secure", cookie)

    def test_session_and_account_responses_are_not_cacheable(self):
        request = self.request()
        user = {'id': 'fixture', 'role': 'admin', 'must_change': False}
        with patch('backend.edr_session_routes.edr_auth.me', return_value=user), \
             patch('backend.edr_session_routes.edr_auth.list_users', return_value=[user]), \
             patch('backend.edr_session_routes.edr_auth.logout') as logout, \
             patch('backend.edr_session_routes._audit'):
            session = edr_session(request)
            accounts = edr_users_list(request)
            logged_out = edr_logout(request)
            for result in (session, accounts, logged_out):
                self.assertIn('no-store', result.headers['cache-control'])
                self.assertIn('private', result.headers['cache-control'])
                self.assertEqual(result.status_code, 200)
            self.assertEqual(json.loads(session.body)['user'], user)
            self.assertEqual(json.loads(accounts.body)['items'], [user])
            self.assertTrue(json.loads(logged_out.body)['ok'])
            logout.assert_called_once()

    def test_must_change_admin_cannot_access_account_list(self):
        request = self.request()
        with patch('backend.edr_session_routes.edr_auth.me', return_value={'role': 'admin', 'must_change': True}), \
             patch('backend.edr_session_routes.edr_auth.list_users') as listing:
            with self.assertRaises(HTTPException) as raised:
                edr_users_list(request)
            self.assertEqual(raised.exception.status_code, 403)
            listing.assert_not_called()
            self.assertEqual(edr_session(request).status_code, 200)

    def test_account_mutation_responses_are_not_cacheable(self):
        from backend import edr_session_routes as routes
        request = self.request()
        actor = {'id': 'fixture-admin', 'role': 'admin', 'must_change': False}
        account = {'id': 'fixture-account', 'username': 'fixture', 'role': 'analyst', 'enabled': True}
        with patch.object(routes, '_require_admin', return_value=actor), \
             patch.object(routes, '_audit'), \
             patch.object(routes.edr_auth, 'create_user', return_value=account), \
             patch.object(routes.edr_auth, 'update_user', return_value=account), \
             patch.object(routes.edr_auth, 'reset_password'), \
             patch.object(routes.edr_auth, 'delete_user'):
            responses = [routes.edr_users_create(request, {}), routes.edr_users_update('fixture-account', request, {}),
                         routes.edr_users_reset('fixture-account', request, {}), routes.edr_users_delete('fixture-account', request)]
            for response in responses:
                self.assertEqual(response.status_code, 200)
                self.assertIn('no-store', response.headers['cache-control'])
                self.assertIn('private', response.headers['cache-control'])
            self.assertEqual(json.loads(responses[0].body), account)
            self.assertEqual(json.loads(responses[3].body), {'ok': True})
