import unittest
from unittest.mock import patch

from fastapi import HTTPException
from fastapi import FastAPI
from starlette.requests import Request
from backend import agent_release_api as api


class ReleaseDownloadGuardTests(unittest.TestCase):
    def test_download_routes_reject_unprivileged_requests_before_packaging(self):
        app = FastAPI()
        app.include_router(api.router)
        self.assertIn('/api/agent/install-package', app.openapi()['paths'])
        self.assertIn('/api/agent/linux-package', app.openapi()['paths'])
        request = Request({'type': 'http', 'headers': []})
        for user, status in ((None, 401), ({'role': 'viewer'}, 403)):
            with self.subTest(status=status), patch('backend.edr_auth.me', return_value=user), \
                 patch('backend.agent_package_builder.build_install_package') as windows_builder, \
                 patch('backend.agent_linux_package.build_linux_package') as linux_builder:
                for endpoint in (api.api_agent_install_package, api.api_agent_linux_package):
                    with self.assertRaises(HTTPException) as caught:
                        endpoint(request)
                    self.assertEqual(caught.exception.status_code, status)
                windows_builder.assert_not_called()
                linux_builder.assert_not_called()

    def test_missing_architecture_is_rejected_before_packaging(self):
        request = Request({'type': 'http', 'headers': []})
        with patch.object(api, '_require_admin', return_value={}), \
             patch('backend.agent_release.release_status', return_value={'status': 'missing', 'integrity_verified': False}), \
             patch('backend.agent_package_builder.build_install_package') as builder:
            with self.assertRaises(HTTPException) as caught:
                api.api_agent_install_package(request, require_latest=False, arch='arm64')
            self.assertEqual(caught.exception.status_code, 409)
            builder.assert_not_called()

    def test_unverified_or_mismatched_release_is_never_packaged(self):
        request = Request({'type': 'http', 'headers': []})
        for status in ('mismatch', 'missing', 'unverified', 'stale'):
            with self.subTest(status=status), patch.object(api, '_require_admin', return_value={}), \
                 patch('backend.agent_release.release_status', return_value={'status': status, 'integrity_verified': False}), \
                 patch('backend.agent_package_builder.build_install_package') as builder:
                with self.assertRaises(HTTPException) as caught:
                    api.api_agent_install_package(request, require_latest=False, arch='amd64')
                self.assertEqual(caught.exception.status_code, 409)
                builder.assert_not_called()

    def test_verified_stale_requires_explicit_choice(self):
        request = Request({'type': 'http', 'headers': []})
        with patch.object(api, '_require_admin', return_value={}), \
             patch('backend.agent_release.release_status', return_value={'status': 'stale', 'integrity_verified': True, 'is_latest': False}), \
             patch('backend.agent_package_builder.build_install_package') as builder:
            with self.assertRaises(HTTPException) as caught:
                api.api_agent_install_package(request, require_latest=True, arch='amd64')
            self.assertEqual(caught.exception.status_code, 409)
            builder.assert_not_called()

    def test_contradictory_release_metadata_is_rejected_even_with_stale_choice(self):
        request = Request({'type': 'http', 'headers': []})
        for status, flag in (('latest', False), ('stale', True), ('latest', None)):
            with self.subTest(status=status, flag=flag), patch.object(api, '_require_admin', return_value={}), \
                 patch('backend.agent_release.release_status', return_value={'status': status, 'integrity_verified': True, 'is_latest': flag}), \
                 patch('backend.agent_package_builder.build_install_package') as builder:
                with self.assertRaises(HTTPException) as caught:
                    api.api_agent_install_package(request, require_latest=False, arch='amd64')
                self.assertEqual(caught.exception.status_code, 409)
                builder.assert_not_called()
