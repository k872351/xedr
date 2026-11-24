import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch
from fastapi import HTTPException
from starlette.requests import Request
from backend import edr_api, agent_diagnostics


class DiagnosticAccessTests(unittest.TestCase):
    def test_download_requires_admin_before_metadata_access(self):
        request = Request({'type': 'http', 'headers': []})
        for user, status in ((None, 401), ({'role': 'viewer'}, 403)):
            with patch('backend.edr_auth.me', return_value=user), patch.object(agent_diagnostics, 'get_command_result_meta') as meta:
                with self.assertRaises(HTTPException) as caught:
                    edr_api.api_agent_diagnostics_download('fixture-agent', 'fixture-command', request)
                self.assertEqual(caught.exception.status_code, status)
                meta.assert_not_called()

    def test_download_requires_completed_matching_diagnostic(self):
        request = Request({'type': 'http', 'headers': []})
        cases = [({'ok': False, 'error': '指令不属于该终端'}, 403),
                 ({'ok': True, 'action': 'other', 'status': 'done'}, 400),
                 ({'ok': True, 'action': 'collect_diagnostics', 'status': 'pending'}, 409)]
        for meta, status in cases:
            with patch('backend.edr_auth.me', return_value={'role': 'admin'}), patch.object(agent_diagnostics, 'get_command_result_meta', return_value=meta), patch.object(agent_diagnostics, 'read_download_bytes') as read:
                with self.assertRaises(HTTPException) as caught:
                    edr_api.api_agent_diagnostics_download('fixture-agent', 'fixture-command', request)
                self.assertEqual(caught.exception.status_code, status)
                read.assert_not_called()

    def test_history_skips_unreadable_entry_and_non_files(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as tmp:
            root = Path(tmp)
            folder = root / 'fixture-agent'
            folder.mkdir()
            good = folder / 'fixture-command_good.zip'
            good.write_bytes(b'x' * 40)
            removed = folder / 'fixture-command_removed.zip'
            removed.write_bytes(b'x' * 40)
            (folder / 'fixture-command_directory').mkdir()
            original_lstat = Path.lstat
            def lstat(path):
                if path == removed:
                    raise FileNotFoundError('synthetic concurrent removal')
                return original_lstat(path)
            with patch.object(agent_diagnostics, '_root', return_value=root), patch('backend.agent_edr.ensure'), patch.object(Path, 'lstat', lstat):
                self.assertEqual(agent_diagnostics.resolve_download_path('fixture-agent', 'fixture-command'), good)
                result = agent_diagnostics.list_diagnostics('fixture-agent')
                self.assertEqual(result['total'], 1)
                self.assertEqual(result['items'][0]['filename'], 'good.zip')

    def test_diagnostic_receipt_checks_owner_before_storage(self):
        from backend import agent_edr, agent_commands
        from unittest.mock import Mock
        conn = Mock()
        conn.execute.return_value.fetchone.return_value = {'agent_id': 'fixture-owner', 'action': 'collect_diagnostics'}
        with patch.object(agent_commands, 'ensure'), patch.object(agent_commands, '_connect', return_value=conn), \
             patch.object(agent_diagnostics, 'persist_from_command_result') as persist:
            result = agent_commands.ack_command('fixture-command', ok=True, result={}, caller_agent_id='fixture-other')
            self.assertFalse(result['ok'])
            self.assertTrue(result['forbidden'])
            persist.assert_not_called()

    def test_anonymous_and_nonadmin_rejected_before_listing(self):
        request = Request({'type': 'http', 'headers': []})
        for user, status in ((None, 401), ({'role': 'viewer'}, 403)):
            with patch('backend.edr_auth.me', return_value=user), patch.object(agent_diagnostics, 'list_diagnostics') as listing:
                with self.assertRaises(HTTPException) as caught:
                    edr_api.api_agent_diagnostics_list(request)
                self.assertEqual(caught.exception.status_code, status)
                listing.assert_not_called()

    def test_invalid_identifier_rejected(self):
        request = Request({'type': 'http', 'headers': []})
        with patch('backend.edr_auth.me', return_value={'role': 'admin'}), patch.object(agent_diagnostics, 'list_diagnostics') as listing:
            with self.assertRaises(HTTPException) as caught:
                edr_api.api_agent_diagnostics_list(request, agent_id='invalid identifier')
            self.assertEqual(caught.exception.status_code, 400)
            listing.assert_not_called()
