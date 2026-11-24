import unittest
from unittest.mock import patch

from fastapi import HTTPException

from backend import edr_api


class ResponseApprovalRouteTests(unittest.TestCase):
    def call_as(self, role, payload):
        request = object()
        with patch.object(edr_api, "_require_user", return_value={"role": role, "username": role}), \
             patch.object(edr_api, "_actor", return_value=role), \
             patch("backend.response_approval.request_action", return_value={"ok": True, "status": "sent"}) as submit:
            result = edr_api.api_agent_command_create("agent-1", request, payload)
        return result, submit

    def test_admin_dispatches_without_approval(self):
        result, submit = self.call_as("admin", {"action": "kill_process", "params": {"pid": 42}})
        self.assertTrue(result["ok"])
        kwargs = submit.call_args.kwargs
        self.assertTrue(kwargs["skip_approval"])
        self.assertEqual(kwargs["actor_role"], "admin")

    def test_analyst_is_submitted_for_approval(self):
        result, submit = self.call_as("analyst", {"action": "kill_process", "params": {"pid": 42}})
        self.assertTrue(result["ok"])
        kwargs = submit.call_args.kwargs
        self.assertFalse(kwargs["skip_approval"])
        self.assertEqual(kwargs["actor_role"], "analyst")

    def test_analyst_cannot_force_skip_approval(self):
        with self.assertRaises(HTTPException) as raised:
            self.call_as("analyst", {"action": "kill_process", "force": True})
        self.assertEqual(raised.exception.status_code, 403)


if __name__ == "__main__":
    unittest.main()
