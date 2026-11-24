# -*- coding: utf-8 -*-
"""策略对账单测：漂移检测、异常状态识别、审计冷却。"""
import unittest

from backend import policy_reconcile as recon


class PolicyReconcileTests(unittest.TestCase):
    def _payload(self, status="applied", applied_rev=5, local_sync=10, error=""):
        return {
            "local_policy_rev": applied_rev,
            "local_sync_rev": local_sync,
            "policy_applied": status == "applied",
            "health": {"policy": {"status": status, "applied_rev": applied_rev, "error": error}},
        }

    def test_converged(self):
        r = recon.evaluate(self._payload(applied_rev=5), server_policy_rev=5,
                           server_sync_rev=10, policy_applied=True)
        self.assertEqual(r["state"], "converged")
        self.assertFalse(r["need_attention"])

    def test_behind_policy_rev(self):
        r = recon.evaluate(self._payload(applied_rev=3), server_policy_rev=5,
                           server_sync_rev=10, policy_applied=True)
        self.assertEqual(r["state"], "behind")
        self.assertIn("rev 3", r["reason"])

    def test_rejected_status_wins(self):
        r = recon.evaluate(self._payload(status="rejected", error="签名失败"),
                           server_policy_rev=5, server_sync_rev=10, policy_applied=False)
        self.assertEqual(r["state"], "rejected")
        self.assertTrue(r["need_attention"])
        self.assertIn("签名失败", r["reason"])

    def test_rolled_back(self):
        r = recon.evaluate(self._payload(status="rolled_back"),
                           server_policy_rev=5, server_sync_rev=10, policy_applied=False)
        self.assertEqual(r["state"], "rolled_back")
        self.assertTrue(r["need_attention"])

    def test_probation_not_attention(self):
        r = recon.evaluate(self._payload(status="probation"),
                           server_policy_rev=5, server_sync_rev=10, policy_applied=False)
        self.assertEqual(r["state"], "probation")
        self.assertFalse(r["need_attention"])

    def test_old_agent_no_health(self):
        r = recon.evaluate({"local_policy_rev": 0, "local_sync_rev": 0, "policy_applied": False},
                           server_policy_rev=5, server_sync_rev=10, policy_applied=False)
        self.assertEqual(r["state"], "unknown")

    def test_behind_sync_only(self):
        r = recon.evaluate(self._payload(applied_rev=5, local_sync=7),
                           server_policy_rev=5, server_sync_rev=10, policy_applied=True)
        self.assertEqual(r["state"], "behind")
        self.assertIn("同步版本", r["reason"])


if __name__ == "__main__":
    unittest.main()
