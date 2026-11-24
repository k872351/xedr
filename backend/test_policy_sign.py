"""策略签名：与 Agent FA-POLICY-V1 消息格式对齐，并完成服务端签→验闭环。"""
from __future__ import annotations

import base64
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

from backend import policy_sign


class PolicySignTests(unittest.TestCase):
    def test_sign_message_golden(self):
        # 与 agent/policy_sign_test.go TestPolicySignMessageGolden 保持一致
        msg = policy_sign.policy_sign_message(1, {"heartbeat_sec": 30, "response_enabled": True})
        self.assertEqual(
            msg,
            b'FA-POLICY-V1\n1\n{"heartbeat_sec":30,"response_enabled":true}',
        )

    def test_float_normalized_like_go(self):
        msg = policy_sign.policy_sign_message(2, {"heartbeat_sec": 30.0, "response_enabled": True})
        self.assertEqual(
            msg,
            b'FA-POLICY-V1\n2\n{"heartbeat_sec":30,"response_enabled":true}',
        )

    def test_sign_verify_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            with patch.object(policy_sign, "_data_root", return_value=root):
                for k in ("EDR_POLICY_PRIV_PEM", "EDR_POLICY_PUB_B64"):
                    os.environ.pop(k, None)
                kp = policy_sign.ensure_policy_keypair()
                self.assertTrue(kp.get("ok"))
                body = {"response_enabled": True, "heartbeat_sec": 15, "fim_enabled": False}
                signed = policy_sign.attach_policy_signature(body, 7)
                self.assertIn("_sig", signed)
                pub = base64.b64decode(kp["pubkey"])
                pk = Ed25519PublicKey.from_public_bytes(pub)
                pk.verify(
                    base64.b64decode(signed["_sig"]),
                    policy_sign.policy_sign_message(7, body),
                )

    def test_sig_keys_excluded_from_message(self):
        a = policy_sign.policy_sign_message(1, {"a": 1, "_sig": "x", "sig_ed25519": "y"})
        b = policy_sign.policy_sign_message(1, {"a": 1})
        self.assertEqual(a, b)

    def test_attach_used_by_agent_side_bundle(self):
        from backend import agent_edr

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            with patch.object(policy_sign, "_data_root", return_value=root), \
                 patch.object(agent_edr, "get_policy", return_value={
                     "ok": True, "rev": 3,
                     "policy": {"response_enabled": True, "heartbeat_sec": 20},
                 }), \
                 patch.object(agent_edr, "poll_commands", return_value={"items": []}), \
                 patch.object(agent_edr, "list_whitelist", return_value={"items": []}), \
                 patch.object(agent_edr, "ensure"), \
                 patch.object(agent_edr, "_dp_crypto_for", return_value=None):
                out = agent_edr.agent_side_bundle("agent-test")
                self.assertTrue(out["policy"].get("_sig"))
                self.assertEqual(out["policy_rev"], 3)


if __name__ == "__main__":
    unittest.main()
