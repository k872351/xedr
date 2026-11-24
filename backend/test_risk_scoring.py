# -*- coding: utf-8 -*-
"""多信号风险评分单测：覆盖权重、衰减、战术宽度、重复、血缘传播、快照。"""
from __future__ import annotations

import time
import unittest

from . import risk_scoring as rs


class SeverityTest(unittest.TestCase):
    def test_thresholds(self):
        cases = {
            0: "info", 29: "info", 30: "low", 59: "low",
            60: "medium", 89: "medium", 90: "high", 129: "high",
            130: "critical", 500: "critical",
        }
        for score, want in cases.items():
            self.assertEqual(rs.severity_from_score(score), want, f"score={score}")

    def test_negative_score(self):
        self.assertEqual(rs.severity_from_score(-10), "info")


class ReportTest(unittest.TestCase):
    def setUp(self):
        rs.reset()
        self.agent = "agent-score-test"
        self.t0 = time.time()

    def tearDown(self):
        rs.reset()

    def _detail(self, pid=4242, ppid=100):
        return {"pid": pid, "ppid": ppid, "etype": "process_access", "path": "C:\\tmp\\x.exe"}

    def test_single_signal_uses_config_weight(self):
        d = self._detail()
        out = rs.report(self.agent, d, "lsass_access", now=self.t0)
        self.assertTrue(out["applied"])
        # lsass_access weight=48，落在 low 段（30≤48<60）
        self.assertEqual(out["delta"], 48)
        self.assertEqual(out["score"], 48)
        self.assertEqual(out["level"], "low")
        self.assertEqual(d["risk_score"], 48)
        self.assertEqual(d["risk_level"], "low")
        self.assertEqual(d["risk_breakdown"]["tactic"], "credential_access")

    def test_static_risk_score_is_floor(self):
        d = self._detail()
        d["risk_score"] = 95
        out = rs.report(self.agent, d, "default", now=self.t0)
        self.assertEqual(out["score"], 10)  # 内部累计分
        self.assertEqual(d["risk_score"], 95)  # 展示分不退步
        self.assertEqual(d["risk_level"], "high")

    def test_repeat_within_cooldown_diminishes(self):
        d = self._detail()
        rs.report(self.agent, d, "lsass_access", now=self.t0)
        out2 = rs.report(self.agent, self._detail(), "lsass_access", now=self.t0 + 5)
        # 第二次 divisor=2 → 48//2=24
        self.assertEqual(out2["delta"], 24)
        out3 = rs.report(self.agent, self._detail(), "lsass_access", now=self.t0 + 10)
        # 第三次 divisor=4 → 48//4=12，同技术第3次 +6 → 18
        self.assertEqual(out3["delta"], 18)

    def test_repeat_after_cooldown_resets(self):
        rs.report(self.agent, self._detail(), "lsass_access", now=self.t0)
        out2 = rs.report(self.agent, self._detail(), "lsass_access", now=self.t0 + 60)
        self.assertEqual(out2["delta"], 48)  # 权重重置

    def test_distinct_tactic_bonus(self):
        rs.report(self.agent, self._detail(), "lsass_access", now=self.t0)  # tactic #1
        # office_spawn 是新战术（execution），应带 +12*(2-1)
        out2 = rs.report(self.agent, self._detail(), "office_spawn", now=self.t0 + 1)
        self.assertEqual(out2["delta"], 28 + 12)
        self.assertEqual(out2["distinct_tactics"], 2)

    def test_same_tactic_no_bonus(self):
        rs.report(self.agent, self._detail(), "script_interpreter", now=self.t0)  # execution
        # office_spawn 同为 execution，无新战术奖励
        out2 = rs.report(self.agent, self._detail(), "office_spawn", now=self.t0 + 1)
        self.assertEqual(out2["delta"], 28)
        self.assertEqual(out2["distinct_tactics"], 1)

    def test_time_decay(self):
        rs.report(self.agent, self._detail(), "lsass_access", now=self.t0)
        # 90 秒后（3 个间隔 × 8 = 24），48 - 24 = 24
        out = rs.report(self.agent, self._detail(), "task_persist", now=self.t0 + 90)
        self.assertEqual(out["score"], 24 + 38 + 12)  # 衰减后叠加 task_persist(38)+新战术奖励(12)

    def test_decay_to_zero(self):
        rs.report(self.agent, self._detail(), "script_interpreter", now=self.t0)  # 12
        out = rs.report(self.agent, self._detail(), "script_interpreter", now=self.t0 + 300)
        # 300s → 10 间隔 × 8 = 80 > 12 → 衰减到 0；同信号冷却窗外权重重置=12
        self.assertEqual(out["score"], 12)

    def test_score_cap(self):
        for i in range(60):
            rs.report(self.agent, self._detail(), "lsass_access", now=self.t0 + i * 60)
        snap = rs.snapshot(self.agent, self._detail())
        self.assertLessEqual(snap["score"], 1000)

    def test_ancestry_propagation(self):
        # 先给父进程一些分，再让子进程命中以触发向上传播
        parent_detail = {"pid": 100}
        rs.report(self.agent, parent_detail, "task_persist", now=self.t0)
        child = self._detail(pid=4242, ppid=100)
        out = rs.report(self.agent, child, "lsass_access", now=self.t0 + 1)
        self.assertEqual(out["propagated"], 24)  # 48 * 50%
        parent_snap = rs.snapshot(self.agent, parent_detail)
        self.assertEqual(parent_snap["score"], 38 + 24)

    def test_unknown_signal_uses_default(self):
        d = self._detail()
        out = rs.report(self.agent, d, "no.such.signal", now=self.t0)
        self.assertEqual(out["delta"], 10)

    def test_custom_weight_override(self):
        d = self._detail()
        out = rs.report(self.agent, d, "lsass_access", weight=3, now=self.t0)
        self.assertEqual(out["delta"], 3)
        self.assertEqual(d["risk_score"], 3)


class SnapshotTest(unittest.TestCase):
    def setUp(self):
        rs.reset()
        self.agent = "agent-snap-test"
        self.t0 = time.time()

    def tearDown(self):
        rs.reset()

    def test_snapshot_empty(self):
        snap = rs.snapshot(self.agent, {"pid": 999})
        self.assertEqual(snap["score"], 0)
        self.assertEqual(snap["level"], "info")

    def test_host_snapshot_sorted(self):
        rs.report(self.agent, {"pid": 1}, "script_interpreter", now=self.t0)
        rs.report(self.agent, {"pid": 2}, "lsass_access", now=self.t0)
        host = rs.host_snapshot(self.agent)
        self.assertEqual(len(host), 2)
        self.assertGreaterEqual(host[0]["score"], host[1]["score"])

    def test_reset_clears_state(self):
        rs.report(self.agent, {"pid": 1}, "lsass_access", now=self.t0)
        rs.reset()
        self.assertEqual(rs.host_snapshot(self.agent), [])


if __name__ == "__main__":
    unittest.main()
