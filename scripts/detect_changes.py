# -*- coding: utf-8 -*-
"""变更驱动的测试模块选择器（CI 按需测试）。

读取 .github/test_modules.json 的「路径 glob → 模块」映射，按本次变更文件
输出需要运行的模块矩阵。设计原则：

- **保守回退**：任何未匹配到模块的变更（或映射文件缺失/损坏）一律返回
  `plan=all`，退化为现有全量门禁，绝不因为选择器 bug 漏测。
- **tier 分级**：tier0=快速门（PR 必跑），tier1=全量门（push/main、规则或协议变更）。
- 纯函数 `select_modules()` 无副作用，方便单测；CLI 只做 I/O。

用法:
  python scripts/detect_changes.py --files backend/risk_scoring.py agent/slow_lane.go
  python scripts/detect_changes.py --stdin          # 每行一个变更文件
  python scripts/detect_changes.py --git-diff       # git diff --name-only HEAD~1
  python scripts/detect_changes.py --self-test      # 内置断言自检（CI 用）
  python scripts/detect_changes.py --files ... --json   # 输出 JSON 矩阵
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

ROOT = Path(__file__).resolve().parent.parent
MAPPING_PATH = ROOT / ".github" / "test_modules.json"

# 这些路径即使变更也不触发代码测试（纯文档/日志），但会被记录。
DOC_ONLY = re.compile(
    r"^(docs/|.*\.md$|\.workbuddy/|\.pytest_cache/|结果/|reports/)", re.I
)


def load_mapping(path: Optional[Path] = None) -> Dict[str, Any]:
    p = path or MAPPING_PATH
    try:
        doc = json.loads(Path(p).read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(doc, dict) or not isinstance(doc.get("modules"), list):
        return {}
    return doc


def _glob_to_regex(pattern: str) -> re.Pattern:
    """把路径 glob 转正则：支持 ** (跨目录) 与 * (单段)。

    逐字符扫描，不依赖 fnmatch.translate 的实现细节（各 Python 版本返回值不同）。
    """
    s = pattern.replace("\\", "/")
    out: List[str] = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == "*":
            if i + 1 < n and s[i + 1] == "*":
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        elif c == "[":
            j = s.find("]", i + 1)
            if j > i + 1:
                body = s[i + 1:j].replace("\\", "\\\\")
                out.append("[" + body + "]")
                i = j + 1
            else:
                out.append(re.escape(c))
                i += 1
        else:
            out.append(re.escape(c))
            i += 1
    return re.compile(r"^" + "".join(out) + r"$", re.I)


def path_matches(path: str, pattern: str) -> bool:
    p = str(path).replace("\\", "/").lstrip("./")
    pat = str(pattern).replace("\\", "/").lstrip("./")
    if not p or not pat:
        return False
    # 无斜杠的 pattern 只匹配文件名（避免 config/*.json 误伤深层文件）
    if "/" not in pat:
        return fnmatch.fnmatch(p.rsplit("/", 1)[-1], pat)
    if pat.endswith("/**"):
        prefix = pat[:-3]
        return p == prefix or p.startswith(prefix + "/")
    if _glob_to_regex(pat).match(p):
        return True
    return False


def select_modules(changed: Iterable[str], mapping: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """纯函数：按变更文件返回模块选择结果。

    返回 {
      plan: "targeted" | "all",
      reason: str,
      modules: [ {id, tier, paths, tests, runner, extra_commands, timeout_minutes, matched_by:[...]} ],
      doc_only_changes: [str],
      unmatched_changes: [str],
      tiers: [str]
    }
    """
    cfg = mapping if mapping is not None else load_mapping()
    files = [str(f).replace("\\", "/").lstrip("./") for f in changed if str(f).strip()]
    if not cfg:
        return {"plan": "all", "reason": "mapping_missing_or_invalid", "modules": [],
                "doc_only_changes": [], "unmatched_changes": files, "tiers": ["tier1"]}
    if not files:
        return {"plan": "all", "reason": "no_changed_files", "modules": [],
                "doc_only_changes": [], "unmatched_changes": [], "tiers": ["tier1"]}
    defaults = cfg.get("defaults") or {}
    on_unmatched = str(defaults.get("on_unmatched") or "all")
    mods: List[Dict[str, Any]] = []
    doc_only: List[str] = []
    unmatched: List[str] = []
    matched_files = set()

    for mod in cfg["modules"]:
        if not isinstance(mod, dict) or not mod.get("id"):
            continue
        pats = mod.get("paths") or []
        hits = [f for f in files if any(path_matches(f, pt) for pt in pats)]
        if not hits:
            continue
        matched_files.update(hits)
        entry = dict(mod)
        entry["matched_by"] = sorted(hits)[:20]
        mods.append(entry)

    for f in files:
        if DOC_ONLY.match(f):
            doc_only.append(f)
        elif f not in matched_files:
            unmatched.append(f)

    real_unmatched = [f for f in unmatched if not DOC_ONLY.match(f)]
    if real_unmatched and on_unmatched == "all":
        return {
            "plan": "all",
            "reason": f"unmatched_code_changes:{len(real_unmatched)}",
            "modules": [],
            "doc_only_changes": sorted(doc_only),
            "unmatched_changes": sorted(real_unmatched),
            "tiers": ["tier1"],
        }
    if not mods:
        # 只有文档变更 → 仍跑 tier0 快速门，不做全量
        return {"plan": "targeted", "reason": "doc_only_changes", "modules": [],
                "doc_only_changes": sorted(doc_only), "unmatched_changes": [],
                "tiers": ["tier0"]}
    tiers = sorted({str(m.get("tier") or defaults.get("tier") or "tier1") for m in mods})
    return {
        "plan": "targeted",
        "reason": f"matched:{','.join(sorted(m['id'] for m in mods))}",
        "modules": mods,
        "doc_only_changes": sorted(doc_only),
        "unmatched_changes": sorted(real_unmatched),
        "tiers": tiers,
    }


def _git_diff() -> List[str]:
    try:
        out = subprocess.check_output(
            ["git", "diff", "--name-only", "HEAD~1", "HEAD"],
            cwd=str(ROOT), stderr=subprocess.DEVNULL, text=True, timeout=30,
        )
        return [l.strip() for l in out.splitlines() if l.strip()]
    except Exception:
        return []


def _self_test() -> int:
    """内置断言自检：不依赖 git/外部文件，CI 可直接跑。"""
    cfg = load_mapping()
    assert cfg, "test_modules.json 应可加载且含 modules"
    assert len(cfg["modules"]) >= 8, "模块数不应缩水"
    for m in cfg["modules"]:
        assert m.get("id") and m.get("paths") and m.get("runner"), f"模块字段缺失: {m}"

    # glob 语义
    assert path_matches("backend/risk_scoring.py", "backend/risk_scoring.py")
    assert path_matches("backend/matchers/keywords.py", "backend/matchers/**")
    assert path_matches("config/correlation_rules.json", "config/*.json")
    assert not path_matches("rules/windows/a.json", "config/*.json")
    assert path_matches("agent_admin/src/App.vue", "agent_admin/src/**")
    assert not path_matches("backend/risk_scoring.py", "agent/**")

    # 定向选择
    r = select_modules(["backend/risk_scoring.py"], cfg)
    assert r["plan"] == "targeted", r
    ids = {m["id"] for m in r["modules"]}
    assert "backend-detection" in ids, ids

    # 多模块
    r2 = select_modules(["agent/slow_lane.go", "agent_admin/src/App.vue"], cfg)
    assert r2["plan"] == "targeted", r2
    assert {"agent-core", "web"} <= {m["id"] for m in r2["modules"]}, r2

    # 未匹配代码变更 → 全量回退（核心安全不变量）
    r3 = select_modules(["some/unknown/new_module.py"], cfg)
    assert r3["plan"] == "all" and r3["reason"].startswith("unmatched_code_changes"), r3

    # 纯文档 → 不做全量
    r4 = select_modules(["docs/架构决策记录.md"], cfg)
    assert r4["plan"] == "targeted" and r4["reason"] == "doc_only_changes", r4

    # 空输入 → 全量
    assert select_modules([], cfg)["plan"] == "all"
    # 坏映射 → 全量（不能漏测）
    assert select_modules(["backend/x.py"], {})["plan"] == "all"

    print("[detect_changes] self-test OK: %d modules, all invariants hold" % len(cfg["modules"]))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="变更驱动的测试模块选择器")
    ap.add_argument("--files", nargs="*", default=[], help="变更文件列表")
    ap.add_argument("--stdin", action="store_true", help="从 stdin 逐行读变更文件")
    ap.add_argument("--git-diff", action="store_true", help="用 git diff HEAD~1..HEAD")
    ap.add_argument("--json", action="store_true", help="输出 JSON 矩阵")
    ap.add_argument("--self-test", action="store_true", help="运行内置自检")
    args = ap.parse_args(argv)
    if args.self_test:
        return _self_test()
    files = list(args.files)
    if args.stdin:
        files += [l.strip() for l in sys.stdin.read().splitlines() if l.strip()]
    if args.git_diff:
        files += _git_diff()
    result = select_modules(files)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"plan={result['plan']} reason={result['reason']} tiers={','.join(result['tiers'])}")
        for m in result["modules"]:
            print(f"  - {m['id']} [{m.get('tier')}] <- {','.join(m['matched_by'][:3])}")
        if result["unmatched_changes"]:
            print(f"  ! unmatched: {','.join(result['unmatched_changes'][:5])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
