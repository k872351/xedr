# -*- coding: utf-8 -*-
"""CHANGELOG 强制门禁（借鉴 wazuh changelog-enforcer）。

规则：非 draft PR 若改动了「代码/配置/规则资产」，必须同时改动
CHANGELOG.md，或带 `no-changelog` / `skip-changelog` 标签。
纯文档改动（docs/**、*.md、AGENTS.md 等）豁免。

设计：
- 纯函数 `evaluate()` 无副作用，便于单测与自检。
- CLI 从 --files / --stdin / --git-diff 取变更，从 --labels 取标签。
- 不依赖 GitHub API；由 workflow 通过 env 传入 labels（见 quality.yml 说明）。
- 返回码 0=通过，1=未通过（CI 可据此 fail）。

用法:
  python scripts/check_changelog.py --files backend/x.py --labels ""        # FAIL(1)
  python scripts/check_changelog.py --files backend/x.py CHANGELOG.md       # OK(0)
  python scripts/check_changelog.py --files backend/x.py --labels no-changelog  # OK(0)
  python scripts/check_changelog.py --self-test                             # 内置断言
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional

ROOT = Path(__file__).resolve().parent.parent

EXEMPT_LABELS = frozenset({"no-changelog", "skip-changelog", "dependencies"})

# 纯文档/仓库元数据：改动这些不需要 CHANGELOG
DOC_PATTERNS = (
    "docs/**", "*.md", "AGENTS.md", ".github/pull_request_template.md",
    ".workbuddy/**", ".pytest_cache/**", "结果/**", "reports/**",
)
# 明确属于「代码/配置/资产」、需要 CHANGELOG 的路径
CODE_PATTERNS = (
    "backend/**", "agent/**", "agent_admin/**", "scripts/**",
    "rules/**", "config/**", "tests/**", "baselines/**", "log_rules/**",
    "edr_server.py", ".github/workflows/**", ".github/test_modules.json",
    "requirements.txt", "VERSION.json", "CONTRIBUTING.md", "SECURITY.md",
)


def _matches(path: str, pattern: str) -> bool:
    p = str(path).replace("\\", "/").lstrip("./")
    pat = pattern.replace("\\", "/").lstrip("./")
    if pat.endswith("/**"):
        prefix = pat[:-3]
        return p == prefix or p.startswith(prefix + "/")
    if "/" in pat:
        return fnmatch.fnmatch(p, pat) or p.startswith(pat.rstrip("*"))
    return fnmatch.fnmatch(p.rsplit("/", 1)[-1], pat)


def _any_match(path: str, patterns: Iterable[str]) -> bool:
    return any(_matches(path, pt) for pt in patterns)


def evaluate(changed: Iterable[str], labels: Iterable[str] = (),
             *, draft: bool = False) -> Dict[str, object]:
    """纯函数：判定 CHANGELOG 门禁是否通过。"""
    files = [str(f).replace("\\", "/").lstrip("./") for f in changed if str(f).strip()]
    label_set = {str(l).strip().lower() for l in labels if str(l).strip()}
    if draft:
        return {"ok": True, "reason": "draft_pr_exempt", "code_changes": [], "labels": sorted(label_set)}
    if label_set & EXEMPT_LABELS:
        return {"ok": True, "reason": "exempt_label", "code_changes": [], "labels": sorted(label_set)}
    if any(f.lower() == "changelog.md" for f in files):
        return {"ok": True, "reason": "changelog_updated", "code_changes": [], "labels": sorted(label_set)}

    code_changes = [
        f for f in files
        if _any_match(f, CODE_PATTERNS) and not _any_match(f, DOC_PATTERNS)
    ]
    if not code_changes:
        return {"ok": True, "reason": "no_code_changes", "code_changes": [], "labels": sorted(label_set)}
    return {"ok": False, "reason": "code_changed_without_changelog",
            "code_changes": sorted(code_changes)[:20], "labels": sorted(label_set)}


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
    assert evaluate(["backend/x.py"])["ok"] is False, "纯代码变更必须要求 CHANGELOG"
    assert evaluate(["backend/x.py", "CHANGELOG.md"])["ok"] is True, "改了 CHANGELOG 应通过"
    assert evaluate(["backend/x.py"], ["no-changelog"])["ok"] is True, "豁免标签应通过"
    assert evaluate(["backend/x.py"], ["dependencies"])["ok"] is True
    assert evaluate(["backend/x.py"], draft=True)["ok"] is True, "draft 应豁免"
    assert evaluate(["docs/架构决策记录.md"])["ok"] is True, "纯文档应豁免"
    assert evaluate(["README.md"])["ok"] is True
    assert evaluate(["AGENTS.md"])["ok"] is True
    assert evaluate([])["ok"] is True, "空变更应通过"
    assert evaluate([".github/workflows/quality.yml"])["ok"] is False, "CI 变更也要 CHANGELOG"
    assert _matches("backend/a/b.py", "backend/**")
    assert _matches("agent_admin/src/App.vue", "agent_admin/**")
    assert not _matches("docs/a.md", "backend/**")
    print("[check_changelog] self-test OK")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="CHANGELOG 强制门禁")
    ap.add_argument("--files", nargs="*", default=[])
    ap.add_argument("--stdin", action="store_true")
    ap.add_argument("--git-diff", action="store_true")
    ap.add_argument("--labels", default="", help="逗号分隔的 PR 标签")
    ap.add_argument("--draft", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return _self_test()
    files = list(args.files)
    if args.stdin:
        files += [l.strip() for l in sys.stdin.read().splitlines() if l.strip()]
    if args.git_diff:
        files += _git_diff()
    labels = [x.strip() for x in args.labels.split(",") if x.strip()]
    result = evaluate(files, labels, draft=args.draft)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"changelog_gate={'PASS' if result['ok'] else 'FAIL'} reason={result['reason']}")
        if not result["ok"]:
            print("  代码变更未同步 CHANGELOG.md，请更新或加 no-changelog 标签：")
            for f in result["code_changes"]:  # type: ignore[index]
                print(f"    - {f}")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
