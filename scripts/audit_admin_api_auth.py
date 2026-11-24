#!/usr/bin/env python3
"""扫描管理端路由是否调用 _require_user / _require_admin（静态启发式）。

用法：
  python scripts/audit_admin_api_auth.py
  python scripts/audit_admin_api_auth.py --strict
"""
from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"

# Agent 凭据/注册等公开或凭据鉴权接口，不走管理端会话
ALLOW_UNAUTH_PREFIXES = (
    "/api/agent/register",
    "/api/agent/heartbeat",
    "/api/agent/events",
    "/api/agent/batch",
    "/api/agent/v2/events",
    "/api/agent/credential",
    "/api/agent/sync",
    "/api/agent/commands/ack",
    "/api/agent/commands/result",
    "/health",
    "/api/health",
    "/api/auth/login",
    "/api/auth/captcha",
    "/api/edr/auth/login",
    "/api/edr/auth/logout",
    "/api/edr/auth/captcha",
)

AUTH_CALL_NAMES = frozenset({
    "_require_user", "_require_admin", "_require_agent",
    "require_user", "require_admin",
    "_agent_auth", "_require_agent_or_user",
})


def _route_paths(decorator: ast.AST) -> list[str]:
    if not isinstance(decorator, ast.Call):
        return []
    func = decorator.func
    if isinstance(func, ast.Attribute) and func.attr in {"get", "post", "put", "patch", "delete"}:
        if decorator.args and isinstance(decorator.args[0], ast.Constant) and isinstance(decorator.args[0].value, str):
            return [decorator.args[0].value]
    return []


def _calls_require(node: ast.AST) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            f = child.func
            if isinstance(f, ast.Name) and f.id in AUTH_CALL_NAMES:
                return True
            if isinstance(f, ast.Attribute) and f.attr in AUTH_CALL_NAMES:
                return True
    return False


def _allowed(path: str) -> bool:
    p = path.split("{", 1)[0]
    return any(p.startswith(pref) or path.startswith(pref) for pref in ALLOW_UNAUTH_PREFIXES)


def audit_file(path: Path) -> list[dict]:
    src = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(src, filename=str(path))
    except SyntaxError as e:
        return [{"file": str(path), "error": str(e)}]
    findings = []
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        routes = []
        for dec in node.decorator_list:
            routes.extend(_route_paths(dec))
        if not routes:
            continue
        protected = _calls_require(node)
        for route in routes:
            if protected or _allowed(route):
                continue
            findings.append({
                "file": str(path.relative_to(ROOT)).replace("\\", "/"),
                "function": node.name,
                "route": route,
                "issue": "no _require_user/_require_admin call detected",
            })
    return findings


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--strict", action="store_true", help="有告警时退出码 1")
    args = ap.parse_args()
    files = sorted(BACKEND.glob("edr_*routes*.py")) + sorted(BACKEND.glob("edr_api.py"))
    files += sorted(BACKEND.glob("*_api.py"))
    seen = set()
    all_findings = []
    for f in files:
        if f in seen or not f.is_file():
            continue
        seen.add(f)
        all_findings.extend(audit_file(f))

    print(f"scanned {len(seen)} route modules")
    if not all_findings:
        print("OK: no unprotected admin-looking routes found by heuristic")
        return 0
    print(f"WARN: {len(all_findings)} potential gaps:")
    for it in all_findings:
        if "error" in it:
            print(f"  PARSE {it['file']}: {it['error']}")
        else:
            print(f"  {it['route']}  ({it['file']}::{it['function']})")
    return 1 if args.strict else 0


if __name__ == "__main__":
    sys.exit(main())
