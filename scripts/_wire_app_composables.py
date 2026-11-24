# -*- coding: utf-8 -*-
"""Wire App.vue to domain composables + buildPageContext (one-shot)."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "agent_admin" / "src" / "App.vue"
KEYS = (ROOT / "agent_admin" / "src" / "_page_context_keys.txt").read_text(encoding="utf-8").splitlines()

text = APP.read_text(encoding="utf-8")

# 1) Ensure imports after componentHealth import
needle = "import {\n  looksBadName, parseHashBag, ancestorChainFromTree, ancestorChainFromEvidence,\n} from './threatChainHelpers.js'"
insert = needle + """
import { buildPageContext } from './buildPageContext.js'
import { useHunt } from './composables/useHunt.js'
import { useAgentsFleet } from './composables/useAgentsFleet.js'
import { useThreatCases } from './composables/useThreatCases.js'
import { useResponseOps } from './composables/useResponseOps.js'
"""
if "buildPageContext" not in text:
    if needle not in text:
        raise SystemExit("threatChainHelpers import not found")
    text = text.replace(needle, insert, 1)

# 2) Replace pageContextBindings block with buildPageContext shorthand
m = re.search(
    r"const pageContextBindings = \{.*?\n\}\nconst pageContext = Object\.create\(null\)\n"
    r"for \(const key of Object\.keys\(pageContextBindings\)\) \{\n"
    r"  Object\.defineProperty\(pageContext, key, \{\n"
    r"    enumerable: true,\n"
    r"    get: \(\) => pageContextBindings\[key\],\n"
    r"    set: \(value\) => \{\n"
    r"      const binding = pageContextBindings\[key\]\n"
    r"      if \(isRef\(binding\)\) binding\.value = value\n"
    r"    \},\n"
    r"  \}\)\n"
    r"\}\n",
    text,
    flags=re.S,
)
if not m:
    raise SystemExit("pageContextBindings block not found")

shorthand = ",\n".join(f"  {k}" for k in KEYS)
replacement = (
    "const pageContext = buildPageContext({\n"
    f"{shorthand},\n"
    "})\n"
)
text = text[: m.start()] + replacement + text[m.end()]

APP.write_text(text, encoding="utf-8")
print("wired imports + pageContext; lines", len(text.splitlines()))
