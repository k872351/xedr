"""Rule source metadata used by the console."""
from typing import Any, Dict


def is_elastic_rule(r: Dict[str, Any]) -> bool:
    """Elastic 导入规则（含误标为 custom 的旧数据）。"""
    if not isinstance(r, dict):
        return False
    if str(r.get("source") or "").strip().lower() == "elastic":
        return True
    rid = str(r.get("id") or "").strip().lower()
    if rid.startswith("elastic-"):
        return True
    if str(r.get("elastic_rule_id") or "").strip():
        return True
    note = str(r.get("note") or "").strip()
    return note.startswith("Elastic:") or note.startswith("Elastic EVM")


def _enrich_rule_item(r: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(r)
    if is_elastic_rule(out) and str(out.get("source") or "").lower() != "elastic":
        out["source"] = "elastic"
    return out


