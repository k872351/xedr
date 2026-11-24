# -*- coding: utf-8 -*-
from backend.agent_rules import classify_rule_coverage, _rule_compilable, _rule_fields_complete


def test_compilable_regex_invalid():
    assert not _rule_compilable({
        "id": "r1", "title": "x", "modules": ["process"], "fields": ["path"],
        "patterns": ["(unclosed"], "match": "regex",
    })


def test_compilable_substring():
    assert _rule_compilable({
        "id": "r1", "title": "x", "modules": ["process"], "fields": ["path"],
        "patterns": ["evil.exe"], "match": "substring",
    })


def test_fields_complete():
    assert _rule_fields_complete({
        "id": "r1", "title": "t", "modules": ["process"], "fields": ["path"],
    })
    assert not _rule_fields_complete({"id": "r1", "modules": ["process"], "fields": ["path"]})


def test_classify_ladder_states():
    base = {
        "id": "rule-a", "title": "A", "modules": ["process"], "fields": ["path"],
        "patterns": ["x"], "match": "substring",
    }
    c = classify_rule_coverage(base, hit_ids=set())
    assert c["state"] == "fields_complete"
    c2 = classify_rule_coverage({**base, "replay_at": "2026-01-01"}, hit_ids=set())
    assert c2["state"] == "replayed"
    c3 = classify_rule_coverage(base, hit_ids={"rule-a"})
    assert c3["state"] == "production_hit"
    c4 = classify_rule_coverage({"id": "only", "title": "t"}, hit_ids=set())
    assert c4["state"] == "imported"
