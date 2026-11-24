# -*- coding: utf-8 -*-
from backend.ioc_import_format import (
    normalize_lib_type, normalize_ioc_value, parse_ioc_import_line, detect_ioc_type,
)
from backend.ioc_db import sample_preview


def test_lib_type_map():
    assert normalize_lib_type("file_hash") == "hash"
    assert normalize_lib_type("IP") == "ip"
    assert normalize_lib_type("url") == "path"
    assert normalize_lib_type("name") == "process"


def test_ip_port_strip():
    assert normalize_ioc_value("ip", "121.36.3.54:62747") == "121.36.3.54"
    assert normalize_ioc_value("ip", "2001:db8::1") == "2001:db8::1"


def test_process_basename():
    assert normalize_ioc_value("process", r"C:\Temp\evil.exe") == "evil.exe"


def test_detect_auto():
    assert detect_ioc_type("evil.exe") == "process"
    assert detect_ioc_type("495c65f0dbff5d9e325c2f7b686d2411") == "hash"
    assert detect_ioc_type("1.2.3.4") == "ip"
    assert detect_ioc_type("bad.example.com") == "domain"
    assert detect_ioc_type("powershell -enc AAAA") == "cmdline"


def test_parse_plain_auto():
    t, v, note = parse_ioc_import_line("evil.exe", default_type="auto")
    assert t == "process" and v == "evil.exe" and note == ""


def test_parse_csv_like_lib():
    t, v, note = parse_ioc_import_line(
        "file_hash,495c65f0dbff5d9e325c2f7b686d2411,MalwareBazaar,elf",
        default_type="hash",
    )
    assert t == "hash"
    assert v.startswith("495c")
    assert "MalwareBazaar" in note and "elf" in note


def test_parse_type_colon():
    t, v, note = parse_ioc_import_line("domain:evil.example", default_type="hash")
    assert t == "domain"
    assert v == "evil.example"
    assert note == ""


def test_skip_header():
    assert parse_ioc_import_line("type,value,source,malware", default_type="hash") is None


def test_sample_preview_caps_at_100():
    out = sample_preview(40, offset=80)
    assert out.get("max_rows") == 100
    assert out.get("offset", 0) <= 99
    assert out.get("shown", 0) <= 20  # 80..99 → at most 20
    out2 = sample_preview(40, offset=200)
    assert out2.get("offset") <= 99
