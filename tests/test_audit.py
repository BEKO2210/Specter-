"""Tests für das Audit-Log."""

from __future__ import annotations

import json

from specter.audit import AuditLog


def test_audit_writes_jsonl(tmp_path):
    audit = AuditLog(tmp_path / "audit")
    audit.record("test_event", foo="bar", n=3)
    audit.record("zweites", ok=True)
    assert audit.path.exists()
    lines = audit.path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["event"] == "test_event"
    assert first["foo"] == "bar"
    assert first["n"] == 3
    assert "ts" in first


def test_audit_creates_directory(tmp_path):
    target = tmp_path / "neu" / "verschachtelt"
    audit = AuditLog(target)
    assert target.exists()
    audit.record("x")
    assert audit.path.parent == target


def test_audit_serializes_non_json_default(tmp_path):
    audit = AuditLog(tmp_path / "audit")
    from pathlib import Path
    audit.record("pfad", p=Path("/tmp/x"))  # Path ist nicht nativ JSON-faehig
    line = json.loads(audit.path.read_text(encoding="utf-8").strip())
    assert line["p"] == "/tmp/x"
