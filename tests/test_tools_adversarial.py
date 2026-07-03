"""Robustheit der Werkzeugschicht gegen fehlerhafte Tool-Calls.

Werkzeug-Argumente kommen von einem Sprachmodell. Ein fehlgeleitetes oder
manipuliertes Modell kann falsche Typen, fehlende Felder oder gar kein Objekt
liefern. Zwei fail-safe-Garantien müssen dann gelten und werden hier geprüft:

1. Kein ``run()`` wirft je eine ungefangene Ausnahme — es kommt immer ein
   ``ToolResult`` zurück (im Zweifel ``is_error=True``).
2. Ein fehlschlagendes Werkzeug bricht nie den gesamten Audit-Lauf ab: die
   ``SafeTool``-Hülle fängt jede Ausnahme ab und protokolliert sie.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from specter.audit import AuditLog
from specter.config import Config, Engagement
from specter.safety import SafetyPolicy
from specter.state import EngagementState
from specter.tools import build_registry
from specter.tools.base import SafeTool, ToolResult


def _registry(tmp_path: Path):
    allowed = tmp_path / "targets"
    allowed.mkdir(exist_ok=True)
    cfg = Config(
        engagement=Engagement("X", "Y", "R"), allowed_targets=["127.0.0.1"],
        forbidden_targets=[], allowed_paths=[allowed.resolve()],
        max_file_bytes=100_000, allowed_binaries=["curl", "nmap"],
        command_timeout=5, require_approval=False, max_iterations=5,
        model="claude-sonnet-5",
    )
    audit = AuditLog(tmp_path / "audit")
    return build_registry(cfg, SafetyPolicy(cfg), audit, EngagementState()), audit


# Müll-Argumente, die ein fehlgeleitetes LLM liefern könnte.
JUNK_DICTS = [
    {}, {"x": 1}, {"path": 5}, {"path": None}, {"command": 5}, {"command": None},
    {"data": None}, {"data": []}, {"findings": "x"}, {"title": 5},
    {"asset_type": None, "identifier": []}, {"scanner": 5, "target": None},
    {"file_path": 5}, {"content": None}, {"objective": 5},
]
NON_DICTS = [None, [], "string", 5, True, [{"x": 1}]]


def test_every_tool_returns_toolresult_on_junk_dicts(tmp_path):
    reg, _ = _registry(tmp_path)
    for name, tool in reg.items():
        for junk in JUNK_DICTS:
            result = tool.run(junk)
            assert isinstance(result, ToolResult), f"{name} -> {type(result)}"


def test_every_tool_survives_non_dict_arguments(tmp_path):
    """Kein Objekt (None/Liste/String) darf einen AttributeError auslösen."""
    reg, _ = _registry(tmp_path)
    for name, tool in reg.items():
        for junk in NON_DICTS:
            result = tool.run(junk)
            assert isinstance(result, ToolResult), f"{name}({junk!r})"


def test_registry_wraps_every_tool_in_safetool(tmp_path):
    reg, _ = _registry(tmp_path)
    assert reg  # nicht leer
    for name, tool in reg.items():
        assert isinstance(tool, SafeTool), name
        # Delegation der Metadaten funktioniert.
        assert tool.spec["name"] == name
        assert isinstance(tool.active, bool)
        assert tool.inner is not None


# ---- SafeTool isoliert Ausnahmen (deckt den Fehlerpfad ab) ----

class _ExplodingTool:
    name = "boom"
    active = False

    @property
    def spec(self):
        return {"name": self.name, "description": "", "input_schema": {}}

    def run(self, arguments):
        raise RuntimeError("absichtlicher Absturz")


def test_safetool_isolates_exceptions(tmp_path):
    audit = AuditLog(tmp_path / "audit")
    safe = SafeTool(_ExplodingTool(), audit)
    result = safe.run({"beliebig": "wert"})
    assert isinstance(result, ToolResult)
    assert result.is_error
    assert "boom" in result.content
    assert "RuntimeError" in result.content


def test_safetool_normalizes_non_dict_before_inner(tmp_path):
    """Ein Nicht-Dict wird zu {} normalisiert, bevor das innere Tool läuft."""
    seen = {}

    class _Recorder:
        name = "rec"
        active = False

        @property
        def spec(self):
            return {"name": self.name, "description": "", "input_schema": {}}

        def run(self, arguments):
            seen["args"] = arguments
            return ToolResult("ok")

    safe = SafeTool(_Recorder(), AuditLog(tmp_path / "a"))
    safe.run(None)
    assert seen["args"] == {}
    safe.run(["nicht", "dict"])
    assert seen["args"] == {}


def test_safetool_records_exception_in_audit(tmp_path):
    audit = AuditLog(tmp_path / "audit")
    SafeTool(_ExplodingTool(), audit).run({})
    log_text = (tmp_path / "audit").read_text() if (tmp_path / "audit").is_file() \
        else _read_audit_dir(tmp_path / "audit")
    assert "tool.exception" in log_text


def _read_audit_dir(path: Path) -> str:
    # AuditLog kann in eine Datei oder ein Verzeichnis schreiben — beides lesen.
    if path.is_dir():
        return "\n".join(p.read_text(encoding="utf-8", errors="ignore")
                         for p in path.rglob("*") if p.is_file())
    return path.read_text(encoding="utf-8", errors="ignore") if path.exists() else ""
