"""Tests fuer den Re-Test-/Delta-Modus."""

from __future__ import annotations

import datetime as _dt
import json

from specter.assets import AssetGraph
from specter.audit import AuditLog
from specter.config import Config, Engagement
from specter.findings import Finding, FindingsStore
from specter.report import build_json, build_markdown
from specter.retest import DeltaResult, compute_delta
from specter.safety import SafetyPolicy
from specter.state import EngagementState
from specter.tools.retest import RetestTool


def _cfg(tmp_path, **ov) -> Config:
    allowed = tmp_path / "targets"
    allowed.mkdir(exist_ok=True)
    d = dict(
        engagement=Engagement("Muster GmbH", "GF", "REF-1"),
        allowed_targets=["127.0.0.1"], forbidden_targets=[],
        allowed_paths=[allowed.resolve()], max_file_bytes=100_000,
        allowed_binaries=["curl"], command_timeout=5, require_approval=False,
        max_iterations=5, model="claude-sonnet-5",
    )
    d.update(ov)
    return Config(**d)


def _store(*findings) -> FindingsStore:
    s = FindingsStore()
    for f in findings:
        s.add(f)
    return s


# ------------------------------ compute_delta -----------------------------

def test_delta_resolved_new_still_open():
    old = Finding("Altes SQLi", "injection", "hoch", "api", location="a.py:1")
    common = Finding("Offenes Secret", "secret_exposure", "hoch", "app", location="c:1")
    previous = {
        "generated_at": "2026-06-01 10:00",
        "findings": [old.to_dict(), common.to_dict()],
    }
    current = _store(
        common,  # weiterhin offen
        Finding("Neu: RDP offen", "remote_access", "hoch", "host", location="h:3389"),
    )
    delta = compute_delta(previous, current, today=_dt.date(2026, 7, 1))
    assert len(delta.resolved) == 1 and delta.resolved[0]["title"] == "Altes SQLi"
    assert len(delta.new) == 1 and "RDP" in delta.new[0].title
    assert len(delta.still_open) == 1 and delta.still_open[0].id == common.id
    assert delta.aging_days == 30


def test_delta_no_previous_findings():
    delta = compute_delta({"generated_at": "2026-06-01 10:00"}, _store(
        Finding("x", "injection", "hoch", "a")))
    assert len(delta.new) == 1 and delta.resolved == []


def test_delta_invalid_previous():
    delta = compute_delta("kein dict", _store())
    assert delta.resolved == [] and delta.new == []


def test_delta_bad_date_no_aging():
    delta = compute_delta({"generated_at": "kaputt", "findings": []}, _store())
    assert delta.aging_days is None


def test_delta_missing_date():
    delta = compute_delta({"findings": []}, _store())
    assert delta.aging_days is None and delta.previous_date == ""


def test_delta_to_dict():
    common = Finding("A", "injection", "hoch", "x", location="a:1")
    previous = {"generated_at": "2026-06-20 09:00", "findings": [common.to_dict()]}
    delta = compute_delta(previous, _store(common), today=_dt.date(2026, 7, 1))
    d = delta.to_dict()
    assert d["counts"] == {"resolved": 0, "new": 0, "still_open": 1}
    assert d["aging_days"] == 11


# ------------------------------- Report -----------------------------------

def test_delta_section_in_markdown():
    old = Finding("Behobenes Problem", "misconfiguration", "mittel", "srv")
    previous = {"generated_at": "2026-06-01 10:00", "findings": [old.to_dict()]}
    current = _store(Finding("Neues Problem", "injection", "hoch", "api"))
    delta = compute_delta(previous, current, today=_dt.date(2026, 7, 1))
    md = build_markdown(_cfg_dummy(), AssetGraph(), current, [], delta=delta)
    assert "Re-Test / Veraenderung" in md
    assert "Behobenes Problem" in md
    assert "Neues Problem" in md


def test_delta_absent_no_section():
    md = build_markdown(_cfg_dummy(), AssetGraph(), _store(), [])
    assert "## Re-Test / Veraenderung" not in md


def test_delta_in_json():
    old = Finding("x", "injection", "hoch", "a", location="a:1")
    previous = {"generated_at": "2026-06-01 10:00", "findings": [old.to_dict()]}
    delta = compute_delta(previous, _store(), today=_dt.date(2026, 7, 1))
    data = build_json(_cfg_dummy(), AssetGraph(), _store(), [], delta=delta)
    assert data["retest"]["counts"]["resolved"] == 1
    # Ohne Delta ist der Schluessel None.
    assert build_json(_cfg_dummy(), AssetGraph(), _store(), [])["retest"] is None


def _cfg_dummy() -> Config:
    from pathlib import Path
    return Config(
        engagement=Engagement("X", "Y", "R"), allowed_targets=[], forbidden_targets=[],
        allowed_paths=[Path("/x")], max_file_bytes=1000, allowed_binaries=[],
        command_timeout=5, require_approval=False, max_iterations=5,
        model="claude-sonnet-5",
    )


# --------------------------------- Tool -----------------------------------

def _tool(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    state.findings.add(Finding("Bleibt", "injection", "hoch", "api", location="a:1"))
    return RetestTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state), state, cfg


def _write_prev(tmp_path, obj) -> str:
    p = tmp_path / "targets" / "alt.json"
    p.write_text(json.dumps(obj), encoding="utf-8")
    return str(p)


def test_retest_tool_success(tmp_path):
    tool, state, _ = _tool(tmp_path)
    bleibt = state.findings.all()[0]
    prev = {"generated_at": "2026-06-01 10:00", "findings": [
        bleibt.to_dict(),
        Finding("Weg", "misconfiguration", "niedrig", "x").to_dict()]}
    path = _write_prev(tmp_path, prev)
    r = tool.run({"previous_report": path})
    assert not r.is_error and "Re-Test" in r.content
    assert state.delta is not None
    assert len(state.delta.resolved) == 1 and len(state.delta.still_open) == 1


def test_retest_tool_scope_denied(tmp_path):
    tool, _, _ = _tool(tmp_path)
    r = tool.run({"previous_report": "/etc/passwd"})
    assert r.is_error and "VERWEIGERT" in r.content


def test_retest_tool_missing_file(tmp_path):
    tool, _, _ = _tool(tmp_path)
    r = tool.run({"previous_report": str(tmp_path / "targets" / "weg.json")})
    assert r.is_error and "existiert nicht" in r.content


def test_retest_tool_invalid_json(tmp_path):
    tool, _, _ = _tool(tmp_path)
    p = tmp_path / "targets" / "bad.json"
    p.write_text("<nope>", encoding="utf-8")
    r = tool.run({"previous_report": str(p)})
    assert r.is_error and "JSON" in r.content


def test_retest_tool_too_large(tmp_path):
    tool, _, cfg = _tool(tmp_path)
    cfg.max_file_bytes = 5
    path = _write_prev(tmp_path, {"findings": [{"id": "x" * 50}]})
    r = tool.run({"previous_report": path})
    assert r.is_error and "zu gross" in r.content


def test_deltaresult_defaults():
    d = DeltaResult()
    assert d.resolved == [] and d.new == [] and d.still_open == []
    assert d.aging_days is None
