"""Tests fuer die neuen Werkzeuge: analyze_ad, analyze_exchange, run_scanner."""

from __future__ import annotations

import json
import subprocess
from unittest.mock import patch

import pytest

from specter.audit import AuditLog
from specter.config import Config, Engagement, ScannerPolicy
from specter.safety import SafetyPolicy
from specter.state import EngagementState
from specter.tools.analyze_ad import AnalyzeAdTool
from specter.tools.analyze_exchange import AnalyzeExchangeTool
from specter.tools.run_scanner import RunScannerTool


def _cfg(tmp_path, **ov) -> Config:
    allowed = tmp_path / "targets"
    allowed.mkdir(exist_ok=True)
    d = dict(
        engagement=Engagement("X", "Y", "R"),
        allowed_targets=["127.0.0.1", "10.10.0.0/16"], forbidden_targets=[],
        allowed_paths=[allowed.resolve()], max_file_bytes=100_000,
        allowed_binaries=["curl"], command_timeout=10, require_approval=False,
        max_iterations=5, model="claude-sonnet-5",
    )
    d.update(ov)
    return Config(**d)


def _write_json(tmp_path, name, obj) -> str:
    p = tmp_path / "targets" / name
    p.write_text(json.dumps(obj), encoding="utf-8")
    return str(p)


# ------------------------------- analyze_ad -------------------------------

def _ad_tool(cfg, tmp_path):
    state = EngagementState()
    return AnalyzeAdTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state), state


def test_analyze_ad_success(tmp_path):
    cfg = _cfg(tmp_path)
    tool, state = _ad_tool(cfg, tmp_path)
    path = _write_json(tmp_path, "ad.json", {
        "domain": "corp.de",
        "password_policy": {"min_length": 6, "complexity": False, "lockout_threshold": 0},
        "users": [{"name": "svc", "enabled": True, "kerberos_preauth": False}]})
    r = tool.run({"path": path})
    assert not r.is_error and "AD-Analyse" in r.content
    assert len(state.findings) >= 3


def test_analyze_ad_scope_denied(tmp_path):
    cfg = _cfg(tmp_path)
    tool, _ = _ad_tool(cfg, tmp_path)
    r = tool.run({"path": "/etc/passwd"})
    assert r.is_error and "VERWEIGERT" in r.content


def test_analyze_ad_missing_file(tmp_path):
    cfg = _cfg(tmp_path)
    tool, _ = _ad_tool(cfg, tmp_path)
    r = tool.run({"path": str(tmp_path / "targets" / "fehlt.json")})
    assert r.is_error and "existiert nicht" in r.content


def test_analyze_ad_invalid_json(tmp_path):
    cfg = _cfg(tmp_path)
    tool, _ = _ad_tool(cfg, tmp_path)
    p = tmp_path / "targets" / "kaputt.json"
    p.write_text("{nicht: valides json", encoding="utf-8")
    r = tool.run({"path": str(p)})
    assert r.is_error and "JSON" in r.content


def test_analyze_ad_too_large(tmp_path):
    cfg = _cfg(tmp_path, max_file_bytes=10)
    tool, _ = _ad_tool(cfg, tmp_path)
    path = _write_json(tmp_path, "big.json", {"domain": "x" * 100})
    r = tool.run({"path": path})
    assert r.is_error and "zu gross" in r.content


def test_analyze_ad_no_findings(tmp_path):
    cfg = _cfg(tmp_path)
    tool, state = _ad_tool(cfg, tmp_path)
    path = _write_json(tmp_path, "clean.json", {"domain": "corp.de"})
    r = tool.run({"path": path})
    assert not r.is_error and "ohne Befunde" in r.content
    assert len(state.findings) == 0


# ---------------------------- analyze_exchange ----------------------------

def test_analyze_exchange_success(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeExchangeTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "ex.json", {
        "host": "mail.de", "build": "15.1.2000.1",
        "external_services": ["ECP"], "tls": {"protocols": ["TLSv1.0"]}})
    r = tool.run({"path": path})
    assert not r.is_error and "Exchange-Analyse" in r.content
    assert len(state.findings) >= 3


def test_analyze_exchange_scope_denied(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeExchangeTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    r = tool.run({"path": "/etc/hosts"})
    assert r.is_error and "VERWEIGERT" in r.content


def test_analyze_exchange_missing_file(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeExchangeTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    r = tool.run({"path": str(tmp_path / "targets" / "weg.json")})
    assert r.is_error and "existiert nicht" in r.content


def test_analyze_exchange_invalid_json(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeExchangeTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    p = tmp_path / "targets" / "bad.json"
    p.write_text("<<<nope>>>", encoding="utf-8")
    r = tool.run({"path": str(p)})
    assert r.is_error and "JSON" in r.content


def test_analyze_exchange_too_large(tmp_path):
    cfg = _cfg(tmp_path, max_file_bytes=5)
    state = EngagementState()
    tool = AnalyzeExchangeTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "big.json", {"host": "x" * 50})
    r = tool.run({"path": path})
    assert r.is_error and "zu gross" in r.content


def test_analyze_exchange_no_findings(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeExchangeTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "clean.json", {"host": "mail.de", "build": "15.2.1600.5"})
    r = tool.run({"path": path})
    assert not r.is_error and "ohne Befunde" in r.content


# ------------------------------ run_scanner -------------------------------

def _scanner_tool(cfg, tmp_path, approval=None):
    state = EngagementState()
    tool = RunScannerTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state,
                          approval_fn=approval)
    return tool, state


def test_run_scanner_unknown(tmp_path):
    tool, _ = _scanner_tool(_cfg(tmp_path), tmp_path)
    r = tool.run({"scanner": "metasploit", "target": "127.0.0.1"})
    assert r.is_error and "Unbekannter Scanner" in r.content


def test_run_scanner_disabled(tmp_path):
    tool, _ = _scanner_tool(_cfg(tmp_path), tmp_path)   # keine scanners konfiguriert
    r = tool.run({"scanner": "nmap", "target": "127.0.0.1"})
    assert r.is_error and "nicht freigegeben" in r.content


def test_run_scanner_out_of_scope(tmp_path):
    cfg = _cfg(tmp_path, scanners={"nmap": ScannerPolicy(enabled=True)})
    tool, _ = _scanner_tool(cfg, tmp_path)
    r = tool.run({"scanner": "nmap", "target": "8.8.8.8"})
    assert r.is_error and "VERWEIGERT" in r.content


def test_run_scanner_forbidden_extra_arg(tmp_path):
    cfg = _cfg(tmp_path, scanners={"nmap": ScannerPolicy(enabled=True)})
    tool, _ = _scanner_tool(cfg, tmp_path)
    r = tool.run({"scanner": "nmap", "target": "127.0.0.1", "extra_args": ["-oN", "/etc/x"]})
    assert r.is_error and "VERWEIGERT" in r.content


def test_run_scanner_extra_args_not_list(tmp_path):
    cfg = _cfg(tmp_path, scanners={"nmap": ScannerPolicy(enabled=True)})
    tool, _ = _scanner_tool(cfg, tmp_path)
    r = tool.run({"scanner": "nmap", "target": "127.0.0.1", "extra_args": "nope"})
    assert r.is_error and "Liste" in r.content


def test_run_scanner_approval_rejected(tmp_path):
    cfg = _cfg(tmp_path, scanners={"nmap": ScannerPolicy(enabled=True)})
    tool, _ = _scanner_tool(cfg, tmp_path, approval=lambda _c: False)
    r = tool.run({"scanner": "nmap", "target": "127.0.0.1"})
    assert r.is_error and "abgelehnt" in r.content


def test_run_scanner_success_records_findings(tmp_path):
    cfg = _cfg(tmp_path, scanners={"nmap": ScannerPolicy(enabled=True)})
    tool, state = _scanner_tool(cfg, tmp_path)
    out = "22/tcp open ssh OpenSSH 8.9\n3389/tcp open ms-wbt-server\n"
    fake = subprocess.CompletedProcess([], 0, stdout=out, stderr="")
    with patch("subprocess.run", return_value=fake):
        r = tool.run({"scanner": "nmap", "target": "127.0.0.1", "ports": "22,3389",
                      "rationale": "Portscan"})
    assert not r.is_error
    assert len(state.findings) == 2
    assert len(state.scanner_runs) == 1
    assert state.scanner_runs[0]["scanner"] == "nmap"


def test_run_scanner_truncated_output_note(tmp_path):
    cfg = _cfg(tmp_path, scanners={
        "nmap": ScannerPolicy(enabled=True, max_output_bytes=50)})
    tool, state = _scanner_tool(cfg, tmp_path)
    big = "22/tcp open ssh\n" + ("x" * 500)
    fake = subprocess.CompletedProcess([], 0, stdout=big, stderr="")
    with patch("subprocess.run", return_value=fake):
        r = tool.run({"scanner": "nmap", "target": "127.0.0.1"})
    assert "gekuerzt" in r.content
    assert state.scanner_runs[0]["truncated"] is True


def test_run_scanner_runtime_error(tmp_path):
    cfg = _cfg(tmp_path, scanners={"nmap": ScannerPolicy(enabled=True)})
    tool, _ = _scanner_tool(cfg, tmp_path)
    with patch("subprocess.run", side_effect=FileNotFoundError()):
        r = tool.run({"scanner": "nmap", "target": "127.0.0.1"})
    assert r.is_error and "nicht installiert" in r.content


def test_run_scanner_aggressive_without_optin(tmp_path):
    cfg = _cfg(tmp_path, scanners={"nmap": ScannerPolicy(enabled=True)})
    tool, _ = _scanner_tool(cfg, tmp_path)
    r = tool.run({"scanner": "nmap", "target": "127.0.0.1", "aggressive": True})
    assert r.is_error and "VERWEIGERT" in r.content
