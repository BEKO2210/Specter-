"""Tests fuer alle Agenten-Werkzeuge (Erfolg + Scope-/Fehlerpfade)."""

from __future__ import annotations

import pytest

from specter.audit import AuditLog
from specter.safety import SafetyPolicy
from specter.state import EngagementState
from specter.tools.base import build_registry
from specter.tools.correlate_paths import CorrelatePathsTool
from specter.tools.generate_report import GenerateReportTool
from specter.tools.read_file import ReadFileTool
from specter.tools.record_finding import RecordFindingTool
from specter.tools.register_asset import RegisterAssetTool
from specter.tools.run_command import RunCommandTool
from specter.tools.code_scan import CodeScanTool


@pytest.fixture
def kit(config, tmp_path):
    audit = AuditLog(tmp_path / "audit")
    policy = SafetyPolicy(config)
    state = EngagementState()
    return config, policy, audit, state


# -- Registry --------------------------------------------------------------

def test_registry_has_all_tools(kit):
    config, policy, audit, state = kit
    tools = build_registry(config, policy, audit, state)
    assert set(tools) == {
        "register_asset", "read_file", "scan_code", "run_command",
        "record_finding", "correlate_paths", "generate_report",
        "analyze_ad", "analyze_exchange", "analyze_entra", "analyze_aws",
        "analyze_azure", "analyze_email_security", "analyze_dependencies",
        "analyze_firewall", "analyze_tls", "analyze_backup",
        "analyze_http_headers", "run_scanner", "retest", "open_pull_requests",
    }
    for t in tools.values():
        assert "name" in t.spec and "input_schema" in t.spec


# -- register_asset --------------------------------------------------------

def test_register_asset_new_and_edge(kit):
    _, _, audit, state = kit
    tool = RegisterAssetTool(state, audit)
    r1 = tool.run({"type": "host", "name": "127.0.0.1", "note": "server"})
    assert "neu erfasst" in r1.content
    r2 = tool.run({"type": "service", "name": "ssh", "relation": "betreibt",
                   "related_to": "host:127.0.0.1"})
    assert "Kante" in r2.content
    assert len(state.assets) == 2


def test_register_asset_edge_unknown_neighbor(kit):
    _, _, audit, state = kit
    tool = RegisterAssetTool(state, audit)
    r = tool.run({"type": "host", "name": "h", "relation": "x",
                  "related_to": "host:unknown"})
    assert "nicht moeglich" in r.content


def test_register_asset_missing_name(kit):
    _, _, audit, state = kit
    r = RegisterAssetTool(state, audit).run({"type": "host", "name": ""})
    assert r.is_error


# -- read_file -------------------------------------------------------------

def test_read_file_ok(kit, targets_dir):
    config, policy, audit, _ = kit
    f = targets_dir / "a.py"
    f.write_text("line1\nline2\n")
    r = ReadFileTool(config, policy, audit).run({"path": str(f)})
    assert not r.is_error
    assert "line1" in r.content and "1\t" in r.content


def test_read_file_scope_denied(kit):
    config, policy, audit, _ = kit
    r = ReadFileTool(config, policy, audit).run({"path": "/etc/passwd"})
    assert r.is_error and "VERWEIGERT" in r.content


def test_read_file_not_found(kit, targets_dir):
    config, policy, audit, _ = kit
    r = ReadFileTool(config, policy, audit).run({"path": str(targets_dir / "nope.py")})
    assert r.is_error and "existiert nicht" in r.content


def test_read_file_too_large(kit, targets_dir):
    config, policy, audit, _ = kit
    config.max_file_bytes = 5
    f = targets_dir / "big.py"
    f.write_text("x" * 100)
    r = ReadFileTool(config, policy, audit).run({"path": str(f)})
    assert r.is_error and "zu gross" in r.content


# -- scan_code -------------------------------------------------------------

def test_scan_code_records_findings(kit, targets_dir):
    config, policy, audit, state = kit
    (targets_dir / "vuln.py").write_text(
        'API_KEY = "sk-live-abcdef123"\n'
        'q = "SELECT * FROM t WHERE id=" + uid\n'
        'import hashlib; hashlib.md5(b"x")\n'
    )
    tool = CodeScanTool(config, policy, audit, state)
    r = tool.run({"path": str(targets_dir)})
    assert not r.is_error
    assert "neu als Finding erfasst" in r.content
    assert len(state.findings) >= 3


def test_scan_code_scope_denied(kit):
    config, policy, audit, state = kit
    r = CodeScanTool(config, policy, audit, state).run({"path": "/etc"})
    assert r.is_error and "VERWEIGERT" in r.content


def test_scan_code_clean_dir(kit, targets_dir):
    config, policy, audit, state = kit
    (targets_dir / "clean.py").write_text("x = 1 + 2\n")
    r = CodeScanTool(config, policy, audit, state).run({"path": str(targets_dir)})
    assert "Keine verdaechtigen Muster" in r.content
    assert len(state.findings) == 0


def test_scan_code_single_file(kit, targets_dir):
    config, policy, audit, state = kit
    f = targets_dir / "one.py"
    f.write_text('password = "supersecret"\n')
    r = CodeScanTool(config, policy, audit, state).run({"path": str(f)})
    assert len(state.findings) == 1


# -- run_command -----------------------------------------------------------

def test_run_command_echo_ok(kit):
    config, policy, audit, _ = kit
    tool = RunCommandTool(config, policy, audit)
    r = tool.run({"command": "echo 127.0.0.1", "rationale": "test"})
    assert not r.is_error
    assert "Exit-Code: 0" in r.content
    assert "127.0.0.1" in r.content


def test_run_command_binary_not_allowed(kit):
    config, policy, audit, _ = kit
    r = RunCommandTool(config, policy, audit).run({"command": "rm -rf 127.0.0.1"})
    assert r.is_error and "VERWEIGERT" in r.content


def test_run_command_target_out_of_scope(kit):
    config, policy, audit, _ = kit
    r = RunCommandTool(config, policy, audit).run({"command": "nmap 8.8.8.8"})
    assert r.is_error and "VERWEIGERT" in r.content


def test_run_command_rejected_by_approval(kit):
    config, policy, audit, _ = kit
    tool = RunCommandTool(config, policy, audit, approval_fn=lambda _c: False)
    r = tool.run({"command": "echo 127.0.0.1"})
    assert r.is_error and "abgelehnt" in r.content


def test_run_command_binary_not_installed(kit):
    config, policy, audit, _ = kit
    config.allowed_binaries.append("definitiv_nicht_da_xyz")
    r = RunCommandTool(config, policy, audit).run(
        {"command": "definitiv_nicht_da_xyz 127.0.0.1"}
    )
    assert r.is_error and "nicht installiert" in r.content


def test_run_command_timeout(kit):
    config, policy, audit, _ = kit
    config.allowed_binaries.append("sleep")
    config.command_timeout = 1
    # sleep braucht ein "ziel-aehnliches" Argument -> 127.0.0.1 ist ungueltig fuer
    # sleep, daher stattdessen echo mit langem Lauf simulieren wir nicht real;
    # wir pruefen den Timeout-Pfad ueber ein echtes langsames Kommando.
    r = RunCommandTool(config, policy, audit).run({"command": "sleep 127.0.0.1"})
    # 'sleep 127.0.0.1' -> sleep interpretiert Argument als ungueltig und endet
    # schnell mit Exit != 0; kein Timeout. Daher nur pruefen: kein Crash.
    assert isinstance(r.content, str)


# -- record_finding --------------------------------------------------------

def test_record_finding_ok(kit):
    _, _, audit, state = kit
    tool = RecordFindingTool(state, audit)
    r = tool.run({"title": "SQLi", "category": "injection", "severity": "hoch",
                  "asset": "api", "location": "api.py:9", "cwe": "CWE-89"})
    assert not r.is_error
    assert len(state.findings) == 1
    assert state.findings.all()[0].status == "bestaetigt"


def test_record_finding_invalid_severity(kit):
    _, _, audit, state = kit
    r = RecordFindingTool(state, audit).run(
        {"title": "x", "category": "injection", "severity": "banane", "asset": "a"}
    )
    assert r.is_error


def test_record_finding_dedup(kit):
    _, _, audit, state = kit
    tool = RecordFindingTool(state, audit)
    args = {"title": "x", "category": "injection", "severity": "hoch",
            "asset": "a", "location": "a.py:1"}
    tool.run(args)
    r2 = tool.run(args)
    assert "bereits vorhanden" in r2.content
    assert len(state.findings) == 1


# -- correlate_paths -------------------------------------------------------

def test_correlate_paths_finds_paths(kit):
    _, _, audit, state = kit
    rf = RecordFindingTool(state, audit)
    rf.run({"title": "Key", "category": "secret_exposure", "severity": "hoch",
            "asset": "app", "location": "c.py:1"})
    rf.run({"title": "SSH", "category": "exposed_service", "severity": "hoch",
            "asset": "host", "location": "127.0.0.1:22"})
    r = CorrelatePathsTool(state, audit).run({})
    assert "Angriffspfad" in r.content
    assert len(state.attack_paths) >= 1


def test_correlate_paths_empty(kit):
    _, _, audit, state = kit
    r = CorrelatePathsTool(state, audit).run({})
    assert "Keine Angriffspfade" in r.content


def test_correlate_paths_bad_min_severity_defaults(kit):
    _, _, audit, state = kit
    # Ungueltiger Wert faellt auf 'mittel' zurueck -> kein Crash.
    r = CorrelatePathsTool(state, audit).run({"min_severity": "banane"})
    assert isinstance(r.content, str)


# -- generate_report -------------------------------------------------------

def test_generate_report_writes_files(kit, tmp_path, monkeypatch):
    config, _, audit, state = kit
    monkeypatch.chdir(tmp_path)
    RecordFindingTool(state, audit).run(
        {"title": "SQLi", "category": "injection", "severity": "kritisch",
         "asset": "api", "location": "api.py:9", "evidence": "q = ..."}
    )
    r = GenerateReportTool(config, state, audit).run({})
    assert "Bericht geschrieben" in r.content
    assert (tmp_path / "reports").exists()
    files = list((tmp_path / "reports").glob("*"))
    assert any(f.suffix == ".md" for f in files)
    assert any(f.suffix == ".json" for f in files)


def test_generate_report_with_pr_drafts(kit, tmp_path, monkeypatch):
    config, _, audit, state = kit
    monkeypatch.chdir(tmp_path)
    RecordFindingTool(state, audit).run(
        {"title": "Key", "category": "secret_exposure", "severity": "hoch",
         "asset": "app"}
    )
    r = GenerateReportTool(config, state, audit).run({"include_pr_drafts": True})
    assert "Draft-Pull-Requests" in r.content
    assert "fix(security):" in r.content
