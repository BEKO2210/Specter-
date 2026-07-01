"""Gezielte Tests fuer Randfaelle, damit alle Zweige abgedeckt sind."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from specter.assets import AssetGraph
from specter.attack_paths import correlate
from specter.audit import AuditLog
from specter.config import Config, Engagement
from specter.findings import Finding, FindingsStore, Severity
from specter.report import build_json, build_markdown
from specter.safety import SafetyPolicy, ScopeViolation
from specter.state import EngagementState
from specter.tools.code_scan import CodeScanTool
from specter.tools.read_file import ReadFileTool
from specter.tools.run_command import RunCommandTool


# -- assets: Edge.to_dict --------------------------------------------------

def test_edge_to_dict():
    g = AssetGraph()
    g.add_asset("host", "h")
    g.add_asset("service", "s")
    g.add_edge("host:h", "service:s", "betreibt")
    d = g.edges()[0].to_dict()
    assert d == {"src": "host:h", "dst": "service:s", "relation": "betreibt"}


# -- findings: get / extend ------------------------------------------------

def test_store_get_and_extend():
    store = FindingsStore()
    added = store.extend([
        Finding("a", "injection", "hoch", "x", location="a:1"),
        Finding("b", "crypto_weakness", "mittel", "y"),
    ])
    assert added == 2
    fid = store.all()[0].id
    assert store.get(fid) is not None
    assert store.get("nichtvorhanden") is None
    assert store.by_severity(Severity.HOCH)[0].category == "injection"


# -- attack_paths: auth+access, cloud, dedup -------------------------------

def test_auth_access_path():
    store = FindingsStore()
    store.add(Finding("Kein MFA", "auth_weakness", "hoch", "app"))
    store.add(Finding("IDOR", "access_control", "hoch", "app"))
    paths = correlate(store, AssetGraph())
    assert any("Rechteausweitung" in p.title for p in paths)


def test_cloud_storage_path():
    store = FindingsStore()
    store.add(Finding("Public Bucket", "cloud_storage", "hoch", "s3://x"))
    paths = correlate(store, AssetGraph())
    assert any("Cloud-Speicher" in p.title for p in paths)


def test_attack_path_dedup():
    # Dieselbe Regel zweimal angewandt erzeugt identische Pfade; die Dedup-Logik
    # in correlate() behaelt jeden Pfad nur einmal.
    from specter.attack_paths import _rule_secret_to_service

    store = FindingsStore()
    store.add(Finding("Key", "secret_exposure", "hoch", "app", location="c:1"))
    store.add(Finding("SSH", "exposed_service", "hoch", "host", location="h:22"))
    paths = correlate(
        store, AssetGraph(),
        rules=[_rule_secret_to_service, _rule_secret_to_service],
    )
    sigs = [(p.title, tuple(sorted(p.finding_ids))) for p in paths]
    assert len(sigs) == len(set(sigs)) == 1


# -- report: keine Findings ------------------------------------------------

def _cfg(tmp_path) -> Config:
    return Config(
        engagement=Engagement("X", "Y", "R"),
        allowed_targets=["127.0.0.1"], forbidden_targets=[],
        allowed_paths=[tmp_path.resolve()], max_file_bytes=1000,
        allowed_binaries=["echo"], command_timeout=5,
        require_approval=False, max_iterations=5, model="claude-sonnet-5",
    )


def test_report_without_findings(tmp_path):
    cfg = _cfg(tmp_path)
    md = build_markdown(cfg, AssetGraph(), FindingsStore(), [])
    assert "_Keine Findings erfasst._" in md
    assert "_Keine korrelierten Angriffspfade._" in md
    data = build_json(cfg, AssetGraph(), FindingsStore(), [])
    assert data["summary"]["findings"] == 0


# -- safety: leere Scopes, Parse-Fehler, host:port, Nicht-Ziel-Argumente ---

def _policy(tmp_path, **overrides) -> SafetyPolicy:
    cfg = _cfg(tmp_path)
    for k, v in overrides.items():
        setattr(cfg, k, v)
    return SafetyPolicy(cfg)


def test_empty_path_scope_denied(tmp_path):
    pol = _policy(tmp_path, allowed_paths=[])
    with pytest.raises(ScopeViolation, match="Kein Datei-Scope"):
        pol.check_path("x")


def test_empty_target_scope_denied(tmp_path):
    pol = _policy(tmp_path, allowed_targets=[])
    with pytest.raises(ScopeViolation, match="Kein Netzwerk-Scope"):
        pol.check_target("127.0.0.1")


def test_forbidden_target(tmp_path):
    pol = _policy(tmp_path, forbidden_targets=["127.0.0.1"])
    with pytest.raises(ScopeViolation, match="Sperrliste"):
        pol.check_target("127.0.0.1")


def test_command_parse_error(tmp_path):
    pol = _policy(tmp_path)
    with pytest.raises(ScopeViolation, match="nicht parsebar"):
        pol.check_command('echo "unbalanced 127.0.0.1')


def test_empty_command(tmp_path):
    pol = _policy(tmp_path)
    with pytest.raises(ScopeViolation, match="Leerer Befehl"):
        pol.check_command("   ")


def test_host_port_normalization(tmp_path):
    pol = _policy(tmp_path)
    assert pol.check_target("127.0.0.1:22") == "127.0.0.1"


def test_command_with_nontarget_argument(tmp_path):
    pol = _policy(tmp_path, allowed_binaries=["echo"])
    # 'plainword' ist kein Ziel (kein . : oder ://) und wird uebersprungen;
    # 127.0.0.1 ist das gueltige Ziel.
    argv = pol.check_command("echo plainword 127.0.0.1")
    assert argv == ["echo", "plainword", "127.0.0.1"]


# -- code_scan: max_results-Grenze + zu grosse Datei + Lesefehler ----------

def _scan_kit(tmp_path):
    cfg = _cfg(tmp_path)
    return CodeScanTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "audit"),
                        EngagementState()), cfg


def test_scan_max_results_limit(tmp_path):
    tool, _ = _scan_kit(tmp_path)
    # Zwei Dateien mit je einem echten Secret-Treffer; max_results=1 stoppt
    # nach der ersten Datei (deckt die File- und Pattern-Break-Zweige ab).
    (tmp_path / "a.py").write_text('password = "abc12345"\n')
    (tmp_path / "b.py").write_text('api_key = "xyz78901"\n')
    r = tool.run({"path": str(tmp_path), "max_results": 1})
    assert "1 Fundstelle" in r.content


def test_scan_skips_too_large(tmp_path):
    tool, cfg = _scan_kit(tmp_path)
    cfg.max_file_bytes = 10
    (tmp_path / "big.py").write_text('password = "' + "x" * 100 + '"')
    r = tool.run({"path": str(tmp_path)})
    assert "Keine verdaechtigen Muster" in r.content


def test_scan_handles_read_error(tmp_path, monkeypatch):
    tool, _ = _scan_kit(tmp_path)
    (tmp_path / "x.py").write_text('password = "abc123"')

    def boom(self, *a, **k):
        raise OSError("kein Zugriff")

    monkeypatch.setattr(Path, "read_text", boom)
    r = tool.run({"path": str(tmp_path)})
    assert "Keine verdaechtigen Muster" in r.content   # Datei uebersprungen


# -- read_file: Lesefehler -------------------------------------------------

def test_read_file_os_error(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    f = tmp_path / "a.py"
    f.write_text("x")

    def boom(self, *a, **k):
        raise OSError("defekt")

    monkeypatch.setattr(Path, "read_text", boom)
    tool = ReadFileTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "audit"))
    r = tool.run({"path": str(f)})
    assert r.is_error and "Lesefehler" in r.content


# -- run_command: Timeout --------------------------------------------------

def test_run_command_timeout(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    tool = RunCommandTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "audit"))

    def raise_timeout(*a, **k):
        raise subprocess.TimeoutExpired(cmd="echo", timeout=5)

    monkeypatch.setattr(subprocess, "run", raise_timeout)
    r = tool.run({"command": "echo 127.0.0.1"})
    assert r.is_error and "Zeitlimit" in r.content
