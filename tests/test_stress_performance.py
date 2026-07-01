"""Stress- und Performance-Tests: Verhalten unter Last und gegen ReDoS.

Grosszuegige Zeitgrenzen, damit die Tests nicht flaky sind - sie fangen aber
pathologische Blow-ups (z. B. katastrophales Regex-Backtracking) sicher ab.
"""

from __future__ import annotations

import time
from pathlib import Path

from specter.assets import AssetGraph
from specter.audit import AuditLog
from specter.attack_paths import correlate
from specter.config import Config, Engagement
from specter.findings import Finding, FindingsStore, Severity
from specter.report import build_markdown, write_reports
from specter.safety import SafetyPolicy
from specter.state import EngagementState
from specter.tools.code_scan import CodeScanTool


def _cfg(tmp_path, **ov) -> Config:
    allowed = tmp_path / "targets"
    allowed.mkdir(exist_ok=True)
    d = dict(
        engagement=Engagement("Stress GmbH", "Y", "R"),
        allowed_targets=["127.0.0.1"], forbidden_targets=[],
        allowed_paths=[allowed.resolve()], max_file_bytes=2_000_000,
        allowed_binaries=["curl"], command_timeout=10,
        require_approval=False, max_iterations=5, model="claude-sonnet-5",
    )
    d.update(ov)
    return Config(**d)


def test_scan_large_codebase(tmp_path):
    """300 Dateien, jede mit einer Schwachstelle - Scan muss zuegig durchlaufen."""
    cfg = _cfg(tmp_path)
    root = tmp_path / "targets"
    for i in range(300):
        (root / f"modul_{i}.py").write_text(f'API_KEY = "sk-live-token{i:06d}"\n')
    state = EngagementState()
    tool = CodeScanTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)

    start = time.monotonic()
    tool.run({"path": str(root), "max_results": 10_000})
    elapsed = time.monotonic() - start

    assert len(state.findings) == 300
    assert elapsed < 10.0, f"Scan zu langsam: {elapsed:.1f}s"


def test_scan_respects_max_results_under_load(tmp_path):
    cfg = _cfg(tmp_path)
    root = tmp_path / "targets"
    for i in range(200):
        (root / f"m_{i}.py").write_text(f'password = "GeheimPW{i:05d}"\n')
    state = EngagementState()
    tool = CodeScanTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    r = tool.run({"path": str(root), "max_results": 50})
    assert "50 Fundstelle" in r.content


def test_regex_no_catastrophic_backtracking(tmp_path):
    """Eine sehr lange, gemein konstruierte Zeile darf den Scanner nicht haengen."""
    cfg = _cfg(tmp_path)
    root = tmp_path / "targets"
    # Lange Zeile, die die SQL-/Secret-Muster reizt (viele +, Anfuehrungszeichen).
    payload = "SELECT " + ("a+" * 20_000) + "'" + ("x" * 20_000)
    (root / "evil.py").write_text(payload + "\n")
    (root / "evil2.py").write_text("password = " + ("A" * 50_000) + "\n")
    state = EngagementState()
    tool = CodeScanTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)

    start = time.monotonic()
    tool.run({"path": str(root)})
    elapsed = time.monotonic() - start
    assert elapsed < 5.0, f"Moegliches ReDoS: {elapsed:.1f}s"


def test_correlate_scales(tmp_path):
    """Viele Findings korrelieren in vertretbarer Zeit."""
    store = FindingsStore()
    for i in range(150):
        store.add(Finding(f"Secret {i}", "secret_exposure", Severity.HOCH,
                          f"app{i}", location=f"c{i}.py:1"))
    for i in range(150):
        store.add(Finding(f"Dienst {i}", "exposed_service", Severity.HOCH,
                          f"host{i}", location=f"10.0.0.{i}:22"))
    start = time.monotonic()
    paths = correlate(store, AssetGraph())
    elapsed = time.monotonic() - start
    # 150 Secrets x 150 Dienste -> viele Pfade, aber deterministisch und schnell.
    assert len(paths) > 100
    assert elapsed < 5.0, f"Korrelation zu langsam: {elapsed:.1f}s"


def test_report_with_many_findings(tmp_path):
    cfg = _cfg(tmp_path)
    store = FindingsStore()
    for i in range(500):
        sev = [Severity.KRITISCH, Severity.HOCH, Severity.MITTEL,
               Severity.NIEDRIG, Severity.INFO][i % 5]
        store.add(Finding(f"Finding {i}", "injection", sev, f"asset{i}",
                          location=f"f{i}.py:{i}", evidence=f"code {i}"))
    graph = AssetGraph()
    for i in range(100):
        graph.add_asset("host", f"10.0.0.{i}")

    start = time.monotonic()
    md = build_markdown(cfg, graph, store, [])
    paths = write_reports(cfg, graph, store, [], directory=tmp_path / "reports")
    elapsed = time.monotonic() - start

    assert len(store) == 500
    assert "500 Finding" in md
    assert paths["markdown"].exists() and paths["json"].exists()
    assert elapsed < 5.0, f"Reporterstellung zu langsam: {elapsed:.1f}s"


def test_many_assets_and_edges(tmp_path):
    """Grosser Asset-Graph mit vielen Kanten bleibt konsistent."""
    graph = AssetGraph()
    for i in range(500):
        graph.add_asset("host", f"10.0.{i // 256}.{i % 256}")
    graph.add_asset("service", "zentral")
    added = 0
    for a in list(graph.assets()):
        if a.type == "host":
            added += int(graph.add_edge(a.key, "service:zentral", "verbindet"))
    assert added == 500
    assert len(graph.neighbors("service:zentral")) == 500
