"""Tests fuer die Angriffspfad-Korrelation und den Report."""

from __future__ import annotations

from pathlib import Path

from specter.assets import AssetGraph
from specter.attack_paths import AttackPath, aggregate_paths, correlate
from specter.config import Config, Engagement
from specter.findings import Finding, FindingsStore, Severity
from specter.report import build_json, build_markdown, write_reports


def _config() -> Config:
    return Config(
        engagement=Engagement("Test-Engagement", "Tester", "REF-1"),
        allowed_targets=["127.0.0.1"], forbidden_targets=[],
        allowed_paths=[Path(".").resolve()], max_file_bytes=1000,
        allowed_binaries=["nmap"], command_timeout=10,
        require_approval=True, max_iterations=5, model="claude-sonnet-5",
    )


def test_aggregate_single_path_unchanged():
    p = AttackPath("Titel", Severity.HOCH, ["Schritt"], ["SPEC-1"])
    result = aggregate_paths([p])
    assert len(result) == 1
    assert result[0].instances == 1


def test_aggregate_merges_same_title():
    paths = [
        AttackPath("Kontoübernahme", Severity.HOCH, ["a"], ["F1", "S1"],
                   rationale="Grund."),
        AttackPath("Kontoübernahme", Severity.KRITISCH, ["b"], ["F2", "S1"],
                   rationale="Grund."),
        AttackPath("Datenabfluss", Severity.HOCH, ["c"], ["F3"]),
    ]
    result = aggregate_paths(paths)
    assert len(result) == 2                       # zwei Titel
    top = result[0]
    assert top.title == "Kontoübernahme"
    assert top.severity is Severity.KRITISCH      # hoechster Schweregrad
    assert top.instances == 2
    assert set(top.finding_ids) == {"F1", "S1", "F2"}   # vereinigt, dedupliziert
    assert "Zusammengefasst aus 2" in top.rationale


def test_correlate_aggregates_by_default():
    store = FindingsStore()
    store.add(Finding("K1", "secret_exposure", "hoch", "app", location="a:1"))
    store.add(Finding("K2", "secret_exposure", "hoch", "app", location="a:2"))
    store.add(Finding("SSH", "exposed_service", "hoch", "host", location="h:22"))
    aggregated = correlate(store, AssetGraph())
    raw = correlate(store, AssetGraph(), aggregate=False)
    # Zwei Secrets x 1 Dienst -> 2 Einzelpfade, 1 Sammelpfad.
    assert len(raw) == 2
    account_takeover = [p for p in aggregated if "Secret" in p.title]
    assert len(account_takeover) == 1
    assert account_takeover[0].instances == 2


def test_report_shows_instance_count():
    cfg = _config()
    store = FindingsStore()
    store.add(Finding("K1", "secret_exposure", "hoch", "app", location="a:1"))
    store.add(Finding("K2", "secret_exposure", "hoch", "app", location="a:2"))
    store.add(Finding("SSH", "exposed_service", "hoch", "host", location="h:22"))
    graph = AssetGraph()
    paths = correlate(store, graph)
    md = build_markdown(cfg, graph, store, paths)
    assert "Kombinationen" in md


def test_secret_plus_service_makes_critical_path():
    store = FindingsStore()
    store.add(Finding("Hardcoded Key", "secret_exposure", "hoch", "app",
                      location="cfg.py:3"))
    store.add(Finding("Offener SSH", "exposed_service", "hoch", "host",
                      location="127.0.0.1:22"))
    paths = correlate(store, AssetGraph())
    assert any(p.severity is Severity.KRITISCH for p in paths)
    assert any("Secret" in p.title for p in paths)


def test_injection_plus_data_is_path():
    store = FindingsStore()
    store.add(Finding("SQLi", "injection", "hoch", "api", location="api.py:9"))
    store.add(Finding("Kundendaten", "sensitive_data", "hoch", "db"))
    paths = correlate(store, AssetGraph())
    assert any("Datenabfluss" in p.title for p in paths)


def test_no_paths_without_combination():
    store = FindingsStore()
    store.add(Finding("Debug an", "misconfiguration", "niedrig", "app"))
    paths = correlate(store, AssetGraph())
    assert paths == []


def test_min_severity_filters_findings():
    store = FindingsStore()
    store.add(Finding("Key", "secret_exposure", "niedrig", "app"))
    store.add(Finding("SSH", "exposed_service", "niedrig", "host"))
    # Mit Mindest-Schwere "hoch" fallen beide raus -> kein Pfad.
    assert correlate(store, AssetGraph(), min_severity=Severity.HOCH) == []


def test_report_markdown_and_json(tmp_path):
    cfg = _config()
    store = FindingsStore()
    store.add(Finding("SQLi", "injection", "kritisch", "api", location="api.py:9",
                      evidence="query = 'SELECT ' + x"))
    graph = AssetGraph()
    graph.add_asset("code", "api.py")
    paths = correlate(store, graph)

    md = build_markdown(cfg, graph, store, paths, generated_at="2026-07-01 12:00")
    assert "Sicherheitsbericht" in md
    assert "SQLi" in md
    assert "Angriffspfade" in md

    data = build_json(cfg, graph, store, paths)
    assert data["summary"]["findings"] == 1
    assert data["findings"][0]["category"] == "injection"

    out = write_reports(cfg, graph, store, paths, directory=tmp_path / "reports")
    assert out["markdown"].exists() and out["json"].exists()
