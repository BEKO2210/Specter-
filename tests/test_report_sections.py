"""Tests für die produktionsreifen Report-Abschnitte."""

from __future__ import annotations

from pathlib import Path

from specter.assets import AssetGraph
from specter.config import Config, Engagement, ScannerPolicy
from specter.findings import Finding, FindingsStore
from specter.report import build_json, build_markdown, write_reports


def _cfg(**ov) -> Config:
    d = dict(
        engagement=Engagement("Muster GmbH", "GF", "REF-1"),
        allowed_targets=["127.0.0.1", "10.10.0.0/16"], forbidden_targets=[],
        allowed_paths=[Path("/opt/targets")], max_file_bytes=1000,
        allowed_binaries=["curl"], command_timeout=5, require_approval=False,
        max_iterations=5, model="claude-sonnet-5",
        scanners={"nmap": ScannerPolicy(enabled=True)},
    )
    d.update(ov)
    return Config(**d)


def _store(*findings) -> FindingsStore:
    s = FindingsStore()
    for f in findings:
        s.add(f)
    return s


def test_report_has_all_sections():
    cfg = _cfg()
    store = _store(
        Finding("Default admin", "default_credentials", "hoch", "app",
                location="app:1", evidence="admin=admin"),
        Finding("Altes Exchange", "outdated_component", "kritisch", "mail",
                source="exchange_analyzer"),
    )
    md = build_markdown(cfg, AssetGraph(), store, [])
    for heading in [
        "# Sicherheitsbericht", "## Executive Summary", "## Risiko-Einstufung",
        "## Angriffspfade", "## Quick Wins", "## Langfristige Maßnahmen",
        "## Technische Findings", "## BSI-IT-Grundschutz-Mapping",
        "## Scanner-Ergebnisse", "## Scope-Hinweise", "## Limitierungen",
        "## Nächste Schritte",
    ]:
        assert heading in md, f"Abschnitt fehlt: {heading}"
    # BSI-Bezug muss der Test-Substring finden.
    assert "BSI IT-Grundschutz" in md


def test_quick_wins_listed():
    cfg = _cfg()
    store = _store(Finding("Klartext-Secret", "secret_exposure", "hoch", "app"))
    md = build_markdown(cfg, AssetGraph(), store, [])
    assert "Klartext-Secret" in md
    # Auch in JSON als Quick Win markiert.
    data = build_json(cfg, AssetGraph(), store, [])
    assert data["summary"]["quick_wins"] == 1
    assert len(data["quick_wins"]) == 1


def test_no_quick_wins_message():
    cfg = _cfg()
    store = _store(Finding("Info", "misconfiguration", "niedrig", "app"))
    md = build_markdown(cfg, AssetGraph(), store, [])
    assert "Keine unmittelbaren Quick Wins" in md


def test_long_term_measures():
    cfg = _cfg()
    store = _store(
        Finding("SQLi", "injection", "hoch", "api"),
        Finding("Altes Exchange", "outdated_component", "kritisch", "mail"),
    )
    md = build_markdown(cfg, AssetGraph(), store, [])
    assert "SAST/DAST" in md
    assert "Patch-" in md


def test_empty_long_term_message():
    cfg = _cfg()
    store = _store(Finding("Sonstiges", "other", "info", "x"))
    md = build_markdown(cfg, AssetGraph(), store, [])
    assert "Keine strategischen Maßnahmen" in md


def test_scanner_results_rendered():
    cfg = _cfg()
    runs = [{"scanner": "nmap", "target": "10.10.0.5", "command": "nmap ...",
             "returncode": 0, "finding_count": 3, "truncated": True, "error": ""}]
    md = build_markdown(cfg, AssetGraph(), _store(), [], scanner_runs=runs)
    assert "nmap" in md and "10.10.0.5" in md and "gekürzt" in md


def test_scanner_results_error_shown():
    cfg = _cfg()
    runs = [{"scanner": "nikto", "target": "10.10.0.5", "returncode": None,
             "finding_count": 0, "truncated": False, "error": "Zeitlimit"}]
    md = build_markdown(cfg, AssetGraph(), _store(), [], scanner_runs=runs)
    assert "Zeitlimit" in md


def test_no_scanners_message():
    md = build_markdown(_cfg(), AssetGraph(), _store(), [])
    assert "Keine aktiven Scanner ausgeführt" in md


def test_scope_section_reflects_config():
    cfg = _cfg()
    md = build_markdown(cfg, AssetGraph(), _store(), [])
    assert "127.0.0.1" in md
    assert "nmap" in md          # aktivierter Scanner


def test_cvss_in_markdown_and_json():
    cfg = _cfg()
    store = _store(Finding("SQLi", "injection", "kritisch", "api", location="a:1"))
    md = build_markdown(cfg, AssetGraph(), store, [])
    assert "CVSS-Lite:" in md
    data = build_json(cfg, AssetGraph(), store, [])
    assert data["findings"][0]["cvss"] >= 9.0
    assert data["findings"][0]["cvss_rating"] == "Kritisch"
    assert data["summary"]["max_cvss"] >= 9.0


def test_bsi_table_in_json():
    cfg = _cfg()
    store = _store(Finding("SQLi", "injection", "hoch", "api", location="a:1"))
    data = build_json(cfg, AssetGraph(), store, [])
    assert len(data["bsi_mapping"]) == 1
    assert data["bsi_mapping"][0]["bsi_bezug"].startswith("APP.3.1")
    assert "scope" in data and data["scope"]["enabled_scanners"] == ["nmap"]


def test_pipe_characters_escaped_in_bsi_table():
    cfg = _cfg()
    store = _store(Finding("A | B", "injection", "hoch", "x | y"))
    md = build_markdown(cfg, AssetGraph(), store, [])
    # Pipe in der BSI-Tabellenzelle korrekt als \| escaped (rendert als echtes
    # '|', zerbricht die Tabelle nicht) — besser als der frühere Ersatz durch '/'.
    assert "A \\| B" in md
    # Und die Tabellenzeile hat weiterhin die korrekte Spaltenzahl.
    table_rows = [ln for ln in md.splitlines()
                  if ln.startswith("| SPEC-") and "\\|" in ln]
    assert table_rows and table_rows[0].count(" | ") >= 4


def test_write_reports_with_scanner_runs(tmp_path):
    cfg = _cfg()
    store = _store(Finding("x", "injection", "hoch", "a"))
    runs = [{"scanner": "nmap", "target": "127.0.0.1", "returncode": 0,
             "finding_count": 1, "truncated": False, "error": ""}]
    paths = write_reports(cfg, AssetGraph(), store, [], directory=tmp_path / "r",
                          scanner_runs=runs)
    assert paths["markdown"].exists() and paths["json"].exists()
    assert "nmap" in paths["markdown"].read_text(encoding="utf-8")
