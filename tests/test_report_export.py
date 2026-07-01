"""Tests fuer den markengerechten HTML-Report-Export."""

from __future__ import annotations

from pathlib import Path

from specter.assets import AssetGraph
from specter.attack_paths import AttackPath, correlate
from specter.config import Config, Engagement, ScannerPolicy
from specter.findings import Finding, FindingsStore, Severity
from specter.report_export import build_html, write_html


def _cfg(**ov) -> Config:
    d = dict(
        engagement=Engagement("Muster GmbH", "GF", "REF-1"),
        allowed_targets=["127.0.0.1"], forbidden_targets=[],
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


def test_html_is_wellformed_document():
    html = build_html(_cfg(), AssetGraph(), _store(), [])
    assert html.startswith("<!doctype html>")
    assert "</html>" in html
    assert "Specter" in html and "Defensive Security Intelligence" in html


def test_html_contains_all_sections():
    cfg = _cfg()
    store = _store(
        Finding("Default admin", "default_credentials", "hoch", "app",
                location="app:1", evidence="admin=admin"),
        Finding("SQLi", "injection", "kritisch", "api"),
    )
    html = build_html(cfg, AssetGraph(), store, [])
    for heading in ["Executive Summary", "Risiko-Einstufung", "Angriffspfade",
                    "Quick Wins", "Langfristige Ma", "Technische Findings",
                    "BSI-IT-Grundschutz-Mapping", "Scanner-Ergebnisse",
                    "Scope-Hinweise", "Nächste Schritte"]:
        assert heading in html, f"Abschnitt fehlt: {heading}"


def test_html_escapes_user_content():
    store = _store(Finding("<script>alert(1)</script>", "injection", "hoch", "x",
                           evidence="<b>böse</b>"))
    html = build_html(_cfg(), AssetGraph(), store, [])
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "&lt;b&gt;böse" in html


def test_html_severity_badges():
    store = _store(Finding("x", "injection", "kritisch", "a"))
    html = build_html(_cfg(), AssetGraph(), store, [])
    assert "sev-krit" in html
    assert "Kritisch" in html


def test_html_attack_paths_and_instances():
    cfg = _cfg()
    store = _store(
        Finding("K1", "secret_exposure", "hoch", "app", location="a:1"),
        Finding("K2", "secret_exposure", "hoch", "app", location="a:2"),
        Finding("SSH", "exposed_service", "hoch", "host", location="h:22"),
    )
    paths = correlate(store, AssetGraph())
    html = build_html(cfg, AssetGraph(), store, paths)
    assert "AP-1" in html
    assert "Kombinationen" in html


def test_html_empty_states():
    html = build_html(_cfg(), AssetGraph(), _store(), [])
    assert "Keine korrelierten Angriffspfade" in html
    assert "Keine Findings erfasst" in html
    assert "Keine aktiven Scanner ausgeführt" in html


def test_html_scanner_runs():
    runs = [{"scanner": "nmap", "target": "10.10.0.5", "returncode": 0,
             "finding_count": 3, "truncated": True, "error": ""}]
    html = build_html(_cfg(), AssetGraph(), _store(), [], scanner_runs=runs)
    assert "nmap" in html and "10.10.0.5" in html and "gekürzt" in html


def test_html_print_css_present():
    html = build_html(_cfg(), AssetGraph(), _store(), [])
    assert "@media print" in html
    assert "page-break" in html


def test_html_bsi_table():
    store = _store(Finding("SQLi", "injection", "hoch", "api", location="a:1"))
    html = build_html(_cfg(), AssetGraph(), store, [])
    assert "APP.3.1" in html


def test_write_html_creates_file(tmp_path):
    store = _store(Finding("x", "injection", "hoch", "a"))
    path = write_html(_cfg(), AssetGraph(), store, [], directory=tmp_path / "r")
    assert path.exists() and path.suffix == ".html"
    content = path.read_text(encoding="utf-8")
    assert "<!doctype html>" in content


def test_html_paths_severity_badge_in_paths():
    p = AttackPath("Domänenübernahme", Severity.KRITISCH, ["Schritt 1"], ["F1"])
    html = build_html(_cfg(), AssetGraph(), _store(), [p])
    assert "Domänenübernahme" in html
    assert "Schritt 1" in html
