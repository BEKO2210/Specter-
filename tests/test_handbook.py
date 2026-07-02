"""Tests fuer das Lern-/Bedien-Handbuch (HTML-Erzeugung)."""

from __future__ import annotations

from specter.handbook import ANALYZERS, build_handbook_html, write_handbook


def test_handbook_html_structure_and_content():
    html = build_handbook_html("Muster GmbH", generated_at="2026-01-01")
    # Grundgeruest
    assert html.startswith("<!doctype html>")
    assert html.strip().endswith("</html>")
    assert "Dein Specter-Handbuch" in html
    assert "Muster GmbH" in html
    assert "2026-01-01" in html
    # Alle vierzehn Analyzer sind dokumentiert.
    for name, _what, _why in ANALYZERS:
        assert name in html
    assert len(ANALYZERS) == 14
    # Kernbotschaften: defensiv, Rahmen, Recht, Versicherung.
    assert "defensiv" in html
    assert "202" in html  # Hackerparagraf-Hinweis
    assert "DSGVO" in html
    assert "Versicherung" in html
    assert "fail-closed" in html


def test_handbook_html_default_company_and_date_branch():
    # Ohne generated_at wird das aktuelle Datum verwendet (kein Crash).
    html = build_handbook_html()
    assert "Ihr Unternehmen" in html
    assert "Handbuch fuer" in html


def test_write_handbook_creates_file(tmp_path):
    path = write_handbook(tmp_path / "out", company_name="Beispiel AG")
    assert path.exists()
    assert path.name == "specter-handbuch.html"
    text = path.read_text(encoding="utf-8")
    assert "Beispiel AG" in text
    assert "Spickzettel" in text
