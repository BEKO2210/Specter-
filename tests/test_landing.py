"""Tests für die Marketing-Landingpage (HTML-Erzeugung)."""

from __future__ import annotations

from specter.landing import (
    COVERAGE, PACKAGES, PROBLEMS, STEPS, build_landing_html, write_landing,
)


def test_landing_html_structure_and_content():
    html = build_landing_html("Specter", "info@example.de", generated_at="2026-01-01")
    assert html.startswith("<!doctype html>")
    assert html.strip().endswith("</html>")
    assert "<title>Specter" in html
    assert "2026-01-01" in html
    # Kontaktadresse als mailto verlinkt.
    assert "mailto:info@example.de" in html
    # Alle Inhaltsbloecke sind gerendert.
    assert len(PROBLEMS) == 3 and len(COVERAGE) == 14 and len(PACKAGES) == 3
    for title, _d in PROBLEMS:
        assert title in html
    for title, _d in COVERAGE:
        assert title in html
    for name, _amt, _d in PACKAGES:
        assert name in html
    for title, _d in STEPS:
        assert title in html
    # Kernbotschaften Vertrauen/Recht/DSGVO.
    assert "DSGVO" in html
    assert "202" in html
    assert "Offline" in html
    # Responsiv (Viewport + Media-Query).
    assert "viewport" in html
    assert "@media" in html


def test_landing_html_defaults_branch():
    html = build_landing_html()
    assert "kontakt@example.de" in html
    assert "Specter" in html


def test_write_landing_creates_file(tmp_path):
    path = write_landing(tmp_path / "out", contact_email="hallo@firma.de")
    assert path.exists()
    assert path.name == "specter-landingpage.html"
    text = path.read_text(encoding="utf-8")
    assert "hallo@firma.de" in text
    assert "Gratis-Check" in text
