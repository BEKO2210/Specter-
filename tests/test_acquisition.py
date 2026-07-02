"""Tests fuer den Zielkunden-/Akquiseplan."""

from __future__ import annotations

import html as _html

from specter.acquisition import (
    CADENCE, CHANNELS, ICP, INDUSTRIES, OBJECTIONS, PROCESS,
    build_acquisition_html, write_acquisition,
)


def test_acquisition_html_structure_and_content():
    html = build_acquisition_html("Ludwigsburg/Stuttgart", generated_at="2026-01-01")
    assert html.startswith("<!doctype html>")
    assert html.strip().endswith("</html>")
    assert "Zielkunden &amp; Akquiseplan" in html
    assert "Ludwigsburg/Stuttgart" in html
    assert "2026-01-01" in html
    # Alle Inhaltsbloecke sind vertreten.
    for item in ICP:
        assert _html.escape(item) in html
    for name, _why in INDUSTRIES:
        assert _html.escape(name) in html
    for c in CHANNELS:
        assert _html.escape(c) in html
    for title, _d in PROCESS:
        assert _html.escape(title) in html
    for when, _a in CADENCE:
        assert _html.escape(when) in html
    for obj, _ans in OBJECTIONS:
        assert _html.escape(obj) in html
    # Rechtlicher Rahmen.
    assert "UWG" in html
    assert "202" in html


def test_acquisition_data_shape():
    assert len(ICP) >= 4
    assert len(INDUSTRIES) == 8
    assert len(PROCESS) == 6
    assert len(CADENCE) == 4
    assert len(OBJECTIONS) == 4


def test_acquisition_default_region_branch():
    html = build_acquisition_html()
    assert "Ludwigsburg/Stuttgart" in html


def test_write_acquisition_creates_file(tmp_path):
    path = write_acquisition(tmp_path / "out", region="Region X")
    assert path.exists()
    assert path.name == "specter-akquiseplan.html"
    text = path.read_text(encoding="utf-8")
    assert "Region X" in text
    assert "Akquise in sechs Schritten" in text
