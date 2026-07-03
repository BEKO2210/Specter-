"""Tests für den Angebots-/Preis-One-Pager."""

from __future__ import annotations

import html as _html

from specter.offer import ADDONS, PACKAGES, STEPS, build_offer_html, write_offer


def test_offer_html_structure_and_content():
    html = build_offer_html("Muster GmbH", "b@example.de", generated_at="2026-01-01")
    assert html.startswith("<!doctype html>")
    assert html.strip().endswith("</html>")
    assert "Angebot &amp; Preise" in html
    assert "Muster GmbH" in html
    assert "2026-01-01" in html
    assert "mailto:b@example.de" in html
    # Genau ein hervorgehobenes Paket (Basis-Audit).
    assert html.count("class='pkg feat'") == 1
    assert "Beliebt" in html
    # Alle Pakete, Add-ons und Schritte erscheinen.
    for name, _price, _d, _f, _feat in PACKAGES:
        assert name in html
    for name, _price, _d in ADDONS:
        assert name in html
    for title, _d in STEPS:
        assert _html.escape(title) in html
    # Vertrauens-/Rechts-Kernaussagen.
    assert "defensiv" in html
    assert "202" in html
    assert "DSGVO" in html


def test_offer_data_shape():
    assert len(PACKAGES) == 3 and len(ADDONS) == 3 and len(STEPS) == 3
    # Genau ein Paket ist als hervorgehoben markiert.
    assert sum(1 for *_x, feat in PACKAGES if feat) == 1


def test_offer_default_customer_and_date_branch():
    html = build_offer_html()
    assert "Ihr Unternehmen" in html
    assert "kontakt@example.de" in html


def test_write_offer_creates_file(tmp_path):
    path = write_offer(tmp_path / "out", customer_name="Beispiel AG")
    assert path.exists()
    assert path.name == "specter-angebot.html"
    text = path.read_text(encoding="utf-8")
    assert "Beispiel AG" in text
    assert "Optionale Zusatzleistungen" in text
