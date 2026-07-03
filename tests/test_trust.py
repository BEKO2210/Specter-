"""Tests fuer den Vertrauens-/Sicherheits-One-Pager und die Garantien."""

from __future__ import annotations

from specter.trust import (
    DATA_PROTECTION, GUARANTEES, NOT_DOING, build_trust_html,
    data_protection_points, trust_guarantees, write_trust_onepager,
)


def test_trust_guarantee_accessors_are_copies():
    g = trust_guarantees()
    d = data_protection_points()
    assert g == GUARANTEES and d == DATA_PROTECTION
    # Rueckgabe ist eine Kopie - Aenderungen wirken nicht auf die Konstanten.
    g.append(("x", "y"))
    assert len(trust_guarantees()) == len(GUARANTEES)


def test_trust_html_structure_and_content():
    html = build_trust_html("Muster GmbH", generated_at="2026-01-01")
    assert html.startswith("<!doctype html>")
    assert html.strip().endswith("</html>")
    assert "Muster GmbH" in html
    assert "2026-01-01" in html
    # Kernbotschaften
    assert "defensiv" in html
    assert "202a-c StGB" in html
    assert "DSGVO" in html
    assert "Audit-Log" in html
    # Alle Garantien, Datenschutzpunkte und Negativ-Liste sind enthalten.
    for title, _detail in GUARANTEES:
        assert title in html
    for title, _detail in DATA_PROTECTION:
        assert title in html
    for item in NOT_DOING:
        assert item in html


def test_trust_html_default_customer_and_date_branch():
    html = build_trust_html()
    assert "Ihr Unternehmen" in html
    assert "Vertrauens-" in html


def test_write_trust_onepager_creates_file(tmp_path):
    path = write_trust_onepager(tmp_path / "out", customer_name="Beispiel AG")
    assert path.exists()
    assert path.name == "specter-vertrauen-onepager.html"
    text = path.read_text(encoding="utf-8")
    assert "Beispiel AG" in text
    assert "Warum Sie Specter an Ihre Systeme lassen können" in text
