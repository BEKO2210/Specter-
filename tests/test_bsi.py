"""Tests für das BSI-IT-Grundschutz-Mapping."""

from __future__ import annotations

from specter.bsi import (
    bsi_reference, limitation_for, map_finding, map_findings, priority_label,
)
from specter.findings import Finding, Severity


def test_priority_labels():
    assert priority_label(Severity.KRITISCH) == "Sehr hoch"
    assert priority_label(Severity.HOCH) == "Hoch"
    assert priority_label(Severity.MITTEL) == "Mittel"
    assert priority_label(Severity.NIEDRIG) == "Niedrig"
    assert priority_label(Severity.INFO) == "Information"


def test_reference_per_category():
    f = Finding("SQLi", "injection", "hoch", "app")
    assert bsi_reference(f).startswith("APP.3.1")
    f2 = Finding("Klartext", "personal_data", "mittel", "db")
    assert bsi_reference(f2).startswith("CON.2")


def test_reference_unknown_category_uses_other():
    f = Finding("x", "nichtvorhanden", "info", "a")   # -> other
    assert bsi_reference(f).startswith("ISMS.1")


def test_reference_source_refinement_ad():
    f = Finding("krbtgt alt", "auth_weakness", "hoch", "corp", source="ad_analyzer")
    ref = bsi_reference(f)
    assert "ORP.4" in ref and "APP.2.2" in ref       # Kategorie + AD-Baustein


def test_reference_source_refinement_exchange():
    f = Finding("alt", "outdated_component", "kritisch", "mail",
                source="exchange_analyzer")
    ref = bsi_reference(f)
    assert "OPS.1.1.3" in ref and "APP.5.2" in ref


def test_limitation_per_source():
    assert "statischer" in limitation_for(
        Finding("x", "injection", "hoch", "a", source="static_scan"))
    assert "AD-Exports" in limitation_for(
        Finding("x", "auth_weakness", "hoch", "a", source="ad_analyzer"))
    assert "Netzwerk-Scans" in limitation_for(
        Finding("x", "exposed_service", "hoch", "a", source="nmap"))
    # Unbekannte Quelle -> generischer Hinweis.
    assert "Prüfzeitpunkt" in limitation_for(
        Finding("x", "other", "info", "a", source="irgendwas"))


def test_map_finding_complete_structure():
    f = Finding("Default admin", "default_credentials", "hoch", "app",
                location="app:1", evidence="admin=admin", cwe="CWE-1392")
    m = map_finding(f)
    d = m.to_dict()
    for key in ("finding_id", "risiko", "bereich", "maßnahme", "bsi_bezug",
                "priorität", "evidenz", "einschränkungen"):
        assert d[key]
    assert d["finding_id"] == f.id
    assert d["priorität"] == "Hoch"
    assert d["evidenz"] == "admin=admin"


def test_map_finding_evidence_fallback_to_location():
    f = Finding("x", "injection", "hoch", "a", location="a.py:9")
    assert map_finding(f).evidenz == "a.py:9"
    f2 = Finding("y", "injection", "hoch", "a")
    assert map_finding(f2).evidenz == "n/a"


def test_map_findings_list():
    fs = [Finding("a", "injection", "hoch", "x"),
          Finding("b", "crypto_weakness", "mittel", "y")]
    ms = map_findings(fs)
    assert len(ms) == 2
