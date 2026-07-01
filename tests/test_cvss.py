"""Tests fuer das CVSS-Lite-Scoring."""

from __future__ import annotations

from specter.cvss import cvss_rating, cvss_score
from specter.findings import Severity


def test_info_is_zero():
    assert cvss_score("injection", Severity.INFO) == 0.0


def test_severity_bands_ordered():
    krit = cvss_score("misconfiguration", Severity.KRITISCH)
    hoch = cvss_score("misconfiguration", Severity.HOCH)
    mittel = cvss_score("misconfiguration", Severity.MITTEL)
    niedrig = cvss_score("misconfiguration", Severity.NIEDRIG)
    assert krit > hoch > mittel > niedrig > 0.0


def test_category_adjustment():
    # Injection (+0.5) hoeher als Fehlkonfiguration (-0.3) bei gleichem Schweregrad.
    assert cvss_score("injection", Severity.HOCH) > cvss_score("misconfiguration", Severity.HOCH)


def test_score_bounds():
    for cat in ["injection", "misconfiguration", "other", "secret_exposure"]:
        for sev in Severity:
            s = cvss_score(cat, sev)
            assert 0.0 <= s <= 10.0


def test_unknown_category_neutral():
    # Unbekannte Kategorie -> keine Justierung (Basis-Score des Bandes).
    assert cvss_score("gibtsnicht", Severity.HOCH) == 7.8


def test_one_decimal():
    s = cvss_score("injection", Severity.MITTEL)
    assert round(s, 1) == s


def test_rating_bands():
    assert cvss_rating(0.0) == "Keine"
    assert cvss_rating(3.9) == "Niedrig"
    assert cvss_rating(4.0) == "Mittel"
    assert cvss_rating(6.9) == "Mittel"
    assert cvss_rating(7.0) == "Hoch"
    assert cvss_rating(8.9) == "Hoch"
    assert cvss_rating(9.0) == "Kritisch"
    assert cvss_rating(10.0) == "Kritisch"


def test_kritisch_maps_to_critical_rating():
    s = cvss_score("injection", Severity.KRITISCH)
    assert s >= 9.0 and cvss_rating(s) == "Kritisch"
