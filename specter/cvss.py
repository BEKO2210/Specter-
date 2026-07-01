"""CVSS-Lite: ein deterministischer, numerischer Schweregrad-Score je Finding.

Kunden erwarten oft einen CVSS-Zahlwert. Specter erhebt keine vollstaendigen
CVSS-Vektoren (dafuer fehlt der Kontext), liefert aber einen nachvollziehbaren
Basis-Score von 0.0 bis 10.0, abgeleitet aus dem Schweregrad und einer
kategoriespezifischen Feinjustierung. Die Qualitaetsstufe folgt den Baendern
von CVSS v3.1.

WICHTIG: Dies ist eine transparente Naeherung ("CVSS-Lite"), kein offizieller
CVSS-Base-Score. Der Bericht weist das entsprechend aus.
"""

from __future__ import annotations

from .findings import Severity

# Basis-Score je Schweregrad (Mitte des jeweiligen CVSS-Bandes).
_SEVERITY_BASE: dict[Severity, float] = {
    Severity.KRITISCH: 9.4,
    Severity.HOCH: 7.8,
    Severity.MITTEL: 5.4,
    Severity.NIEDRIG: 3.0,
    Severity.INFO: 0.0,
}

# Kategoriespezifische Feinjustierung (leicht rauf/runter innerhalb des Bandes).
_CATEGORY_ADJUST: dict[str, float] = {
    "injection": 0.5,
    "secret_exposure": 0.4,
    "default_credentials": 0.4,
    "remote_access": 0.4,
    "access_control": 0.3,
    "deserialization": 0.3,
    "outdated_component": 0.3,
    "cloud_storage": 0.3,
    "sensitive_data": 0.2,
    "auth_weakness": 0.1,
    "crypto_weakness": 0.0,
    "personal_data": 0.0,
    "exposed_service": 0.0,
    "transport_security": -0.2,
    "misconfiguration": -0.3,
    "other": -0.3,
}


def cvss_score(category: str, severity: Severity) -> float:
    """Numerischer CVSS-Lite-Basis-Score 0.0-10.0 (eine Nachkommastelle)."""
    if severity is Severity.INFO:
        return 0.0
    base = _SEVERITY_BASE[severity]
    adjust = _CATEGORY_ADJUST.get(category, 0.0)
    return round(min(10.0, max(0.0, base + adjust)), 1)


def cvss_rating(score: float) -> str:
    """Qualitaetsstufe nach CVSS v3.1 (deutsche Bezeichnung)."""
    if score <= 0.0:
        return "Keine"
    if score < 4.0:
        return "Niedrig"
    if score < 7.0:
        return "Mittel"
    if score < 9.0:
        return "Hoch"
    return "Kritisch"
