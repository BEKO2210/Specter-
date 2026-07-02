"""Tests fuer die Erstkontakt-E-Mail-Vorlage."""

from __future__ import annotations

from specter.analyzers.email_security import analyze_email_security
from specter.findings import Finding, Severity
from specter.outreach import _plain, build_outreach_email


def _f(title: str, severity: Severity = Severity.MITTEL) -> Finding:
    return Finding(title=title, category="email_security", severity=severity,
                   asset="x.de", source="email_security_analyzer")


def test_outreach_with_findings_lists_top_three():
    findings = [
        _f("Kein DMARC-Eintrag fuer x.de", Severity.HOCH),
        _f("DMARC nur im Monitoring-Modus (p=none): x.de", Severity.MITTEL),
        _f("DKIM-Schluessel nicht mehr zeitgemaess (1024 Bit): x.de", Severity.NIEDRIG),
        _f("DMARC ohne Auswertungs-Reports (kein rua): x.de", Severity.NIEDRIG),
    ]
    mail = build_outreach_email("x.de", findings, sender_name="Belkis",
                                contact_email="b@example.de")
    assert "x.de" in mail["subject"]
    body = mail["body"]
    # Nur die drei schwersten Befunde erscheinen.
    assert body.count("  - ") == 3
    assert "Belkis" in body and "b@example.de" in body
    assert "defensiv" in body
    # Der schwerste (Kein DMARC) ist dabei.
    assert "kein DMARC-Eintrag hinterlegt" in body


def test_outreach_without_findings_uses_soft_variant():
    mail = build_outreach_email("stark.de", [])
    assert "guten Eindruck" in mail["body"]
    assert "Ihr Specter-Team" in mail["body"]   # Default-Signatur
    assert "  - " not in mail["body"]           # keine Befund-Bullets


def test_plain_covers_all_mappings():
    cases = {
        "Kein SPF-Eintrag fuer x.de": "kein SPF-Eintrag",
        "SPF erlaubt beliebige Absender (+all/?all): x.de": "beliebige Absender",
        "SPF ohne abschliessenden all-Mechanismus: x.de": "keinen klaren Abschluss",
        "Kein DMARC-Eintrag fuer x.de": "kein DMARC-Eintrag hinterlegt",
        "DMARC nur im Monitoring-Modus (p=none): x.de": "p=none",
        "DMARC ohne Auswertungs-Reports (kein rua): x.de": "Auswertungs-Reports",
        "Kein DKIM-Schluessel fuer x.de": "keine DKIM-Signatur",
        "DKIM-Schluessel zu schwach (512 Bit, Selector s): x.de": "zu kurz und gilt als unsicher",
        "DKIM-Schluessel nicht mehr zeitgemaess (1024 Bit, Selector s): x.de": "zu kurz",
    }
    for title, needle in cases.items():
        assert needle in _plain(_f(title))
    # Unbekannter Titel faellt auf den Originaltitel zurueck.
    assert _plain(_f("Irgendein anderer Titel")) == "Irgendein anderer Titel"


def test_outreach_end_to_end_with_real_analyzer():
    export = {"domain": "kunde.de", "spf": "", "dmarc": "v=DMARC1; p=none", "dkim": []}
    findings = analyze_email_security(export)
    mail = build_outreach_email("kunde.de", findings)
    assert mail["subject"].startswith("Kurzer Hinweis")
    assert "kunde.de" in mail["body"]
