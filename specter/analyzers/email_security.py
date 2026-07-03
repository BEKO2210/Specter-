"""Defensive E-Mail-Security-Analyse (SPF, DKIM, DMARC) aus DNS-Export.

Wertet einen lokalen JSON-Export der relevanten DNS-Einträge einer Domain aus
und leitet typische E-Mail-Spoofing-/Phishing-Risiken ab - ohne jede
Live-Abfrage, ohne Versand, ohne Ausnutzung. Diese drei Mechanismen entscheiden,
ob Angreifer im Namen der Firma E-Mails fälschen können (BEC/CEO-Fraud) - im
Mittelstand und bei Versicherern ein Haupteinfallstor.

Erwartete Struktur (alle Felder optional):

    {
      "domain": "musterversicherung.de",
      "spf": "v=spf1 include:_spf.google.com ~all",
      "dmarc": "v=DMARC1; p=none; rua=mailto:dmarc@musterversicherung.de",
      "dkim": [
        {"selector": "google", "key_bits": 1024, "present": true}
      ],
      "mx": ["aspmx.l.google.com"]
    }

Fehlt ein Eintrag (Schlüssel nicht vorhanden oder leer), gilt er als NICHT
vorhanden - das ist der häufigste und schwerste Befund.
"""

from __future__ import annotations

import re
from typing import Any

from ..findings import Finding, Severity
from ._util import as_list

# SPF-Qualifier für "alles andere": -all (streng), ~all (soft), ?all/+all (schwach).
_SPF_SOFT = "~all"
_SPF_STRICT = "-all"
_SPF_WEAK = ("?all", "+all")
MIN_DKIM_BITS = 1024
WEAK_DKIM_BITS = 2048  # < 2048 gilt heute als nicht mehr zeitgemäß


def _mk(title, category, severity, asset, evidence, *, cwe="", owner="E-Mail-/IT-Team") -> Finding:
    return Finding(
        title=title, category=category, severity=severity, asset=asset,
        location=asset, evidence=evidence, cwe=cwe, owner=owner,
        source="email_security_analyzer", status="offen",
    )


def _analyze_spf(spf: Any, domain: str) -> list[Finding]:
    out: list[Finding] = []
    loc = f"{domain}/SPF"
    value = str(spf or "").strip().lower()
    if not value:
        out.append(_mk(
            f"Kein SPF-Eintrag für {domain}",
            "email_security", Severity.HOCH, loc,
            "SPF fehlt - beliebige Absender können im Namen der Domain mailen",
            cwe="CWE-290",
        ))
        return out
    if any(w in value for w in _SPF_WEAK):
        out.append(_mk(
            f"SPF erlaubt beliebige Absender (+all/?all): {domain}",
            "email_security", Severity.HOCH, loc,
            f"SPF={spf} - Qualifier hebt den Schutz praktisch auf", cwe="CWE-290",
        ))
    elif _SPF_STRICT not in value and _SPF_SOFT not in value:
        out.append(_mk(
            f"SPF ohne abschließenden all-Mechanismus: {domain}",
            "email_security", Severity.MITTEL, loc,
            f"SPF={spf} - kein -all/~all, Wirkung unklar", cwe="CWE-290",
        ))
    return out


def _analyze_dmarc(dmarc: Any, domain: str) -> list[Finding]:
    out: list[Finding] = []
    loc = f"{domain}/DMARC"
    value = str(dmarc or "").strip().lower()
    if not value:
        out.append(_mk(
            f"Kein DMARC-Eintrag für {domain}",
            "email_security", Severity.HOCH, loc,
            "DMARC fehlt - SPF/DKIM werden nicht durchgesetzt, Spoofing möglich",
            cwe="CWE-290",
        ))
        return out
    if re.search(r"(?:^|;)\s*p\s*=\s*none\b", value):
        out.append(_mk(
            f"DMARC nur im Monitoring-Modus (p=none): {domain}",
            "email_security", Severity.MITTEL, loc,
            f"DMARC={dmarc} - keine Durchsetzung; Ziel ist p=quarantine oder p=reject",
            cwe="CWE-290",
        ))
    if "rua=" not in value:
        out.append(_mk(
            f"DMARC ohne Auswertungs-Reports (kein rua): {domain}",
            "email_security", Severity.NIEDRIG, loc,
            f"DMARC={dmarc} - ohne rua-Adresse keine Sichtbarkeit über Missbrauch",
        ))
    return out


def _analyze_dkim(dkim: Any, domain: str) -> list[Finding]:
    out: list[Finding] = []
    loc = f"{domain}/DKIM"
    selectors = [d for d in as_list(dkim) if isinstance(d, dict)]
    present = [d for d in selectors if d.get("present", True)]
    if not present:
        out.append(_mk(
            f"Kein DKIM-Schlüssel für {domain}",
            "email_security", Severity.MITTEL, loc,
            "DKIM fehlt - Nachrichten sind nicht kryptografisch signiert",
            cwe="CWE-347",
        ))
        return out
    for d in present:
        selector = str(d.get("selector", "?"))
        try:
            bits = int(d.get("key_bits", 0))
        except (TypeError, ValueError):
            bits = 0
        if 0 < bits < MIN_DKIM_BITS:
            out.append(_mk(
                f"DKIM-Schlüssel zu schwach ({bits} Bit, Selector {selector}): {domain}",
                "crypto_weakness", Severity.HOCH, loc,
                f"key_bits={bits} - mindestens {MIN_DKIM_BITS}, empfohlen {WEAK_DKIM_BITS}",
                cwe="CWE-326",
            ))
        elif MIN_DKIM_BITS <= bits < WEAK_DKIM_BITS:
            out.append(_mk(
                f"DKIM-Schlüssel nicht mehr zeitgemäß ({bits} Bit, Selector {selector}): {domain}",
                "crypto_weakness", Severity.NIEDRIG, loc,
                f"key_bits={bits} - empfohlen sind {WEAK_DKIM_BITS} Bit", cwe="CWE-326",
            ))
    return out


def analyze_email_security(data: dict[str, Any]) -> list[Finding]:
    """Führt alle E-Mail-Security-Prüfungen aus und liefert die Findings."""
    if not isinstance(data, dict):
        return []
    domain = str(data.get("domain", "Domain"))
    findings: list[Finding] = []
    findings += _analyze_spf(data.get("spf"), domain)
    findings += _analyze_dmarc(data.get("dmarc"), domain)
    findings += _analyze_dkim(data.get("dkim"), domain)
    return findings
