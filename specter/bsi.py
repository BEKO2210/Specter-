"""Mapping von Findings auf BSI-IT-Grundschutz-Bausteine.

Ordnet jedes Finding einem passenden Baustein des BSI-IT-Grundschutz-
Kompendiums zu und liefert eine nachvollziehbare, kundentaugliche Struktur:
Finding-ID, Risiko, betroffener Bereich, empfohlene Massnahme, BSI-Bezug,
Prioritaet, Evidenz sowie Einschraenkungen/Annahmen.

Hinweis: Die Zuordnung ist eine sachkundige Orientierung an den Bausteinen des
BSI-IT-Grundschutz-Kompendiums, kein zertifizierter Konformitaetsnachweis.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .findings import Finding, Severity
from .remediation import remediation_for

# Finding-Kategorie -> (Baustein-ID, Baustein-Titel).
CATEGORY_TO_BSI: dict[str, tuple[str, str]] = {
    "secret_exposure": ("ORP.4", "Identitaets- und Berechtigungsmanagement"),
    "injection": ("APP.3.1", "Webanwendungen und Webservices"),
    "auth_weakness": ("ORP.4", "Identitaets- und Berechtigungsmanagement"),
    "access_control": ("ORP.4", "Identitaets- und Berechtigungsmanagement"),
    "crypto_weakness": ("CON.1", "Kryptokonzept"),
    "misconfiguration": ("SYS.1.1", "Allgemeiner Server"),
    "cloud_storage": ("OPS.2.2", "Cloud-Nutzung"),
    "transport_security": ("CON.1", "Kryptokonzept"),
    "deserialization": ("APP.3.1", "Webanwendungen und Webservices"),
    "exposed_service": ("NET.1.1", "Netzarchitektur und -design"),
    "sensitive_data": ("CON.2", "Datenschutz"),
    "remote_access": ("OPS.1.2.5", "Fernwartung"),
    "default_credentials": ("ORP.4", "Identitaets- und Berechtigungsmanagement"),
    "outdated_component": ("OPS.1.1.3", "Patch- und Aenderungsmanagement"),
    "personal_data": ("CON.2", "Datenschutz"),
    "other": ("ISMS.1", "Sicherheitsmanagement"),
}

# Quelle -> zusaetzlicher, spezifischer Baustein.
SOURCE_TO_BSI: dict[str, tuple[str, str]] = {
    "ad_analyzer": ("APP.2.2", "Active Directory Domain Services"),
    "exchange_analyzer": ("APP.5.2", "Microsoft Exchange und Outlook"),
}

# Einschraenkung/Annahme je Erkenntnisquelle.
SOURCE_LIMITATION: dict[str, str] = {
    "static_scan": "Heuristischer Mustertreffer aus statischer Analyse - manuell zu verifizieren.",
    "ad_analyzer": "Bewertung ausschliesslich anhand des bereitgestellten AD-Exports; kein Live-Abgleich.",
    "exchange_analyzer": "Bewertung anhand bereitgestellter Exchange-Daten; Build-Einschaetzung ist heuristisch.",
    "nmap": "Momentaufnahme des Netzwerk-Scans zum Pruefzeitpunkt.",
    "nikto": "Automatischer Webserver-Scan - moegliche Falsch-Positive, manuell zu pruefen.",
    "agent": "Vom Pruefer bestaetigtes Finding.",
    "manual": "Manuell erfasstes Finding.",
}


def priority_label(severity: Severity) -> str:
    return {
        Severity.KRITISCH: "Sehr hoch",
        Severity.HOCH: "Hoch",
        Severity.MITTEL: "Mittel",
        Severity.NIEDRIG: "Niedrig",
        Severity.INFO: "Information",
    }[severity]


@dataclass
class BsiMapping:
    finding_id: str
    risiko: str
    bereich: str
    massnahme: str
    bsi_bezug: str
    prioritaet: str
    evidenz: str
    einschraenkungen: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "risiko": self.risiko,
            "bereich": self.bereich,
            "massnahme": self.massnahme,
            "bsi_bezug": self.bsi_bezug,
            "prioritaet": self.prioritaet,
            "evidenz": self.evidenz,
            "einschraenkungen": self.einschraenkungen,
        }


def bsi_reference(finding: Finding) -> str:
    baustein, titel = CATEGORY_TO_BSI.get(
        finding.category, CATEGORY_TO_BSI["other"]
    )
    ref = f"{baustein} {titel}"
    extra = SOURCE_TO_BSI.get(finding.source)
    if extra:
        ref += f"; {extra[0]} {extra[1]}"
    return ref


def limitation_for(finding: Finding) -> str:
    return SOURCE_LIMITATION.get(
        finding.source, "Bewertung zum Pruefzeitpunkt; Kontext des Betreibers beachten."
    )


def map_finding(finding: Finding) -> BsiMapping:
    return BsiMapping(
        finding_id=finding.id,
        risiko=f"{finding.title} ({finding.category_label})",
        bereich=finding.asset,
        massnahme=remediation_for(finding),
        bsi_bezug=bsi_reference(finding),
        prioritaet=priority_label(finding.severity),
        evidenz=finding.evidence or finding.location or "n/a",
        einschraenkungen=limitation_for(finding),
    )


def map_findings(findings: list[Finding]) -> list[BsiMapping]:
    return [map_finding(f) for f in findings]
