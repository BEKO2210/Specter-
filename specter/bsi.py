"""Mapping von Findings auf BSI-IT-Grundschutz-Bausteine.

Ordnet jedes Finding einem passenden Baustein des BSI-IT-Grundschutz-
Kompendiums zu und liefert eine nachvollziehbare, kundentaugliche Struktur:
Finding-ID, Risiko, betroffener Bereich, empfohlene Maßnahme, BSI-Bezug,
Priorität, Evidenz sowie Einschränkungen/Annahmen.

Hinweis: Die Zuordnung ist eine sachkundige Orientierung an den Bausteinen des
BSI-IT-Grundschutz-Kompendiums, kein zertifizierter Konformitätsnachweis.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .findings import Finding, Severity
from .remediation import remediation_for

# Finding-Kategorie -> (Baustein-ID, Baustein-Titel).
CATEGORY_TO_BSI: dict[str, tuple[str, str]] = {
    "secret_exposure": ("ORP.4", "Identitäts- und Berechtigungsmanagement"),
    "injection": ("APP.3.1", "Webanwendungen und Webservices"),
    "auth_weakness": ("ORP.4", "Identitäts- und Berechtigungsmanagement"),
    "access_control": ("ORP.4", "Identitäts- und Berechtigungsmanagement"),
    "crypto_weakness": ("CON.1", "Kryptokonzept"),
    "misconfiguration": ("SYS.1.1", "Allgemeiner Server"),
    "cloud_storage": ("OPS.2.2", "Cloud-Nutzung"),
    "transport_security": ("CON.1", "Kryptokonzept"),
    "deserialization": ("APP.3.1", "Webanwendungen und Webservices"),
    "exposed_service": ("NET.1.1", "Netzarchitektur und -design"),
    "sensitive_data": ("CON.2", "Datenschutz"),
    "remote_access": ("OPS.1.2.5", "Fernwartung"),
    "default_credentials": ("ORP.4", "Identitäts- und Berechtigungsmanagement"),
    "outdated_component": ("OPS.1.1.3", "Patch- und Änderungsmanagement"),
    "personal_data": ("CON.2", "Datenschutz"),
    "email_security": ("APP.5.3", "Allgemeiner E-Mail-Client und -Server"),
    "backup_resilience": ("CON.3", "Datensicherungskonzept"),
    "web_security": ("APP.3.1", "Webanwendungen und Webservices"),
    "dns_security": ("APP.3.6", "DNS-Server"),
    "container_security": ("SYS.1.6", "Container"),
    "other": ("ISMS.1", "Sicherheitsmanagement"),
}

# Quelle -> zusätzlicher, spezifischer Baustein.
SOURCE_TO_BSI: dict[str, tuple[str, str]] = {
    "ad_analyzer": ("APP.2.2", "Active Directory Domain Services"),
    "exchange_analyzer": ("APP.5.2", "Microsoft Exchange und Outlook"),
    "entra_analyzer": ("OPS.2.2", "Cloud-Nutzung"),
    "aws_analyzer": ("OPS.2.2", "Cloud-Nutzung"),
    "azure_analyzer": ("OPS.2.2", "Cloud-Nutzung"),
    "email_security_analyzer": ("APP.5.3", "Allgemeiner E-Mail-Client und -Server"),
    "dependency_analyzer": ("OPS.1.1.3", "Patch- und Änderungsmanagement"),
    "firewall_analyzer": ("NET.3.2", "Firewall"),
    "tls_analyzer": ("CON.1", "Kryptokonzept"),
    "backup_analyzer": ("CON.3", "Datensicherungskonzept"),
    "http_headers_analyzer": ("APP.3.1", "Webanwendungen und Webservices"),
    "dns_analyzer": ("APP.3.6", "DNS-Server"),
    "database_analyzer": ("APP.4.3", "Relationale Datenbanksysteme"),
    "container_analyzer": ("SYS.1.6", "Container"),
}

# Einschränkung/Annahme je Erkenntnisquelle.
SOURCE_LIMITATION: dict[str, str] = {
    "static_scan": "Heuristischer Mustertreffer aus statischer Analyse - manuell zu verifizieren.",
    "ad_analyzer": "Bewertung ausschließlich anhand des bereitgestellten AD-Exports; kein Live-Abgleich.",
    "exchange_analyzer": "Bewertung anhand bereitgestellter Exchange-Daten; Build-Einschätzung ist heuristisch.",
    "entra_analyzer": "Bewertung ausschließlich anhand des bereitgestellten Entra-ID-/M365-Exports; kein Live-Abgleich mit dem Tenant.",
    "aws_analyzer": "Bewertung ausschließlich anhand des bereitgestellten AWS-Exports; kein Live-Abgleich mit dem Konto.",
    "azure_analyzer": "Bewertung ausschließlich anhand des bereitgestellten Azure-Exports; kein Live-Abgleich mit der Subscription.",
    "email_security_analyzer": "Bewertung ausschließlich anhand des bereitgestellten DNS-Exports (SPF/DKIM/DMARC); keine Live-DNS-Abfrage.",
    "dependency_analyzer": "Bewertung ausschließlich anhand des bereitgestellten Abhängigkeits-/Advisory-Exports; kein Live-Abgleich mit Paket-Registries oder CVE-Feeds.",
    "firewall_analyzer": "Bewertung ausschließlich anhand des bereitgestellten Firewall-/VPN-Konfigurationsexports; keine Live-Verbindung zum Gerät.",
    "tls_analyzer": "Bewertung ausschließlich anhand des bereitgestellten TLS-/Zertifikatsexports; kein Live-Handshake. Ablauf gemessen zum Erhebungszeitpunkt.",
    "backup_analyzer": "Bewertung ausschließlich anhand der bereitgestellten Backup-/Resilienz-Angaben; kein Live-Abgleich mit dem Backup-System.",
    "http_headers_analyzer": "Bewertung ausschließlich anhand der bereitgestellten HTTP-Antwort-Header/Cookies; keine Live-Abfrage.",
    "dns_analyzer": "Bewertung ausschließlich anhand des bereitgestellten DNS-Exports (DNSSEC/CAA/AXFR); keine Live-DNS-Abfrage.",
    "database_analyzer": "Bewertung ausschließlich anhand des bereitgestellten Datenbank-Exports (Port/Auth/TLS/Default-Creds); keine Live-Verbindung zur Datenbank.",
    "container_analyzer": "Bewertung ausschließlich anhand des bereitgestellten (normalisierten) docker-inspect-Exports; kein Live-Zugriff auf Daemon/Container.",
    "nmap": "Momentaufnahme des Netzwerk-Scans zum Prüfzeitpunkt.",
    "nikto": "Automatischer Webserver-Scan - mögliche Falsch-Positive, manuell zu prüfen.",
    "agent": "Vom Prüfer bestätigtes Finding.",
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
    maßnahme: str
    bsi_bezug: str
    priorität: str
    evidenz: str
    einschränkungen: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "risiko": self.risiko,
            "bereich": self.bereich,
            "maßnahme": self.maßnahme,
            "bsi_bezug": self.bsi_bezug,
            "priorität": self.priorität,
            "evidenz": self.evidenz,
            "einschränkungen": self.einschränkungen,
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
        finding.source, "Bewertung zum Prüfzeitpunkt; Kontext des Betreibers beachten."
    )


def map_finding(finding: Finding) -> BsiMapping:
    return BsiMapping(
        finding_id=finding.id,
        risiko=f"{finding.title} ({finding.category_label})",
        bereich=finding.asset,
        maßnahme=remediation_for(finding),
        bsi_bezug=bsi_reference(finding),
        priorität=priority_label(finding.severity),
        evidenz=finding.evidence or finding.location or "n/a",
        einschränkungen=limitation_for(finding),
    )


def map_findings(findings: list[Finding]) -> list[BsiMapping]:
    return [map_finding(f) for f in findings]
