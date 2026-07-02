"""Defensive DNS-Sicherheitsanalyse (DNSSEC, CAA, Zonentransfer) aus DNS-Export.

Wertet einen lokalen JSON-Export der DNS-Konfiguration einer Domain aus und
erkennt typische DNS-Schwaechen, ueber die Angreifer Verkehr umleiten, Zertifikate
faelschen oder ganze Zonen abziehen koennen - rein offline, ohne Live-Abfrage,
ohne Ausnutzung. Der Live-Kollektor (`examples/live_email_check.py`) kann die
tatsaechlichen DNSSEC-/CAA-Daten einer echten Domain per DNS-over-HTTPS abgreifen
und in die hier erwartete Struktur bringen.

Erwartete Struktur (alle Felder optional):

    {
      "domain": "musterfirma.de",
      "dnssec": false,                         # DNSSEC aktiv (ad-Flag)?
      "caa": ["0 issue \"letsencrypt.org\""],  # CAA-Records (Liste)
      "wildcard": false,                        # Wildcard-A/AAAA vorhanden?
      "zone_transfer": false,                   # AXFR offen?
      "dangling_cnames": ["alt.musterfirma.de -> bucket.s3.amazonaws.com"]
    }

Fehlt `dnssec`/`caa`, gilt der Schutz als NICHT vorhanden - das ist der haeufigste
Befund im Mittelstand.
"""

from __future__ import annotations

from typing import Any

from ..findings import Finding, Severity


def _mk(title, severity, asset, evidence, *, cwe="", owner="IT-/DNS-Team") -> Finding:
    return Finding(
        title=title, category="dns_security", severity=severity, asset=asset,
        location=asset, evidence=evidence, cwe=cwe, owner=owner,
        source="dns_analyzer", status="offen",
    )


def analyze_dns(data: dict[str, Any]) -> list[Finding]:
    """Fuehrt alle DNS-Sicherheitspruefungen aus und liefert die Findings."""
    if not isinstance(data, dict):
        return []
    domain = str(data.get("domain", "Domain"))
    out: list[Finding] = []

    if not data.get("dnssec"):
        out.append(_mk(
            f"DNSSEC nicht aktiv: {domain}", Severity.MITTEL, f"{domain}/DNSSEC",
            "Kein DNSSEC (ad-Flag) - DNS-Antworten sind nicht signiert, "
            "Cache-Poisoning/Spoofing moeglich", cwe="CWE-345"))

    caa = data.get("caa")
    caa_list = [c for c in caa if str(c).strip()] if isinstance(caa, list) else []
    if not caa_list:
        out.append(_mk(
            f"Keine CAA-Records: {domain}", Severity.NIEDRIG, f"{domain}/CAA",
            "Ohne CAA darf jede Zertifizierungsstelle Zertifikate ausstellen "
            "(Mis-Issuance-Risiko)", cwe="CWE-295"))

    if data.get("zone_transfer"):
        out.append(_mk(
            f"Offener Zonentransfer (AXFR): {domain}", Severity.HOCH,
            f"{domain}/AXFR",
            "AXFR erlaubt - die komplette Zone (alle Hosts/Subdomains) ist "
            "abziehbar", cwe="CWE-200"))

    if data.get("wildcard"):
        out.append(_mk(
            f"Wildcard-DNS-Eintrag (*): {domain}", Severity.NIEDRIG,
            f"{domain}/Wildcard",
            "Wildcard-A/AAAA faengt beliebige Subdomains ab - erschwert "
            "Missbrauchserkennung", cwe="CWE-183"))

    dangling = data.get("dangling_cnames")
    if isinstance(dangling, list):
        for entry in dangling:
            target = str(entry).strip()
            if not target:
                continue
            out.append(_mk(
                f"Dangling CNAME (Subdomain-Takeover-Risiko): {target}",
                Severity.HOCH, f"{domain}/CNAME",
                f"{target} - Ziel nicht mehr in Betrieb; uebernehmbar durch "
                "Angreifer", cwe="CWE-350"))
    return out
