"""Reine Hilfsfunktionen für den Live-DNS-Check (DNS-over-HTTPS -> Export).

Der eigentliche Netzwerkabruf lebt bewusst im Beispiel-Runner
(`examples/live_email_check.py`); hier stehen nur die deterministischen,
testbaren Bausteine: das AD-Flag (DNSSEC) und die CAA-Records aus einer
geparsten dns.google-Antwort ziehen und daraus die Export-Struktur bauen, die
der Offline-Analyzer `analyze_dns` erwartet.

So bleibt die Kernlogik testbar (offline, 100 % Coverage) und identisch zur
Kunden-Analyse - der Live-Check fuettert nur echte, öffentliche DNS-Daten ein.
Reine Leseabfragen öffentlicher DNS-Einträge, kein Eingriff.
"""

from __future__ import annotations

from typing import Any

# DNS-Record-Typ-Nummern (RFC 1035 / RFC 6844).
_TYPE_CAA = 257


def extract_ad_flag(doh_response: Any) -> bool:
    """Liest das AD-Flag (Authenticated Data = DNSSEC validiert) einer DoH-Antwort."""
    if not isinstance(doh_response, dict):
        return False
    return bool(doh_response.get("AD", False))


def extract_caa(doh_response: Any) -> list[str]:
    """Zieht die CAA-Record-Strings aus einer geparsten dns.google-Antwort."""
    if not isinstance(doh_response, dict):
        return []
    out: list[str] = []
    for ans in doh_response.get("Answer", []):
        if isinstance(ans, dict) and ans.get("type") == _TYPE_CAA:
            data = str(ans.get("data", "")).strip()
            if data:
                out.append(data)
    return out


def build_dns_export(domain: str, soa_response: Any, caa_response: Any) -> dict[str, Any]:
    """Setzt die Export-Struktur für `analyze_dns` aus echten DoH-Antworten zusammen."""
    return {
        "domain": domain,
        "dnssec": extract_ad_flag(soa_response),
        "caa": extract_caa(caa_response),
    }
