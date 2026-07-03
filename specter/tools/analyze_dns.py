"""Tool: DNS-Sicherheits-Export (DNSSEC/CAA/AXFR) offline analysieren."""

from __future__ import annotations

from ..analyzers import analyze_dns
from .base import FileAnalysisTool


class AnalyzeDnsTool(FileAnalysisTool):
    name = "analyze_dns"
    label = "DNS-Sicherheitsanalyse"
    description = (
        "Analysiert einen bereitgestellten Export der DNS-Konfiguration einer "
        "Domain rein defensiv und erfasst DNS-Sicherheitslücken als Findings: "
        "fehlendes DNSSEC (ad-Flag), fehlende CAA-Records, offener Zonentransfer "
        "(AXFR), Wildcard-Einträge sowie dangling CNAMEs "
        "(Subdomain-Takeover-Risiko). Keine Live-Abfrage - nur die lokale Datei "
        "im Scope."
    )
    analyzer = staticmethod(analyze_dns)
