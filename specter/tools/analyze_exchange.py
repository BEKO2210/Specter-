"""Tool: Exchange-Daten offline/passiv analysieren."""

from __future__ import annotations

from ..analyzers import analyze_exchange
from .base import FileAnalysisTool


class AnalyzeExchangeTool(FileAnalysisTool):
    name = "analyze_exchange"
    label = "Exchange-Analyse"
    description = (
        "Analysiert bereitgestellte Exchange-Daten (JSON: Version/Build, extern "
        "erreichbare Dienste, TLS, HTTP-Header) rein defensiv und erfasst Risiken "
        "als Findings: veraltete Version (ProxyLogon/ProxyShell-Ära), extern "
        "erreichbares ECP, schwache TLS-Protokolle, fehlende Sicherheits-Header. "
        "Keine Live-Ausnutzung - nur die lokale Datei im Scope."
    )
    analyzer = staticmethod(analyze_exchange)
