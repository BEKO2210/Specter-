"""Tool: Entra-ID-/Microsoft-365-Export offline analysieren."""

from __future__ import annotations

from ..analyzers import analyze_entra
from .base import FileAnalysisTool


class AnalyzeEntraTool(FileAnalysisTool):
    name = "analyze_entra"
    label = "Entra-ID-/M365-Analyse"
    description = (
        "Analysiert einen bereitgestellten Entra-ID-/Microsoft-365-Export (JSON) "
        "rein defensiv und erfasst typische M365-Risiken als Findings: fehlende "
        "MFA-Erzwingung/Conditional Access, aktive Legacy-Authentifizierung, zu "
        "viele Global Admins, privilegierte Konten ohne MFA, überprivilegierte "
        "App-Registrierungen, anonyme Freigabelinks. Keine Live-Verbindung - nur "
        "die lokale Datei im Scope."
    )
    analyzer = staticmethod(analyze_entra)
