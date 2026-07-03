"""Tool: Active-Directory-Export offline analysieren."""

from __future__ import annotations

from ..analyzers import analyze_ad
from .base import FileAnalysisTool


class AnalyzeAdTool(FileAnalysisTool):
    name = "analyze_ad"
    label = "AD-Analyse"
    description = (
        "Analysiert einen bereitgestellten Active-Directory-Export (JSON, eigene "
        "Struktur oder BloodHound-users-Export) rein defensiv und erfasst "
        "typische AD-Risiken als Findings: schwache Passwort-/Lockout-Policy, "
        "gefährliche Gruppenmitgliedschaften, veraltete/deaktivierte Konten, "
        "SPN/Kerberos-Risiken, krbtgt-Alter. Keine Live-Verbindung - nur die "
        "lokale Datei im Scope."
    )
    analyzer = staticmethod(analyze_ad)
