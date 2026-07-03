"""Tool: Azure-Export offline analysieren."""

from __future__ import annotations

from ..analyzers import analyze_azure
from .base import FileAnalysisTool


class AnalyzeAzureTool(FileAnalysisTool):
    name = "analyze_azure"
    label = "Azure-Analyse"
    description = (
        "Analysiert einen bereitgestellten Azure-Export (JSON) rein defensiv und "
        "erfasst typische Cloud-Risiken als Findings: "
        "öffentliche/unverschlüsselte Storage-Accounts, schwache "
        "TLS-Mindestversion, NSGs mit 0.0.0.0/0 auf sensiblen Ports, VMs mit "
        "Public IP oder veraltetem OS, öffentlich erreichbare Key Vaults und "
        "Azure-SQL-Server ohne TDE, zu viele Subscription-Owner. Keine "
        "Live-Verbindung zur Subscription - nur die lokale Datei im Scope. "
        "Identitäts-/M365-Themen deckt analyze_entra ab."
    )
    analyzer = staticmethod(analyze_azure)
