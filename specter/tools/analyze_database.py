"""Tool: Datenbank-Expositions-Export offline analysieren."""

from __future__ import annotations

from ..analyzers import analyze_database
from .base import FileAnalysisTool


class AnalyzeDatabaseTool(FileAnalysisTool):
    name = "analyze_database"
    label = "Datenbank-Analyse"
    description = (
        "Analysiert einen bereitgestellten Export der Datenbank-Landschaft rein "
        "defensiv und erfasst Expositionslücken als Findings: öffentlich "
        "erreichbare DB-Ports, fehlende Authentifizierung (Redis/MongoDB), "
        "Standard-/Default-Zugangsdaten und unverschlüsselten Transport. Keine "
        "Live-Verbindung - nur die lokale Datei im Scope."
    )
    analyzer = staticmethod(analyze_database)
