"""Tool: Container-/Docker-Konfigurations-Export offline analysieren."""

from __future__ import annotations

from ..analyzers import analyze_container
from .base import FileAnalysisTool


class AnalyzeContainerTool(FileAnalysisTool):
    name = "analyze_container"
    label = "Container-Analyse"
    description = (
        "Analysiert einen bereitgestellten (normalisierten) "
        "Docker-/Container-Konfigurationsexport rein defensiv und erfasst "
        "Fehlkonfigurationen als Findings: privilegierte Container, gemountetes "
        "Docker-Socket, Host-Networking, gefährliche Capabilities, Lauf als root, "
        "ungepinnte :latest-Images und auf allen Interfaces veröffentlichte "
        "Ports. Keine Live-Abfrage - nur die lokale Datei im Scope."
    )
    analyzer = staticmethod(analyze_container)
