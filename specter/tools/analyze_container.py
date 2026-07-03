"""Tool: Container-/Docker-Konfigurations-Export offline analysieren."""

from __future__ import annotations

from typing import Any

from ..analyzers import analyze_container
from ..container_live import coerce_container_export
from .base import FileAnalysisTool


class AnalyzeContainerTool(FileAnalysisTool):
    name = "analyze_container"
    label = "Container-Analyse"
    description = (
        "Analysiert einen bereitgestellten Docker-/Container-"
        "Konfigurationsexport rein defensiv und erfasst Fehlkonfigurationen "
        "als Findings: privilegierte Container, gemountetes Docker-Socket, "
        "Host-Networking, gefährliche Capabilities, Lauf als root, ungepinnte "
        ":latest-Images und auf allen Interfaces veröffentlichte Ports. "
        "Akzeptiert sowohl die rohe `docker inspect`-Ausgabe (Liste) als auch "
        "den normalisierten Export. Keine Live-Abfrage - nur die lokale Datei "
        "im Scope."
    )
    analyzer = staticmethod(analyze_container)

    def _coerce(self, data: Any) -> Any:
        return coerce_container_export(data)
