"""Tool: Abhängigkeits-/SCA-Export (Dependencies + Advisories) offline analysieren."""

from __future__ import annotations

from ..analyzers import analyze_dependencies
from .base import FileAnalysisTool


class AnalyzeDependenciesTool(FileAnalysisTool):
    name = "analyze_dependencies"
    label = "SCA-/Abhängigkeits-Analyse"
    description = (
        "Analysiert einen bereitgestellten Abhängigkeits-Export (JSON) gegen eine "
        "lokal mitgelieferte Advisory-/CVE-Liste rein defensiv (Software "
        "Composition Analysis). Erfasst als Findings: bekannte verwundbare "
        "Paketversionen (Log4Shell-Klasse), nicht mehr gepflegte (deprecated) "
        "Pakete und ungepinnte Versionen. Keine Abfrage von Paket-Registries oder "
        "CVE-Feeds, keine Ausnutzung - nur die lokale Datei im Scope."
    )
    analyzer = staticmethod(analyze_dependencies)
