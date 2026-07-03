"""Tool: Angriffspfade korrelieren (toxische Kombinationen)."""

from __future__ import annotations

from typing import Any

from ..attack_paths import correlate
from ..audit import AuditLog
from ..findings import Severity
from ..state import EngagementState
from .base import ToolResult


class CorrelatePathsTool:
    name = "correlate_paths"
    active = False

    def __init__(self, state: EngagementState, audit: AuditLog) -> None:
        self.state = state
        self.audit = audit

    @property
    def spec(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": (
                "Korreliert die bisher erfassten Findings über den Asset-Graph "
                "zu Angriffspfaden ('toxische Kombinationen'). Ruft die "
                "regelbasierte Engine auf und liefert die gefundenen Pfade "
                "zurück. Sinnvoll, nachdem mehrere Findings erfasst wurden."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "min_severity": {
                        "type": "string",
                        "enum": ["info", "niedrig", "mittel", "hoch", "kritisch"],
                        "description": "Mindest-Schweregrad der einbezogenen Findings (Standard: mittel).",
                    }
                },
            },
        }

    def run(self, arguments: dict[str, Any]) -> ToolResult:
        raw = str(arguments.get("min_severity", "mittel"))
        try:
            min_sev = Severity.parse(raw)
        except ValueError:
            min_sev = Severity.MITTEL

        paths = correlate(self.state.findings, self.state.assets, min_severity=min_sev)
        self.state.attack_paths = paths
        self.audit.record("correlate_paths", count=len(paths), min_severity=min_sev.label)

        if not paths:
            return ToolResult(
                "Keine Angriffspfade korreliert. Mehr/andere Findings nötig "
                "(z. B. exponierter Dienst + Secret, Injection + Datenspeicher)."
            )
        lines = [f"{len(paths)} Angriffspfad(e) korreliert:"]
        for i, p in enumerate(paths, start=1):
            lines.append(f"  AP-{i} [{p.severity.label}] {p.title} "
                         f"(Findings: {', '.join(p.finding_ids)})")
        return ToolResult("\n".join(lines))
