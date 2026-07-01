"""Tool: Strukturiertes Finding erfassen (Findings-Analyse)."""

from __future__ import annotations

from typing import Any

from ..audit import AuditLog
from ..findings import CATEGORIES, Finding, Severity
from ..state import EngagementState
from .base import ToolResult


class RecordFindingTool:
    name = "record_finding"
    active = False

    def __init__(self, state: EngagementState, audit: AuditLog) -> None:
        self.state = state
        self.audit = audit

    @property
    def spec(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": (
                "Erfasst eine bestaetigte Schwachstelle als strukturiertes "
                "Finding (Schweregrad, Kategorie, betroffenes Asset, Evidenz, "
                "CWE, Owner, Gegenmassnahme). Nutze dies fuer jede belegte "
                "Schwachstelle - es ist die Grundlage fuer Angriffspfad-"
                "Korrelation und Bericht."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "category": {
                        "type": "string",
                        "enum": list(CATEGORIES.keys()),
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["info", "niedrig", "mittel", "hoch", "kritisch"],
                    },
                    "asset": {
                        "type": "string",
                        "description": "Betroffenes Asset (Host, Datei, Endpunkt...).",
                    },
                    "location": {"type": "string", "description": "Datei:Zeile oder Host:Port."},
                    "evidence": {"type": "string", "description": "Konkreter Beleg."},
                    "cwe": {"type": "string", "description": "z. B. CWE-89."},
                    "owner": {"type": "string", "description": "Verantwortliches Team/Person."},
                    "remediation": {"type": "string", "description": "Empfohlene Gegenmassnahme."},
                },
                "required": ["title", "category", "severity", "asset"],
            },
        }

    def run(self, arguments: dict[str, Any]) -> ToolResult:
        try:
            finding = Finding(
                title=str(arguments["title"]).strip(),
                category=str(arguments["category"]).strip(),
                severity=Severity.parse(str(arguments["severity"])),
                asset=str(arguments["asset"]).strip(),
                location=str(arguments.get("location", "")).strip(),
                evidence=str(arguments.get("evidence", "")).strip(),
                cwe=str(arguments.get("cwe", "")).strip(),
                owner=str(arguments.get("owner", "")).strip(),
                remediation=str(arguments.get("remediation", "")).strip(),
                source="agent",
                status="bestaetigt",
            )
        except (KeyError, ValueError) as exc:
            return ToolResult(f"Ungueltiges Finding: {exc}", is_error=True)

        stored, is_new = self.state.findings.add(finding)
        self.audit.record(
            "record_finding",
            id=stored.id,
            severity=stored.severity.label,
            category=stored.category,
            is_new=is_new,
        )
        state = "erfasst" if is_new else "bereits vorhanden"
        return ToolResult(
            f"Finding {state}: {stored.id} [{stored.severity.label}] "
            f"{stored.title}. Findings gesamt: {len(self.state.findings)}."
        )
