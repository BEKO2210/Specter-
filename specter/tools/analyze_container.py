"""Tool: Container-/Docker-Konfigurations-Export offline analysieren."""

from __future__ import annotations

import json
from typing import Any

from ..analyzers import analyze_container
from ..audit import AuditLog
from ..config import Config
from ..safety import SafetyPolicy, ScopeViolation
from ..state import EngagementState
from .base import ToolResult


class AnalyzeContainerTool:
    name = "analyze_container"
    active = False

    def __init__(self, config: Config, policy: SafetyPolicy, audit: AuditLog,
                 state: EngagementState) -> None:
        self.config = config
        self.policy = policy
        self.audit = audit
        self.state = state

    @property
    def spec(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": (
                "Analysiert einen bereitgestellten (normalisierten) Docker-/"
                "Container-Konfigurationsexport rein defensiv und erfasst "
                "Fehlkonfigurationen als Findings: privilegierte Container, "
                "gemountetes Docker-Socket, Host-Networking, gefährliche "
                "Capabilities, Lauf als root, ungepinnte :latest-Images und auf "
                "allen Interfaces veröffentlichte Ports. Keine Live-Abfrage - nur "
                "die lokale Datei im Scope."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Pfad zum JSON-Export (im Scope)."},
                },
                "required": ["path"],
            },
        }

    def run(self, arguments: dict[str, Any]) -> ToolResult:
        raw_path = str(arguments.get("path", "")).strip()
        try:
            path = self.policy.check_path(raw_path)
        except ScopeViolation as exc:
            self.audit.record("analyze_container.denied", path=raw_path, reason=str(exc))
            return ToolResult(f"VERWEIGERT: {exc}", is_error=True)
        if not path.is_file():
            return ToolResult(f"Datei existiert nicht: {path}", is_error=True)
        if path.stat().st_size > self.config.max_file_bytes:
            return ToolResult("Datei zu groß.", is_error=True)
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError) as exc:
            self.audit.record("analyze_container.parse_error", path=str(path), reason=str(exc))
            return ToolResult(f"Konnte JSON nicht lesen: {exc}", is_error=True)

        findings = analyze_container(data)
        recorded = self.state.findings.extend(findings)
        self.audit.record("analyze_container.ok", path=str(path),
                          findings=len(findings), recorded=recorded)
        if not findings:
            return ToolResult("Container-Analyse ohne Befunde (oder unbekannte Struktur).")
        lines = [f"Container-Analyse: {len(findings)} Finding(s), {recorded} neu erfasst:"]
        for f in findings[:30]:
            lines.append(f"  [{f.severity.label}] {f.title}")
        return ToolResult("\n".join(lines))
