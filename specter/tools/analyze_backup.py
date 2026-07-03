"""Tool: Backup-/Ransomware-Resilienz-Export offline analysieren."""

from __future__ import annotations

import json
from typing import Any

from ..analyzers import analyze_backup
from ..audit import AuditLog
from ..config import Config
from ..safety import SafetyPolicy, ScopeViolation
from ..state import EngagementState
from .base import ToolResult


class AnalyzeBackupTool:
    name = "analyze_backup"
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
                "Analysiert einen bereitgestellten Backup-/Resilienz-Export (JSON) "
                "rein defensiv und erfasst Ransomware-Resilienzlücken als Findings: "
                "zu wenige Kopien (3-2-1), fehlendes offline-/Immutable-Backup, keine "
                "Offsite-Kopie, ungetestete Wiederherstellung, Backup-Konsole ohne "
                "MFA, unverschlüsselte Backups, zu kurze Aufbewahrung und fehlendes "
                "Wiederanlaufkonzept. Kein Live-Abgleich mit dem Backup-System, keine "
                "Ausnutzung - nur die lokale Datei im Scope."
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
            self.audit.record("analyze_backup.denied", path=raw_path, reason=str(exc))
            return ToolResult(f"VERWEIGERT: {exc}", is_error=True)
        if not path.is_file():
            return ToolResult(f"Datei existiert nicht: {path}", is_error=True)
        if path.stat().st_size > self.config.max_file_bytes:
            return ToolResult("Datei zu groß.", is_error=True)
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError) as exc:
            self.audit.record("analyze_backup.parse_error", path=str(path), reason=str(exc))
            return ToolResult(f"Konnte JSON nicht lesen: {exc}", is_error=True)

        findings = analyze_backup(data)
        recorded = self.state.findings.extend(findings)
        self.audit.record("analyze_backup.ok", path=str(path),
                          findings=len(findings), recorded=recorded)
        if not findings:
            return ToolResult("Backup-/Resilienzanalyse ohne Befunde (oder unbekannte Struktur).")
        lines = [f"Backup-/Resilienzanalyse: {len(findings)} Finding(s), {recorded} neu erfasst:"]
        for f in findings[:30]:
            lines.append(f"  [{f.severity.label}] {f.title}")
        return ToolResult("\n".join(lines))
