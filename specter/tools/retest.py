"""Tool: Re-Test gegen einen früheren Bericht (behoben/neu/weiterhin offen)."""

from __future__ import annotations

import datetime as _dt
import json
from typing import Any

from ..audit import AuditLog
from ..config import Config
from ..retest import compute_delta
from ..safety import SafetyPolicy, ScopeViolation
from ..state import EngagementState
from .base import ToolResult


class RetestTool:
    name = "retest"
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
                "Vergleicht die aktuell erfassten Findings mit einem früheren "
                "JSON-Bericht (Re-Test): was wurde behoben, was ist neu, was ist "
                "weiterhin offen (inkl. Alter in Tagen). Der frühere Bericht muss "
                "eine von Specter erzeugte JSON-Datei im Datei-Scope sein. Sinnvoll "
                "nach der Erfassung der aktuellen Findings, vor dem Bericht."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "previous_report": {
                        "type": "string",
                        "description": "Pfad zum früheren JSON-Bericht (im Scope).",
                    },
                },
                "required": ["previous_report"],
            },
        }

    def run(self, arguments: dict[str, Any]) -> ToolResult:
        raw_path = str(arguments.get("previous_report", "")).strip()
        try:
            path = self.policy.check_path(raw_path)
        except ScopeViolation as exc:
            self.audit.record("retest.denied", path=raw_path, reason=str(exc))
            return ToolResult(f"VERWEIGERT: {exc}", is_error=True)
        if not path.is_file():
            return ToolResult(f"Datei existiert nicht: {path}", is_error=True)
        if path.stat().st_size > self.config.max_file_bytes:
            return ToolResult("Datei zu groß.", is_error=True)
        try:
            previous = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError) as exc:
            self.audit.record("retest.parse_error", path=str(path), reason=str(exc))
            return ToolResult(f"Konnte JSON nicht lesen: {exc}", is_error=True)

        delta = compute_delta(previous, self.state.findings, _dt.date.today())
        self.state.delta = delta
        self.audit.record(
            "retest.ok", path=str(path), resolved=len(delta.resolved),
            new=len(delta.new), still_open=len(delta.still_open),
        )
        alter = f" (letzter Bericht vor {delta.aging_days} Tagen)" if delta.aging_days is not None else ""
        lines = [
            f"Re-Test gegen {path.name}{alter}:",
            f"  Behoben:         {len(delta.resolved)}",
            f"  Neu:             {len(delta.new)}",
            f"  Weiterhin offen: {len(delta.still_open)}",
        ]
        return ToolResult("\n".join(lines))
