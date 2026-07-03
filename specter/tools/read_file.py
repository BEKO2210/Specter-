"""Tool: Lokale Datei lesen (White-Box / Code-Audit) - die "Augen" des Agenten."""

from __future__ import annotations

from typing import Any

from ..audit import AuditLog
from ..config import Config
from ..safety import SafetyPolicy, ScopeViolation
from .base import ToolResult


class ReadFileTool:
    name = "read_file"
    active = False

    def __init__(self, config: Config, policy: SafetyPolicy, audit: AuditLog) -> None:
        self.config = config
        self.policy = policy
        self.audit = audit

    @property
    def spec(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": (
                "Liest eine lokale Datei aus dem freigegebenen Zielverzeichnis "
                "für White-Box-Code-Analyse. Gibt den Inhalt mit Zeilennummern "
                "zurück. Nur Pfade innerhalb von filesystem.allowed_paths sind "
                "erlaubt."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Pfad zur Datei (relativ oder absolut).",
                    }
                },
                "required": ["path"],
            },
        }

    def run(self, arguments: dict[str, Any]) -> ToolResult:
        raw_path = str(arguments.get("path", "")).strip()
        try:
            path = self.policy.check_path(raw_path)
        except ScopeViolation as exc:
            self.audit.record("read_file.denied", path=raw_path, reason=str(exc))
            return ToolResult(f"VERWEIGERT: {exc}", is_error=True)

        if not path.is_file():
            self.audit.record("read_file.not_found", path=str(path))
            return ToolResult(f"Datei existiert nicht: {path}", is_error=True)

        size = path.stat().st_size
        if size > self.config.max_file_bytes:
            self.audit.record("read_file.too_large", path=str(path), size=size)
            return ToolResult(
                f"Datei zu groß ({size} Bytes > {self.config.max_file_bytes}).",
                is_error=True,
            )

        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            self.audit.record("read_file.error", path=str(path), reason=str(exc))
            return ToolResult(f"Lesefehler: {exc}", is_error=True)

        self.audit.record("read_file.ok", path=str(path), bytes=size)
        numbered = "\n".join(
            f"{i:>5}\t{line}" for i, line in enumerate(text.splitlines(), start=1)
        )
        return ToolResult(f"# {path}\n{numbered}")
