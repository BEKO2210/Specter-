"""Basisklassen und Registry fuer Agenten-Werkzeuge."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from ..audit import AuditLog
from ..config import Config
from ..safety import SafetyPolicy


@dataclass
class ToolResult:
    """Rueckgabe eines Tools an den Agenten."""

    content: str
    is_error: bool = False


class Tool(Protocol):
    name: str

    @property
    def spec(self) -> dict[str, Any]:
        """Anthropic tool-definition (name, description, input_schema)."""
        ...

    @property
    def active(self) -> bool:
        """True, wenn das Tool aktiv in fremde Systeme eingreift (Scan/Befehl)."""
        ...

    def run(self, arguments: dict[str, Any]) -> ToolResult:
        ...


def build_registry(
    config: Config, policy: SafetyPolicy, audit: AuditLog
) -> dict[str, Tool]:
    """Erzeugt alle verfuegbaren Tools und gibt sie als Name->Tool-Map zurueck."""
    # Import hier, um Zirkularimporte zu vermeiden.
    from .code_scan import CodeScanTool
    from .read_file import ReadFileTool
    from .run_command import RunCommandTool

    tools: list[Tool] = [
        ReadFileTool(config, policy, audit),
        CodeScanTool(config, policy, audit),
        RunCommandTool(config, policy, audit),
    ]
    return {t.name: t for t in tools}
