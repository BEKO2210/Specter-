"""Basisklassen und Registry für Agenten-Werkzeuge."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from ..audit import AuditLog
from ..config import Config
from ..safety import SafetyPolicy
from ..state import EngagementState


@dataclass
class ToolResult:
    """Rückgabe eines Tools an den Agenten."""

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


class SafeTool:
    """Robuste Hülle um ein Tool.

    Sie erzwingt zwei fail-safe-Eigenschaften für die gesamte Werkzeugschicht
    an einer einzigen Stelle:

    1. **Argument-Normalisierung:** Der Tool-Vertrag erwartet ein JSON-Objekt.
       Liefert ein fehlgeleiteter Aufrufer (oder ein fehlerhafter Tool-Call)
       etwas anderes — ``None``, eine Liste, einen String —, wird daraus eine
       leere Argumentliste statt eines ``AttributeError`` beim ``.get()``.
    2. **Ausnahme-Isolierung:** Kein einzelnes Tool darf den gesamten
       Audit-Lauf abbrechen. Jede unerwartete Ausnahme wird zu einem
       ``is_error``-Ergebnis, das der Agent sieht und aus dem er sich erholen
       kann; der Vorfall wird zusätzlich im Audit-Log vermerkt.
    """

    def __init__(self, inner: Tool, audit: AuditLog) -> None:
        self._inner = inner
        self._audit = audit
        self.name = inner.name

    @property
    def inner(self) -> Tool:
        """Das umhüllte Tool (z. B. für gezielte Introspektion/Tests)."""
        return self._inner

    @property
    def spec(self) -> dict[str, Any]:
        return self._inner.spec

    @property
    def active(self) -> bool:
        return self._inner.active

    def run(self, arguments: Any) -> ToolResult:
        args = arguments if isinstance(arguments, dict) else {}
        try:
            return self._inner.run(args)
        except Exception as exc:  # fail-safe: kein Tool bricht den Lauf ab
            self._audit.record(
                "tool.exception", tool=self.name,
                error=f"{type(exc).__name__}: {exc}"[:500],
            )
            return ToolResult(
                f"Tool '{self.name}' fehlgeschlagen ({type(exc).__name__}): {exc}. "
                "Der Lauf wird fortgesetzt.",
                is_error=True,
            )


def build_registry(
    config: Config,
    policy: SafetyPolicy,
    audit: AuditLog,
    state: EngagementState,
) -> dict[str, Tool]:
    """Erzeugt alle verfügbaren Tools und gibt sie als Name->Tool-Map zurück."""
    # Import hier, um Zirkularimporte zu vermeiden.
    from .analyze_ad import AnalyzeAdTool
    from .analyze_aws import AnalyzeAwsTool
    from .analyze_azure import AnalyzeAzureTool
    from .analyze_backup import AnalyzeBackupTool
    from .analyze_container import AnalyzeContainerTool
    from .analyze_database import AnalyzeDatabaseTool
    from .analyze_dependencies import AnalyzeDependenciesTool
    from .analyze_dns import AnalyzeDnsTool
    from .analyze_email_security import AnalyzeEmailSecurityTool
    from .analyze_entra import AnalyzeEntraTool
    from .analyze_firewall import AnalyzeFirewallTool
    from .analyze_http_headers import AnalyzeHttpHeadersTool
    from .analyze_tls import AnalyzeTlsTool
    from .analyze_exchange import AnalyzeExchangeTool
    from .code_scan import CodeScanTool
    from .correlate_paths import CorrelatePathsTool
    from .generate_report import GenerateReportTool
    from .open_pull_requests import OpenPullRequestsTool
    from .read_file import ReadFileTool
    from .record_finding import RecordFindingTool
    from .register_asset import RegisterAssetTool
    from .retest import RetestTool
    from .run_command import RunCommandTool
    from .run_scanner import RunScannerTool

    tools: list[Tool] = [
        # Recon / Augen
        RegisterAssetTool(state, audit),
        ReadFileTool(config, policy, audit),
        CodeScanTool(config, policy, audit, state),
        # Offline-Analyse bereitgestellter Daten (AD/Exchange/Entra-ID)
        AnalyzeAdTool(config, policy, audit, state),
        AnalyzeExchangeTool(config, policy, audit, state),
        AnalyzeEntraTool(config, policy, audit, state),
        AnalyzeAwsTool(config, policy, audit, state),
        AnalyzeAzureTool(config, policy, audit, state),
        AnalyzeEmailSecurityTool(config, policy, audit, state),
        AnalyzeDnsTool(config, policy, audit, state),
        AnalyzeDatabaseTool(config, policy, audit, state),
        AnalyzeContainerTool(config, policy, audit, state),
        AnalyzeDependenciesTool(config, policy, audit, state),
        AnalyzeFirewallTool(config, policy, audit, state),
        AnalyzeTlsTool(config, policy, audit, state),
        AnalyzeBackupTool(config, policy, audit, state),
        AnalyzeHttpHeadersTool(config, policy, audit, state),
        # Aktiv / Hände
        RunCommandTool(config, policy, audit),
        RunScannerTool(config, policy, audit, state),
        # Findings-Analyse -> Korrelation -> Fix & Report
        RecordFindingTool(state, audit),
        CorrelatePathsTool(state, audit),
        RetestTool(config, policy, audit, state),
        GenerateReportTool(config, state, audit),
        OpenPullRequestsTool(config, audit, state),
    ]
    # Jedes Tool in die fail-safe-Hülle legen (Argument-Normalisierung +
    # Ausnahme-Isolierung an einer zentralen Stelle).
    return {t.name: SafeTool(t, audit) for t in tools}
