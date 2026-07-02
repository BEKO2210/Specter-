"""Basisklassen und Registry fuer Agenten-Werkzeuge."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from ..audit import AuditLog
from ..config import Config
from ..safety import SafetyPolicy
from ..state import EngagementState


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
    config: Config,
    policy: SafetyPolicy,
    audit: AuditLog,
    state: EngagementState,
) -> dict[str, Tool]:
    """Erzeugt alle verfuegbaren Tools und gibt sie als Name->Tool-Map zurueck."""
    # Import hier, um Zirkularimporte zu vermeiden.
    from .analyze_ad import AnalyzeAdTool
    from .analyze_aws import AnalyzeAwsTool
    from .analyze_azure import AnalyzeAzureTool
    from .analyze_backup import AnalyzeBackupTool
    from .analyze_dependencies import AnalyzeDependenciesTool
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
        AnalyzeDependenciesTool(config, policy, audit, state),
        AnalyzeFirewallTool(config, policy, audit, state),
        AnalyzeTlsTool(config, policy, audit, state),
        AnalyzeBackupTool(config, policy, audit, state),
        AnalyzeHttpHeadersTool(config, policy, audit, state),
        # Aktiv / Haende
        RunCommandTool(config, policy, audit),
        RunScannerTool(config, policy, audit, state),
        # Findings-Analyse -> Korrelation -> Fix & Report
        RecordFindingTool(state, audit),
        CorrelatePathsTool(state, audit),
        RetestTool(config, policy, audit, state),
        GenerateReportTool(config, state, audit),
        OpenPullRequestsTool(config, audit, state),
    ]
    return {t.name: t for t in tools}
