"""Basisklassen und Registry für Agenten-Werkzeuge."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable, Protocol

from ..audit import AuditLog
from ..config import Config
from ..findings import Finding
from ..safety import SafetyPolicy, ScopeViolation
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


class FileAnalysisTool:
    """Gemeinsame Basis aller ``analyze_*``-Datei-Tools.

    Der Ablauf ist bei jedem Offline-Analyzer identisch und lebt deshalb nur
    hier: Pfad gegen den Scope prüfen (fail-closed), Datei- und Größen-Check,
    JSON lesen, Analyzer anwenden, Findings in den Engagement-Zustand
    übernehmen und das Ergebnis knapp fürs Modell formatieren. Die konkreten
    Tools liefern nur noch ``name``, ``label``, ``description`` und den
    Analyzer selbst — dadurch verhalten sich alle Datei-Tools garantiert
    gleich (Audit-Events, Fehlertexte, Limits).

    ``_coerce`` ist der Haken für Roh-Formate: Ein Tool kann dort eine echte
    Vendor-Ausgabe (z. B. ``docker inspect``) erkennen und in die vom
    Analyzer erwartete Struktur normalisieren.
    """

    name: str = ""
    label: str = ""
    description: str = ""
    active = False
    analyzer: Callable[[Any], list[Finding]]

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
            "description": self.description,
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Pfad zum JSON-Export (im Scope)."},
                },
                "required": ["path"],
            },
        }

    def _coerce(self, data: Any) -> Any:
        """Normalisiert Roh-Formate; Standard: Daten unverändert durchreichen."""
        return data

    def run(self, arguments: dict[str, Any]) -> ToolResult:
        raw_path = str(arguments.get("path", "")).strip()
        try:
            path = self.policy.check_path(raw_path)
        except ScopeViolation as exc:
            self.audit.record(f"{self.name}.denied", path=raw_path, reason=str(exc))
            return ToolResult(f"VERWEIGERT: {exc}", is_error=True)
        if not path.is_file():
            return ToolResult(f"Datei existiert nicht: {path}", is_error=True)
        if path.stat().st_size > self.config.max_file_bytes:
            return ToolResult("Datei zu groß.", is_error=True)
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError) as exc:
            self.audit.record(f"{self.name}.parse_error", path=str(path), reason=str(exc))
            return ToolResult(f"Konnte JSON nicht lesen: {exc}", is_error=True)

        findings = type(self).analyzer(self._coerce(data))
        recorded = self.state.findings.extend(findings)
        self.audit.record(f"{self.name}.ok", path=str(path),
                          findings=len(findings), recorded=recorded)
        if not findings:
            return ToolResult(f"{self.label} ohne Befunde (oder unbekannte Struktur).")
        lines = [f"{self.label}: {len(findings)} Finding(s), {recorded} neu erfasst:"]
        for f in findings[:30]:
            lines.append(f"  [{f.severity.label}] {f.title}")
        return ToolResult("\n".join(lines))


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
