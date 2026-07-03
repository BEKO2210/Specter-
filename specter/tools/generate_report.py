"""Tool: Bericht erzeugen (Markdown + JSON) und optional Draft-PR-Inhalte."""

from __future__ import annotations

from typing import Any

from ..audit import AuditLog
from ..config import Config
from ..remediation import draft_pr
from ..report import write_reports
from ..report_export import write_html
from ..state import EngagementState
from .base import ToolResult


class GenerateReportTool:
    name = "generate_report"
    active = False

    def __init__(self, config: Config, state: EngagementState, audit: AuditLog) -> None:
        self.config = config
        self.state = state
        self.audit = audit

    @property
    def spec(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": (
                "Erzeugt den Abschlussbericht (Markdown + JSON) aus Asset-Graph, "
                "Findings und Angriffspfaden und schreibt ihn nach reports/. "
                "Mit include_pr_drafts=true werden zusätzlich Draft-Pull-Request-"
                "Texte (Titel + Body) je Finding zurückgegeben. Als letzten "
                "Schritt der Prüfung aufrufen."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "include_pr_drafts": {
                        "type": "boolean",
                        "description": "Zusätzlich Draft-PR-Texte je Finding ausgeben.",
                    }
                },
            },
        }

    def run(self, arguments: dict[str, Any]) -> ToolResult:
        include_drafts = bool(arguments.get("include_pr_drafts", False))
        paths = write_reports(
            self.config, self.state.assets, self.state.findings,
            self.state.attack_paths, scanner_runs=self.state.scanner_runs,
            delta=self.state.delta,
        )
        html_path = write_html(
            self.config, self.state.assets, self.state.findings,
            self.state.attack_paths, scanner_runs=self.state.scanner_runs,
            delta=self.state.delta,
        )
        self.audit.record(
            "generate_report",
            markdown=str(paths["markdown"]),
            json=str(paths["json"]),
            html=str(html_path),
            findings=len(self.state.findings),
            attack_paths=len(self.state.attack_paths),
        )
        out = [
            "Bericht geschrieben:",
            f"  Markdown: {paths['markdown']}",
            f"  JSON:     {paths['json']}",
            f"  HTML:     {html_path}  (im Browser -> Drucken -> Als PDF speichern)",
            f"Findings: {len(self.state.findings)}  ·  "
            f"Angriffspfade: {len(self.state.attack_paths)}",
        ]
        if include_drafts and len(self.state.findings):
            out.append("\nDraft-Pull-Requests (Fix-Vorschläge):")
            for f in self.state.findings.all():
                pr = draft_pr(f)
                out.append(f"\n--- {f.id} ---\nTitel: {pr['title']}\n{pr['body']}")
        return ToolResult("\n".join(out))
