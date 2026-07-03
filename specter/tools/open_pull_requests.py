"""Tool: Draft-Pull-Requests aus Findings erzeugen (offline oder GitHub-online)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable

from ..audit import AuditLog
from ..config import Config
from ..integrations import (
    HttpGitHubClient, build_drafts, open_draft_prs, write_drafts,
)
from ..state import EngagementState
from .base import ToolResult

ApprovalFn = Callable[[str], bool]
ClientFactory = Callable[[str, str], Any]


class OpenPullRequestsTool:
    name = "open_pull_requests"
    active = True

    def __init__(
        self,
        config: Config,
        audit: AuditLog,
        state: EngagementState,
        approval_fn: ApprovalFn | None = None,
        client_factory: ClientFactory | None = None,
        output_dir: str | Path = "reports/pull-requests",
    ) -> None:
        self.config = config
        self.audit = audit
        self.state = state
        self.approval_fn = approval_fn or (lambda _cmd: True)
        self.client_factory = client_factory or (
            lambda repo, token: HttpGitHubClient(repo, token)
        )
        self.output_dir = output_dir

    @property
    def spec(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": (
                "Erzeugt aus den erfassten Findings fertige Draft-Pull-Request-"
                "Texte. Standardmäßig OFFLINE als Markdown-Dateien (nichts "
                "verlässt das Haus). Nur wenn integrations.github in scope.yaml "
                "aktiviert ist und ein Token vorliegt, werden zusätzlich echte "
                "GitHub-Draft-PRs eröffnet (kein Auto-Merge, kein Auto-Apply). "
                "Vor dem Online-Schritt wird eine Freigabe eingeholt."
            ),
            "input_schema": {"type": "object", "properties": {}},
        }

    def run(self, arguments: dict[str, Any]) -> ToolResult:
        findings = self.state.findings.all()
        if not findings:
            return ToolResult("Keine Findings - keine Pull-Requests zu erzeugen.")

        drafts = build_drafts(findings)
        paths = write_drafts(drafts, self.output_dir)
        self.audit.record("open_pull_requests.offline", count=len(paths))
        lines = [
            f"{len(paths)} Draft-PR-Text(e) offline geschrieben nach {self.output_dir}/.",
        ]

        gh = self.config.github
        if not gh.enabled:
            lines.append("GitHub-Integration nicht aktiviert (offline-only).")
            return ToolResult("\n".join(lines))
        if not gh.repo:
            lines.append("Kein Repository konfiguriert (integrations.github.repo).")
            return ToolResult("\n".join(lines))

        token = os.environ.get(gh.token_env, "")
        if not token:
            lines.append(f"Kein Token in ${gh.token_env} - kein Online-Schritt.")
            return ToolResult("\n".join(lines))

        action = f"{len(drafts)} Draft-PR(s) in {gh.repo} eröffnen"
        if not self.approval_fn(action):
            lines.append("Online-Schritt vom Benutzer abgelehnt (nur offline).")
            self.audit.record("open_pull_requests.rejected_by_user", repo=gh.repo)
            return ToolResult("\n".join(lines))

        client = self.client_factory(gh.repo, token)
        results = open_draft_prs(gh, drafts, client)
        ok = [r for r in results if r["url"]]
        failed = [r for r in results if r["error"]]
        self.audit.record("open_pull_requests.online", repo=gh.repo,
                          opened=len(ok), failed=len(failed))
        lines.append(f"GitHub ({gh.repo}): {len(ok)} Draft-PR(s) eröffnet, "
                     f"{len(failed)} fehlgeschlagen.")
        for r in ok[:20]:
            lines.append(f"  {r['finding_id']}: {r['url']}")
        for r in failed[:10]:
            lines.append(f"  [Fehler] {r['finding_id']}: {r['error']}")
        return ToolResult("\n".join(lines))
