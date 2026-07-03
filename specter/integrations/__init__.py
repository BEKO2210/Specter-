"""Opt-in-Integrationen für ausgehende Aktionen (z. B. GitHub-Draft-PRs).

Standardmäßig passiert nichts nach außen: Specter arbeitet offline. Eine
Integration wird erst aktiv, wenn sie in scope.yaml ausdrücklich freigegeben
ist und (für GitHub) ein API-Token vorliegt.
"""

from .github_pr import (
    GitHubError, HttpGitHubClient, PullRequestDraft,
    build_drafts, open_draft_prs, write_drafts,
)

__all__ = [
    "GitHubError", "HttpGitHubClient", "PullRequestDraft",
    "build_drafts", "open_draft_prs", "write_drafts",
]
