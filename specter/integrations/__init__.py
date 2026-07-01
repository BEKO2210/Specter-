"""Opt-in-Integrationen fuer ausgehende Aktionen (z. B. GitHub-Draft-PRs).

Standardmaessig passiert nichts nach aussen: Specter arbeitet offline. Eine
Integration wird erst aktiv, wenn sie in scope.yaml ausdruecklich freigegeben
ist und (fuer GitHub) ein API-Token vorliegt.
"""

from .github_pr import (
    GitHubError, HttpGitHubClient, PullRequestDraft,
    build_drafts, open_draft_prs, write_drafts,
)

__all__ = [
    "GitHubError", "HttpGitHubClient", "PullRequestDraft",
    "build_drafts", "open_draft_prs", "write_drafts",
]
