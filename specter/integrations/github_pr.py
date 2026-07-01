"""GitHub-Draft-Pull-Requests aus Findings erzeugen.

Zwei Betriebsarten:

  * OFFLINE (Standard, immer verfuegbar): fuer jedes Finding wird ein fertiger
    Pull-Request-Text als Markdown-Datei geschrieben. Nichts verlaesst das Haus.
  * ONLINE (opt-in): sofern integrations.github in scope.yaml aktiviert und ein
    Token gesetzt ist, wird pro Finding ein echter Draft-PR eroeffnet - ein
    neuer Branch mit einem Remediation-Trackingdokument plus PR (kein Auto-Merge,
    kein Auto-Apply; ein Mensch prueft und setzt um).

Der Netzwerkzugriff ist hinter einem Client gekapselt (HttpGitHubClient), damit
die Logik ohne echten API-Zugriff testbar bleibt.
"""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..config import GitHubIntegration
from ..findings import Finding
from ..remediation import draft_pr

_API_ROOT = "https://api.github.com"


class GitHubError(Exception):
    """Fehler bei einer GitHub-API-Aktion."""


@dataclass
class PullRequestDraft:
    finding_id: str
    title: str
    body: str

    @property
    def doc_path(self) -> str:
        return f"security/specter/{self.finding_id}.md"


def build_drafts(findings: list[Finding]) -> list[PullRequestDraft]:
    """Erzeugt fuer jedes Finding einen PR-Entwurf (Titel + Body)."""
    drafts: list[PullRequestDraft] = []
    for f in findings:
        pr = draft_pr(f)
        drafts.append(PullRequestDraft(finding_id=f.id, title=pr["title"], body=pr["body"]))
    return drafts


def write_drafts(drafts: list[PullRequestDraft], directory: str | Path) -> list[Path]:
    """OFFLINE: schreibt jeden PR-Entwurf als Markdown-Datei."""
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for d in drafts:
        path = out / f"pr-{d.finding_id}.md"
        path.write_text(f"# {d.title}\n\n{d.body}\n", encoding="utf-8")
        paths.append(path)
    return paths


class HttpGitHubClient:
    """Duenner GitHub-REST-Client (urllib). Nur die benoetigten Endpunkte."""

    def __init__(self, repo: str, token: str) -> None:
        self.repo = repo
        self.token = token

    def _api(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        url = f"{_API_ROOT}{path}"
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self.token}")
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("User-Agent", "specter-security-agent")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
                body = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:300]
            raise GitHubError(f"GitHub {method} {path}: HTTP {exc.code} {detail}") from exc
        except urllib.error.URLError as exc:
            raise GitHubError(f"GitHub {method} {path}: {exc.reason}") from exc
        return json.loads(body) if body else {}

    def base_sha(self, base_branch: str) -> str:
        data = self._api("GET", f"/repos/{self.repo}/git/ref/heads/{base_branch}")
        sha = (data.get("object") or {}).get("sha")
        if not sha:
            raise GitHubError(f"Basis-Branch '{base_branch}' nicht gefunden.")
        return str(sha)

    def create_branch(self, name: str, sha: str) -> None:
        self._api("POST", f"/repos/{self.repo}/git/refs",
                  {"ref": f"refs/heads/{name}", "sha": sha})

    def put_file(self, branch: str, path: str, content: str, message: str) -> None:
        encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
        self._api("PUT", f"/repos/{self.repo}/contents/{path}",
                  {"message": message, "content": encoded, "branch": branch})

    def create_draft_pr(self, head: str, base: str, title: str, body: str) -> str:
        data = self._api("POST", f"/repos/{self.repo}/pulls",
                         {"title": title, "head": head, "base": base,
                          "body": body, "draft": True})
        return str(data.get("html_url", ""))


def open_draft_prs(
    github: GitHubIntegration,
    drafts: list[PullRequestDraft],
    client: HttpGitHubClient,
) -> list[dict[str, Any]]:
    """ONLINE: eroeffnet fuer jeden Entwurf einen echten Draft-PR.

    Fehler je PR werden erfasst (nicht abgebrochen), damit ein einzelner
    Fehlschlag die restlichen PRs nicht verhindert.
    """
    results: list[dict[str, Any]] = []
    for d in drafts:
        branch = f"{github.branch_prefix}{d.finding_id}"
        result: dict[str, Any] = {"finding_id": d.finding_id, "branch": branch,
                                  "url": "", "error": ""}
        try:
            sha = client.base_sha(github.base_branch)
            client.create_branch(branch, sha)
            client.put_file(
                branch, d.doc_path,
                f"# Remediation-Tracking: {d.title}\n\n{d.body}\n",
                f"security(specter): Trackingdokument fuer {d.finding_id}",
            )
            result["url"] = client.create_draft_pr(
                branch, github.base_branch, d.title, d.body)
        except GitHubError as exc:
            result["error"] = str(exc)
        results.append(result)
    return results
