"""Tests fuer die GitHub-Draft-PR-Integration (offline + online, gemockt)."""

from __future__ import annotations

import io
import json
import urllib.error

import pytest

from specter.config import GitHubIntegration
from specter.findings import Finding
from specter.integrations import github_pr
from specter.integrations.github_pr import (
    GitHubError, HttpGitHubClient, PullRequestDraft,
    build_drafts, open_draft_prs, write_drafts,
)


def _findings():
    return [
        Finding("SQL-Injection", "injection", "kritisch", "api", location="a.py:9",
                cwe="CWE-89"),
        Finding("Default admin", "default_credentials", "hoch", "app"),
    ]


# ------------------------------ Entwuerfe ---------------------------------

def test_build_drafts():
    drafts = build_drafts(_findings())
    assert len(drafts) == 2
    assert drafts[0].title.startswith("fix(security):")
    assert drafts[0].finding_id
    assert drafts[0].doc_path.startswith("security/specter/")


def test_write_drafts_offline(tmp_path):
    drafts = build_drafts(_findings())
    paths = write_drafts(drafts, tmp_path / "prs")
    assert len(paths) == 2
    assert all(p.exists() and p.suffix == ".md" for p in paths)
    assert "fix(security)" in paths[0].read_text(encoding="utf-8")


# --------------------------- HttpGitHubClient -----------------------------

def test_client_methods_via_mocked_api(monkeypatch):
    client = HttpGitHubClient("owner/repo", "tok")
    calls = []

    def fake_api(method, path, payload=None):
        calls.append((method, path, payload))
        if path.endswith("/git/ref/heads/main"):
            return {"object": {"sha": "abc123"}}
        if path.endswith("/pulls"):
            return {"html_url": "https://github.com/owner/repo/pull/7"}
        return {}

    monkeypatch.setattr(client, "_api", fake_api)
    assert client.base_sha("main") == "abc123"
    client.create_branch("specter/fix-x", "abc123")
    client.put_file("specter/fix-x", "security/specter/x.md", "inhalt", "msg")
    url = client.create_draft_pr("specter/fix-x", "main", "titel", "body")
    assert url.endswith("/pull/7")
    assert any(m == "PUT" for m, _, _ in calls)


def test_client_base_sha_missing(monkeypatch):
    client = HttpGitHubClient("owner/repo", "tok")
    monkeypatch.setattr(client, "_api", lambda *a, **k: {"object": {}})
    with pytest.raises(GitHubError, match="nicht gefunden"):
        client.base_sha("main")


def test_client_api_success(monkeypatch):
    client = HttpGitHubClient("o/r", "tok")

    class Resp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return json.dumps({"ok": True}).encode()

    monkeypatch.setattr(github_pr.urllib.request, "urlopen", lambda *a, **k: Resp())
    data = client._api("POST", "/repos/o/r/pulls", {"x": 1})
    assert data == {"ok": True}


def test_client_api_http_error(monkeypatch):
    client = HttpGitHubClient("o/r", "tok")

    def boom(*a, **k):
        raise urllib.error.HTTPError("url", 422, "Unprocessable", {},
                                     io.BytesIO(b"validation failed"))

    monkeypatch.setattr(github_pr.urllib.request, "urlopen", boom)
    with pytest.raises(GitHubError, match="HTTP 422"):
        client._api("POST", "/repos/o/r/pulls", {"x": 1})


def test_client_api_url_error(monkeypatch):
    client = HttpGitHubClient("o/r", "tok")

    def boom(*a, **k):
        raise urllib.error.URLError("kein netz")

    monkeypatch.setattr(github_pr.urllib.request, "urlopen", boom)
    with pytest.raises(GitHubError, match="kein netz"):
        client._api("GET", "/repos/o/r/git/ref/heads/main")


def test_client_api_empty_body(monkeypatch):
    client = HttpGitHubClient("o/r", "tok")

    class Resp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return b""

    monkeypatch.setattr(github_pr.urllib.request, "urlopen", lambda *a, **k: Resp())
    assert client._api("POST", "/x", {"a": 1}) == {}


# ------------------------------ open_draft_prs ----------------------------

class FakeClient:
    def __init__(self, fail_on=None):
        self.fail_on = fail_on
        self.branches = []
        self.files = []

    def base_sha(self, base):
        return "sha-" + base

    def create_branch(self, name, sha):
        if self.fail_on == name:
            raise GitHubError("Branch existiert bereits")
        self.branches.append(name)

    def put_file(self, branch, path, content, message):
        self.files.append((branch, path))

    def create_draft_pr(self, head, base, title, body):
        return f"https://github.com/o/r/pull/{len(self.branches)}"


def test_open_draft_prs_success():
    gh = GitHubIntegration(enabled=True, repo="o/r", base_branch="main")
    drafts = build_drafts(_findings())
    results = open_draft_prs(gh, drafts, FakeClient())
    assert len(results) == 2
    assert all(r["url"] and not r["error"] for r in results)
    assert all(r["branch"].startswith("specter/fix-") for r in results)


def test_open_draft_prs_partial_failure():
    gh = GitHubIntegration(enabled=True, repo="o/r", base_branch="main")
    drafts = build_drafts(_findings())
    fail_branch = f"specter/fix-{drafts[0].finding_id}"
    results = open_draft_prs(gh, drafts, FakeClient(fail_on=fail_branch))
    assert results[0]["error"] and not results[0]["url"]
    assert results[1]["url"] and not results[1]["error"]


# ------------------------- open_pull_requests-Tool ------------------------

from pathlib import Path  # noqa: E402

from specter.audit import AuditLog  # noqa: E402
from specter.config import Config, Engagement  # noqa: E402
from specter.state import EngagementState  # noqa: E402
from specter.tools.open_pull_requests import OpenPullRequestsTool  # noqa: E402


def _cfg(tmp_path, github=None) -> Config:
    return Config(
        engagement=Engagement("X", "Y", "R"), allowed_targets=[], forbidden_targets=[],
        allowed_paths=[tmp_path.resolve()], max_file_bytes=100_000,
        allowed_binaries=[], command_timeout=5, require_approval=False,
        max_iterations=5, model="claude-sonnet-5",
        github=github or GitHubIntegration(),
    )


def _state_with_findings():
    st = EngagementState()
    st.findings.add(Finding("SQLi", "injection", "hoch", "api", location="a:1"))
    return st


def _tool(tmp_path, cfg, state, approval=None, factory=None):
    return OpenPullRequestsTool(
        cfg, AuditLog(tmp_path / "audit"), state,
        approval_fn=approval, client_factory=factory,
        output_dir=tmp_path / "prs",
    )


def test_tool_no_findings(tmp_path):
    tool = _tool(tmp_path, _cfg(tmp_path), EngagementState())
    r = tool.run({})
    assert "Keine Findings" in r.content


def test_tool_offline_only_when_disabled(tmp_path):
    tool = _tool(tmp_path, _cfg(tmp_path), _state_with_findings())
    r = tool.run({})
    assert "offline geschrieben" in r.content
    assert "nicht aktiviert" in r.content
    assert (tmp_path / "prs").exists()


def test_tool_enabled_but_no_repo(tmp_path):
    gh = GitHubIntegration(enabled=True, repo="")
    tool = _tool(tmp_path, _cfg(tmp_path, gh), _state_with_findings())
    r = tool.run({})
    assert "Kein Repository" in r.content


def test_tool_enabled_but_no_token(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    gh = GitHubIntegration(enabled=True, repo="o/r")
    tool = _tool(tmp_path, _cfg(tmp_path, gh), _state_with_findings())
    r = tool.run({})
    assert "Kein Token" in r.content


def test_tool_approval_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    gh = GitHubIntegration(enabled=True, repo="o/r")
    tool = _tool(tmp_path, _cfg(tmp_path, gh), _state_with_findings(),
                 approval=lambda _a: False)
    r = tool.run({})
    assert "abgelehnt" in r.content


def test_tool_online_success(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    gh = GitHubIntegration(enabled=True, repo="o/r")
    state = _state_with_findings()
    created = {}

    def factory(repo, token):
        created["repo"] = repo
        return FakeClient()

    tool = _tool(tmp_path, _cfg(tmp_path, gh), state,
                 approval=lambda _a: True, factory=factory)
    r = tool.run({})
    assert "1 Draft-PR(s) eroeffnet" in r.content
    assert created["repo"] == "o/r"


def test_tool_online_with_failure(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    gh = GitHubIntegration(enabled=True, repo="o/r")
    state = _state_with_findings()
    fid = state.findings.all()[0].id

    tool = _tool(tmp_path, _cfg(tmp_path, gh), state, approval=lambda _a: True,
                 factory=lambda repo, token: FakeClient(fail_on=f"specter/fix-{fid}"))
    r = tool.run({})
    assert "1 fehlgeschlagen" in r.content
    assert "[Fehler]" in r.content
