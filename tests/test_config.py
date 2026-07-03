"""Tests für das Laden und Validieren der Scope-Datei."""

from __future__ import annotations

import datetime as _dt

import pytest

from specter.config import Config, GitHubIntegration, ScannerPolicy, ScopeError


def _write(path, text):
    path.write_text(text, encoding="utf-8")
    return path


def test_missing_file(tmp_path):
    with pytest.raises(ScopeError, match="nicht gefunden"):
        Config.load(tmp_path / "fehlt.yaml")


def test_invalid_yaml(tmp_path):
    p = _write(tmp_path / "s.yaml", "engagement: [unbalanced\n")
    with pytest.raises(ScopeError, match="YAML"):
        Config.load(p)


def test_scalar_yaml_rejected(tmp_path):
    # Ein Skalar/Liste ist valides YAML, aber kein Mapping -> saubere ScopeError
    # statt eines rohen AttributeError-Tracebacks.
    p = _write(tmp_path / "s.yaml", "nur-ein-string\n")
    with pytest.raises(ScopeError, match="YAML-Mapping"):
        Config.load(p)


def test_list_yaml_rejected(tmp_path):
    p = _write(tmp_path / "s.yaml", "- a\n- b\n")
    with pytest.raises(ScopeError, match="YAML-Mapping"):
        Config.load(p)


def test_missing_authorization(tmp_path):
    p = _write(tmp_path / "s.yaml", "engagement:\n  name: X\n")
    with pytest.raises(ScopeError, match="authorized_by"):
        Config.load(p)


def test_full_load(tmp_path):
    p = _write(tmp_path / "s.yaml", """
engagement:
  name: Firma XY
  authorized_by: IT-Leitung
  authorization_ref: REF-9
  valid_until: "2999-12-31"
network:
  allowed_targets: ["127.0.0.1", "10.0.0.0/8"]
  forbidden_targets: ["169.254.169.254"]
filesystem:
  allowed_paths: ["./targets"]
  max_file_bytes: 500
commands:
  allowed_binaries: ["nmap", "curl"]
  timeout_seconds: 42
runtime:
  require_approval: false
  max_iterations: 7
  model: claude-sonnet-5
""")
    cfg = Config.load(p)
    assert cfg.engagement.name == "Firma XY"
    assert cfg.allowed_targets == ["127.0.0.1", "10.0.0.0/8"]
    assert cfg.max_file_bytes == 500
    assert cfg.command_timeout == 42
    assert cfg.require_approval is False
    assert cfg.max_iterations == 7
    assert len(cfg.allowed_paths) == 1


def test_expired_authorization(tmp_path):
    p = _write(tmp_path / "s.yaml", """
engagement:
  name: X
  authorized_by: Y
  authorization_ref: R
  valid_until: "2000-01-01"
""")
    with pytest.raises(ScopeError, match="abgelaufen"):
        Config.load(p)


def test_invalid_valid_until(tmp_path):
    p = _write(tmp_path / "s.yaml", """
engagement:
  name: X
  authorized_by: Y
  authorization_ref: R
  valid_until: "kein-datum"
""")
    with pytest.raises(ScopeError, match="gültiges Datum"):
        Config.load(p)


def test_defaults_when_sections_absent(tmp_path):
    p = _write(tmp_path / "s.yaml", """
engagement:
  name: X
  authorized_by: Y
  authorization_ref: R
""")
    cfg = Config.load(p)
    assert cfg.allowed_targets == []
    assert cfg.allowed_paths == []
    assert cfg.require_approval is True          # sicherer Default
    assert cfg.max_iterations == 25
    assert cfg.model == "claude-sonnet-5"


def test_scanners_parsed(tmp_path):
    p = _write(tmp_path / "s.yaml", """
engagement:
  name: X
  authorized_by: Y
  authorization_ref: R
scanners:
  nmap:
    enabled: true
    allow_aggressive: false
    extra_allowed_flags: ["--script=http-title"]
    timeout_seconds: 120
    max_output_bytes: 50000
  nikto:
    enabled: false
""")
    cfg = Config.load(p)
    nmap = cfg.scanner_policy("nmap")
    assert nmap.enabled is True
    assert nmap.allow_aggressive is False
    assert nmap.extra_allowed_flags == ["--script=http-title"]
    assert nmap.timeout_seconds == 120
    assert nmap.max_output_bytes == 50000
    assert cfg.scanner_policy("nikto").enabled is False


def test_scanner_policy_default_disabled(tmp_path):
    p = _write(tmp_path / "s.yaml", """
engagement:
  name: X
  authorized_by: Y
  authorization_ref: R
""")
    cfg = Config.load(p)
    # Nicht konfigurierter Scanner ist per Default deaktiviert (fail-closed).
    pol = cfg.scanner_policy("nmap")
    assert pol.enabled is False
    assert pol.allow_aggressive is False


def test_scanner_policy_from_dict_defaults():
    pol = ScannerPolicy.from_dict(None)
    assert pol.enabled is False
    assert pol.extra_allowed_flags == []
    assert pol.timeout_seconds == 300


def test_github_integration_default_disabled(tmp_path):
    p = _write(tmp_path / "s.yaml", """
engagement:
  name: X
  authorized_by: Y
  authorization_ref: R
""")
    cfg = Config.load(p)
    assert cfg.github.enabled is False
    assert cfg.github.base_branch == "main"
    assert cfg.github.token_env == "GITHUB_TOKEN"


def test_github_integration_parsed(tmp_path):
    p = _write(tmp_path / "s.yaml", """
engagement:
  name: X
  authorized_by: Y
  authorization_ref: R
integrations:
  github:
    enabled: true
    repo: "muster/repo"
    base_branch: "develop"
    branch_prefix: "sec/"
    token_env: "GH_PAT"
""")
    cfg = Config.load(p)
    gh = cfg.github
    assert gh.enabled is True and gh.repo == "muster/repo"
    assert gh.base_branch == "develop" and gh.branch_prefix == "sec/"
    assert gh.token_env == "GH_PAT"


def test_github_integration_from_dict_defaults():
    gh = GitHubIntegration.from_dict(None)
    assert gh.enabled is False and gh.repo == "" and gh.base_branch == "main"


def test_valid_until_future_ok(tmp_path):
    future = (_dt.date.today() + _dt.timedelta(days=1)).isoformat()
    p = _write(tmp_path / "s.yaml", f"""
engagement:
  name: X
  authorized_by: Y
  authorization_ref: R
  valid_until: "{future}"
""")
    cfg = Config.load(p)
    assert cfg.engagement.valid_until == future
