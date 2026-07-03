"""Tests für die Scope-Durchsetzung - die kritischste Komponente.

Ausführen mit:  python -m pytest -q
"""

from __future__ import annotations

from pathlib import Path

import pytest

from specter.config import Config, Engagement
from specter.safety import SafetyPolicy, ScopeViolation


def make_config(tmp_path: Path) -> Config:
    allowed = tmp_path / "targets"
    allowed.mkdir()
    return Config(
        engagement=Engagement("Test", "Tester", "REF-1"),
        allowed_targets=["127.0.0.1", "192.168.56.0/24", "scanme.nmap.org"],
        forbidden_targets=["169.254.169.254"],
        allowed_paths=[allowed.resolve()],
        max_file_bytes=1000,
        allowed_binaries=["nmap", "curl"],
        command_timeout=10,
        require_approval=True,
        max_iterations=5,
        model="claude-sonnet-5",
    )


# -- Dateisystem -----------------------------------------------------------

def test_path_inside_scope_ok(tmp_path):
    policy = SafetyPolicy(make_config(tmp_path))
    target = tmp_path / "targets" / "app.py"
    target.write_text("x=1")
    assert policy.check_path(str(target)) == target.resolve()


def test_path_traversal_denied(tmp_path):
    policy = SafetyPolicy(make_config(tmp_path))
    with pytest.raises(ScopeViolation):
        policy.check_path(str(tmp_path / "targets" / ".." / "secret.txt"))


def test_absolute_outside_denied(tmp_path):
    policy = SafetyPolicy(make_config(tmp_path))
    with pytest.raises(ScopeViolation):
        policy.check_path("/etc/shadow")


# -- Netzwerk-Ziele --------------------------------------------------------

def test_exact_ip_allowed(tmp_path):
    policy = SafetyPolicy(make_config(tmp_path))
    assert policy.check_target("127.0.0.1") == "127.0.0.1"


def test_cidr_membership(tmp_path):
    policy = SafetyPolicy(make_config(tmp_path))
    assert policy.check_target("192.168.56.42") == "192.168.56.42"


def test_ip_outside_cidr_denied(tmp_path):
    policy = SafetyPolicy(make_config(tmp_path))
    with pytest.raises(ScopeViolation):
        policy.check_target("192.168.57.1")


def test_forbidden_target_wins(tmp_path):
    cfg = make_config(tmp_path)
    cfg.allowed_targets.append("169.254.169.254")  # sogar wenn erlaubt gelistet
    policy = SafetyPolicy(cfg)
    with pytest.raises(ScopeViolation):
        policy.check_target("169.254.169.254")


def test_hostname_exact_match(tmp_path):
    policy = SafetyPolicy(make_config(tmp_path))
    assert policy.check_target("http://scanme.nmap.org/") == "scanme.nmap.org"


def test_unlisted_host_denied(tmp_path):
    policy = SafetyPolicy(make_config(tmp_path))
    with pytest.raises(ScopeViolation):
        policy.check_target("example.com")


# -- Befehle ---------------------------------------------------------------

def test_allowed_command_parsed(tmp_path):
    policy = SafetyPolicy(make_config(tmp_path))
    assert policy.check_command("nmap -sV 127.0.0.1") == ["nmap", "-sV", "127.0.0.1"]


def test_binary_not_in_allowlist(tmp_path):
    policy = SafetyPolicy(make_config(tmp_path))
    with pytest.raises(ScopeViolation):
        policy.check_command("rm -rf 127.0.0.1")


def test_command_target_out_of_scope(tmp_path):
    policy = SafetyPolicy(make_config(tmp_path))
    with pytest.raises(ScopeViolation):
        policy.check_command("nmap -sV 8.8.8.8")


def test_shell_metacharacters_denied(tmp_path):
    policy = SafetyPolicy(make_config(tmp_path))
    with pytest.raises(ScopeViolation):
        policy.check_command("nmap 127.0.0.1; rm -rf /")


def test_command_without_target_denied(tmp_path):
    policy = SafetyPolicy(make_config(tmp_path))
    with pytest.raises(ScopeViolation):
        policy.check_command("nmap --version")
