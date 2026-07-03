"""Tests für die sicheren Scanner-Wrapper (Argument-Validierung + Ausführung)."""

from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from specter.config import Config, Engagement, ScannerPolicy
from specter.findings import Severity
from specter.safety import SafetyPolicy, ScopeViolation
from specter.scanners import NiktoScanner, NmapScanner, ScannerError, get_scanner
from specter.scanners.base import Scanner


def _cfg(tmp_path, **ov) -> Config:
    d = dict(
        engagement=Engagement("X", "Y", "R"),
        allowed_targets=["127.0.0.1", "10.10.0.0/16"], forbidden_targets=[],
        allowed_paths=[tmp_path.resolve()], max_file_bytes=100_000,
        allowed_binaries=["curl"], command_timeout=10, require_approval=False,
        max_iterations=5, model="claude-sonnet-5",
    )
    d.update(ov)
    return Config(**d)


# ------------------------------- Registry ---------------------------------

def test_base_scanner_is_abstract():
    base = Scanner()
    assert base.parse("beliebiger output", "ziel") == []
    with pytest.raises(NotImplementedError):
        base.default_argv("t", None, False)


def test_explicit_value_flag_allowance():
    s = NmapScanner()
    # Ein ausdrücklich freigegebenes VALUE-Flag ohne '=' erwartet einen Wert.
    pol = ScannerPolicy(enabled=True, extra_allowed_flags=["--top-ports"])
    s.validate_extra_args(["--top-ports", "500"], pol)
    with pytest.raises(ScannerError, match="Wert für"):
        s.validate_extra_args(["--top-ports"], pol)


def test_get_scanner_known_and_unknown():
    assert isinstance(get_scanner("nmap"), NmapScanner)
    assert isinstance(get_scanner("nikto"), NiktoScanner)
    assert get_scanner("metasploit") is None


# --------------------------- Argument-Allowlist ---------------------------

def test_nmap_default_argv_is_safe():
    s = NmapScanner()
    argv = s.build_argv("127.0.0.1", ScannerPolicy(enabled=True))
    assert argv[0] == "nmap"
    assert "-sT" in argv and "-Pn" in argv       # TCP-Connect, kein root
    assert "-sS" not in argv                       # kein Raw-Scan
    assert argv[-1] == "127.0.0.1"


def test_nmap_ports_validation():
    s = NmapScanner()
    assert "-p" in s.build_argv("127.0.0.1", ScannerPolicy(enabled=True), ports="80,443")
    with pytest.raises(ScannerError):
        s.build_argv("127.0.0.1", ScannerPolicy(enabled=True), ports="80; rm -rf /")


def test_nmap_forbidden_flags_blocked():
    s = NmapScanner()
    pol = ScannerPolicy(enabled=True, allow_aggressive=True)
    for evil in [["-D", "1.2.3.4"], ["-S", "9.9.9.9"], ["--script", "exploit"],
                 ["-oN", "/etc/passwd"], ["-f"], ["--data-string", "x"]]:
        with pytest.raises(ScannerError, match="blockiert|Allowlist|Wert"):
            s.validate_extra_args(evil, pol)


def test_nmap_aggressive_requires_optin():
    s = NmapScanner()
    with pytest.raises(ScannerError, match="allow_aggressive"):
        s.validate_extra_args(["-A"], ScannerPolicy(enabled=True))
    # Mit Freigabe erlaubt.
    s.validate_extra_args(["-A"], ScannerPolicy(enabled=True, allow_aggressive=True))


def test_nmap_unknown_flag_denied():
    s = NmapScanner()
    with pytest.raises(ScannerError, match="Allowlist"):
        s.validate_extra_args(["--total-nonsense"], ScannerPolicy(enabled=True))


def test_nmap_extra_allowed_flags_from_scope():
    s = NmapScanner()
    pol = ScannerPolicy(enabled=True, extra_allowed_flags=["--script=http-title"])
    # --script ist normal verboten, hier aber ausdrücklich freigegeben.
    s.validate_extra_args(["--script=http-title"], pol)


def test_nmap_value_flag_missing_value():
    s = NmapScanner()
    with pytest.raises(ScannerError, match="Wert für"):
        s.validate_extra_args(["-p"], ScannerPolicy(enabled=True))


def test_nmap_non_flag_argument_rejected():
    s = NmapScanner()
    with pytest.raises(ScannerError, match="kein Flag"):
        s.validate_extra_args(["evil.com"], ScannerPolicy(enabled=True))


# ------------------------------ Ausführung -------------------------------

def test_run_denied_when_disabled(tmp_path):
    s = NmapScanner()
    with pytest.raises(ScannerError, match="nicht freigegeben"):
        s.run("127.0.0.1", ScannerPolicy(enabled=False), SafetyPolicy(_cfg(tmp_path)))


def test_run_denied_out_of_scope(tmp_path):
    s = NmapScanner()
    with pytest.raises(ScopeViolation):
        s.run("8.8.8.8", ScannerPolicy(enabled=True), SafetyPolicy(_cfg(tmp_path)))


def test_run_aggressive_without_optin(tmp_path):
    s = NmapScanner()
    with pytest.raises(ScannerError, match="Aggressiver Modus"):
        s.run("127.0.0.1", ScannerPolicy(enabled=True), SafetyPolicy(_cfg(tmp_path)),
              aggressive=True)


def test_run_parses_nmap_output(tmp_path):
    s = NmapScanner()
    out = ("Starting Nmap\n"
           "22/tcp open ssh OpenSSH 8.9\n"
           "3389/tcp open ms-wbt-server Microsoft Terminal Services\n"
           "80/tcp open http nginx 1.18.0\n")
    fake = subprocess.CompletedProcess([], 0, stdout=out, stderr="")
    with patch("subprocess.run", return_value=fake):
        res = s.run("127.0.0.1", ScannerPolicy(enabled=True), SafetyPolicy(_cfg(tmp_path)))
    cats = {f.category for f in res.findings}
    assert "remote_access" in cats            # RDP 3389
    assert "exposed_service" in cats          # ssh/http
    rdp = [f for f in res.findings if "3389" in f.location][0]
    assert rdp.severity is Severity.HOCH


def test_run_handles_missing_binary(tmp_path):
    s = NmapScanner()
    with patch("subprocess.run", side_effect=FileNotFoundError()):
        res = s.run("127.0.0.1", ScannerPolicy(enabled=True), SafetyPolicy(_cfg(tmp_path)))
    assert "nicht installiert" in res.error


def test_run_handles_timeout(tmp_path):
    s = NmapScanner()
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("nmap", 10)):
        res = s.run("127.0.0.1", ScannerPolicy(enabled=True, timeout_seconds=10),
                    SafetyPolicy(_cfg(tmp_path)))
    assert "Zeitlimit" in res.error


def test_run_truncates_output(tmp_path):
    s = NmapScanner()
    big = "22/tcp open ssh\n" + ("x" * 5000)
    fake = subprocess.CompletedProcess([], 0, stdout=big, stderr="")
    pol = ScannerPolicy(enabled=True, max_output_bytes=100)
    with patch("subprocess.run", return_value=fake):
        res = s.run("127.0.0.1", pol, SafetyPolicy(_cfg(tmp_path)))
    assert res.truncated is True
    assert len(res.stdout) == 100


def test_run_never_uses_shell(tmp_path):
    s = NmapScanner()
    fake = subprocess.CompletedProcess([], 0, stdout="", stderr="")
    with patch("subprocess.run", return_value=fake) as m:
        s.run("127.0.0.1", ScannerPolicy(enabled=True), SafetyPolicy(_cfg(tmp_path)))
    _, kwargs = m.call_args
    assert kwargs.get("shell") is False


def test_run_parser_error_captured(tmp_path):
    s = NmapScanner()
    fake = subprocess.CompletedProcess([], 0, stdout="x", stderr="")
    with patch("subprocess.run", return_value=fake), \
         patch.object(NmapScanner, "parse", side_effect=ValueError("boom")):
        res = s.run("127.0.0.1", ScannerPolicy(enabled=True), SafetyPolicy(_cfg(tmp_path)))
    assert "Parser-Fehler" in res.error


def test_scanner_result_to_dict(tmp_path):
    s = NmapScanner()
    fake = subprocess.CompletedProcess([], 0, stdout="22/tcp open ssh\n", stderr="")
    with patch("subprocess.run", return_value=fake):
        res = s.run("127.0.0.1", ScannerPolicy(enabled=True), SafetyPolicy(_cfg(tmp_path)))
    d = res.to_dict()
    assert d["scanner"] == "nmap" and d["target"] == "127.0.0.1"
    assert "command" in d and d["finding_count"] >= 1


# --------------------------------- nikto ----------------------------------

def test_nikto_tuning_dos_blocked():
    s = NiktoScanner()
    with pytest.raises(ScannerError, match="Denial of Service"):
        s.validate_extra_args(["-Tuning", "6"], ScannerPolicy(enabled=True))


def test_nikto_mutate_forbidden():
    s = NiktoScanner()
    with pytest.raises(ScannerError, match="blockiert"):
        s.validate_extra_args(["-mutate", "3"], ScannerPolicy(enabled=True))


def test_nikto_bad_timeout_value():
    s = NiktoScanner()
    with pytest.raises(ScannerError, match="Zahlenwert"):
        s.validate_extra_args(["-timeout", "abc"], ScannerPolicy(enabled=True))


def test_nikto_default_argv():
    s = NiktoScanner()
    argv = s.build_argv("127.0.0.1", ScannerPolicy(enabled=True), ports="443")
    assert argv[0] == "nikto" and "-h" in argv and "127.0.0.1" in argv
    assert "-port" in argv and "443" in argv


def test_nmap_aggressive_default_argv():
    s = NmapScanner()
    pol = ScannerPolicy(enabled=True, allow_aggressive=True)
    argv = s.build_argv("127.0.0.1", pol, aggressive=True)
    assert "--version-all" in argv


def test_nikto_tuning_safe_value_ok():
    s = NiktoScanner()
    # -Tuning ohne '6' ist erlaubt.
    s.validate_extra_args(["-Tuning", "1234"], ScannerPolicy(enabled=True))


def test_nikto_port_value_validation():
    s = NiktoScanner()
    s.validate_extra_args(["-port", "8443"], ScannerPolicy(enabled=True))
    with pytest.raises(ScannerError):
        s.validate_extra_args(["-port", "nope"], ScannerPolicy(enabled=True))


def test_nikto_parse_outdated_and_injection():
    s = NiktoScanner()
    out = ("+ Apache/2.2.8 is out of date.\n"
           "+ Potential SQL Injection detected in parameter id.\n")
    findings = s.parse(out, "10.0.0.1")
    cats = {f.category for f in findings}
    assert "outdated_component" in cats
    assert "injection" in cats


def test_nikto_parse_findings():
    s = NiktoScanner()
    out = ("- Nikto v2.5\n"
           "+ Server: Apache/2.2.8\n"
           "+ The anti-clickjacking X-Frame-Options header is not present.\n"
           "+ OSVDB-3268: /admin/: Directory indexing found.\n"
           "+ Apache/2.2.8 appears to be outdated.\n")
    findings = s.parse(out, "127.0.0.1")
    titles = " ".join(f.title for f in findings)
    assert "X-Frame-Options" in titles
    assert any(f.category == "outdated_component" for f in findings)
    # Server-Banner erzeugt kein Finding.
    assert not any("Server: Apache" in f.title for f in findings)


def test_nikto_parse_skips_status_and_summary_noise():
    """Status-/Zusammenfassungs-/Banner-Zeilen dürfen keine Findings werden."""
    s = NiktoScanner()
    out = (
        "+ Target IP:          127.0.0.1\n"
        "+ SSL Info:        Subject: /CN=lab-expired.local\n"
        "+ Root page / redirects to: https://example/\n"
        "+ No CGI Directories found (use '-C all' to force check all dirs)\n"
        "+ 6544 items checked: 0 error(s) and 4 item(s) reported on remote host\n"
        "+ 1 host(s) tested\n"
        "+ No web server found on 127.0.0.1\n"
        # Ein echter Fund bleibt erhalten:
        "+ The anti-clickjacking X-Frame-Options header is not present.\n"
    )
    findings = s.parse(out, "127.0.0.1")
    assert len(findings) == 1
    assert "X-Frame-Options" in findings[0].title
