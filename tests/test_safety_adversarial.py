"""Adversariale Härtung der SafetyPolicy — der zentralen Sicherheitsgrenze.

Die SafetyPolicy ist die fail-closed-Schranke zwischen dem (evtl. fehlgeleiteten)
Sprachmodell und der echten Welt. Jede Umgehung wäre kritisch. Diese Tests
prüfen genau die Tricks, mit denen solche Scope-Grenzen in der Praxis
umgangen werden — und sichern das korrekte, verweigernde Verhalten als
Regression ab.

Schwerpunkt SSRF: Die Cloud-Metadaten-IP ``169.254.169.254`` (AWS/GCP/Azure)
liegt INNERHALB eines häufig erlaubten Link-Local-/RFC1918-Bereichs. Ein
Angreifer, der Specter zu einem Zugriff darauf bewegen will, probiert
alternative IP-Schreibweisen (IPv6-gemappt, dezimal, oktal, hex). Alle müssen
verweigert werden.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from specter.config import Config, Engagement
from specter.safety import SafetyPolicy, ScopeViolation


def _policy(tmp_path: Path, **ov) -> SafetyPolicy:
    allowed = tmp_path / "targets"
    allowed.mkdir(exist_ok=True)
    d = dict(
        engagement=Engagement("X", "Y", "R"),
        # Metadaten-IP liegt im erlaubten Link-Local-Bereich — sie MUSS trotzdem
        # durch die Sperrliste verweigert werden.
        allowed_targets=["169.254.0.0/16", "10.0.0.0/8", "example.com"],
        forbidden_targets=["169.254.169.254", "metadata.google.internal"],
        allowed_paths=[allowed.resolve()],
        max_file_bytes=100_000, allowed_binaries=["curl", "nmap"],
        command_timeout=10, require_approval=False,
        max_iterations=5, model="claude-sonnet-5",
    )
    d.update(ov)
    return SafetyPolicy(Config(**d))


# ==================== SSRF: verbotene IP in Alternativformen ====================

@pytest.mark.parametrize("form", [
    "169.254.169.254",                 # kanonisch
    "169.254.169.254.",                # trailing dot
    "::ffff:169.254.169.254",          # IPv6-gemappt (dotted)
    "::ffff:a9fe:a9fe",                # IPv6-gemappt (hex)
    "2852039166",                      # dezimal
    "0251.0376.0251.0376",             # oktal
    "0xA9.0xFE.0xA9.0xFE",             # hex
    "http://169.254.169.254/latest/",  # als URL
    "http://[::ffff:169.254.169.254]/",  # URL mit IPv6-gemappt
    "169.254.169.254:80",              # mit Port
])
def test_forbidden_metadata_ip_denied_in_any_form(tmp_path, form):
    pol = _policy(tmp_path)
    with pytest.raises(ScopeViolation):
        pol.check_target(form)


@pytest.mark.parametrize("form", [
    "metadata.google.internal",
    "METADATA.GOOGLE.INTERNAL",        # Case-Variante
    "http://metadata.google.internal/computeMetadata/",
])
def test_forbidden_hostname_denied(tmp_path, form):
    pol = _policy(tmp_path)
    with pytest.raises(ScopeViolation):
        pol.check_target(form)


def test_legitimate_targets_still_allowed(tmp_path):
    pol = _policy(tmp_path)
    assert pol.check_target("10.1.2.3") == "10.1.2.3"
    assert pol.check_target("example.com") == "example.com"
    # Link-local, aber NICHT die Metadaten-IP -> erlaubt.
    assert pol.check_target("169.254.1.1") == "169.254.1.1"
    assert pol.check_target("http://10.0.0.5:8080/pfad") == "10.0.0.5"


def test_unlisted_ip_denied_even_without_forbidden(tmp_path):
    pol = _policy(tmp_path)
    with pytest.raises(ScopeViolation):
        pol.check_target("8.8.8.8")


# ==================== Pfad: Steuerzeichen / NUL / leer ====================

def test_nul_byte_path_is_denied_not_crash(tmp_path):
    """Ein NUL-Byte darf Path.resolve() nicht mit ValueError abstürzen lassen."""
    pol = _policy(tmp_path)
    with pytest.raises(ScopeViolation):
        pol.check_path("harmlos\x00/etc/passwd")


@pytest.mark.parametrize("bad", ["a\nb", "a\rb", "a\tb", "\x01evil", "  ", ""])
def test_control_char_and_empty_paths_denied(tmp_path, bad):
    pol = _policy(tmp_path)
    with pytest.raises(ScopeViolation):
        pol.check_path(bad)


def test_valid_in_scope_path_still_ok(tmp_path):
    pol = _policy(tmp_path)
    target = tmp_path / "targets" / "bericht.txt"
    resolved = pol.check_path(str(target))
    assert resolved == target.resolve()


def test_symlink_escape_denied(tmp_path):
    """Ein Symlink im Scope, der nach draußen zeigt, wird verweigert."""
    pol = _policy(tmp_path)
    link = tmp_path / "targets" / "escape"
    try:
        os.symlink("/etc/passwd", link)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks nicht unterstützt")
    with pytest.raises(ScopeViolation):
        pol.check_path(str(link))


def test_traversal_denied(tmp_path):
    pol = _policy(tmp_path)
    with pytest.raises(ScopeViolation):
        pol.check_path(str(tmp_path / "targets" / ".." / ".." / "etc" / "passwd"))


def test_symlink_loop_handled_gracefully(tmp_path):
    """Eine Symlink-Schleife darf nie mit einer ungefangenen OSError abstürzen —
    erlaubt ist nur: aufgelöster Pfad ODER ScopeViolation."""
    pol = _policy(tmp_path)
    a = tmp_path / "targets" / "a"
    b = tmp_path / "targets" / "b"
    try:
        os.symlink(b, a)
        os.symlink(a, b)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks nicht unterstützt")
    try:
        pol.check_path(str(a))
    except ScopeViolation:
        pass  # ebenfalls akzeptabel (fail-closed)


# ==================== Befehl: Steuerzeichen / Metazeichen ====================

@pytest.mark.parametrize("cmd", [
    "curl http://example.com\x00; rm -rf /",   # NUL-Smuggling
    "curl\rhttp://example.com",                 # Carriage Return
    "curl\thttp://example.com",                 # Tab
    "curl http://example.com; whoami",          # Verkettung
    "curl http://example.com | tee x",          # Pipe
    "curl http://example.com && rm x",          # AND
    "curl $(whoami).example.com",               # Command-Substitution
    "curl ${HOME}.example.com",                 # Variablen-Expansion
    "curl http://example.com > /etc/passwd",    # Umleitung
    "curl `id`.example.com",                    # Backticks
])
def test_command_metachars_and_control_denied(tmp_path, cmd):
    pol = _policy(tmp_path)
    with pytest.raises(ScopeViolation):
        pol.check_command(cmd)


@pytest.mark.parametrize("ctrl", ["\x01", "\x07", "\x0b", "\x1f"])
def test_command_bare_control_char_denied(tmp_path, ctrl):
    """Ein Steuerzeichen ohne sonstiges Metazeichen wird eigenständig abgewiesen."""
    pol = _policy(tmp_path)
    with pytest.raises(ScopeViolation):
        pol.check_command(f"curl {ctrl}http://example.com")


def test_legit_commands_still_parse(tmp_path):
    pol = _policy(tmp_path)
    assert pol.check_command("nmap -sV 10.1.2.3") == ["nmap", "-sV", "10.1.2.3"]
    assert pol.check_command("curl http://example.com")[0] == "curl"


def test_binary_not_allowlisted_denied(tmp_path):
    pol = _policy(tmp_path)
    with pytest.raises(ScopeViolation):
        pol.check_command("wget http://example.com")


def test_command_target_out_of_scope_denied(tmp_path):
    pol = _policy(tmp_path)
    with pytest.raises(ScopeViolation):
        pol.check_command("curl http://8.8.8.8/")


def test_command_hitting_forbidden_ip_denied(tmp_path):
    """Ein Befehl gegen die Metadaten-IP wird über check_target verweigert."""
    pol = _policy(tmp_path)
    with pytest.raises(ScopeViolation):
        pol.check_command("curl http://169.254.169.254/latest/meta-data/")
