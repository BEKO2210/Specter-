"""Gemeinsame Basis fuer sichere Scanner-Wrapper."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from typing import Any

from ..config import ScannerPolicy
from ..findings import Finding
from ..safety import SafetyPolicy

# Ports wie "80", "80,443", "1-1024" - keine Shell-Sonderzeichen.
_PORTS_RE = re.compile(r"^[0-9]{1,5}(?:[,-][0-9]{1,5})*$")


class ScannerError(Exception):
    """Validierungs-/Freigabefehler - die Ausfuehrung wird verweigert."""


@dataclass
class ScannerResult:
    scanner: str
    target: str
    argv: list[str]
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    findings: list[Finding] = field(default_factory=list)
    error: str = ""
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanner": self.scanner,
            "target": self.target,
            "command": " ".join(self.argv),
            "returncode": self.returncode,
            "finding_count": len(self.findings),
            "truncated": self.truncated,
            "error": self.error,
        }


class Scanner:
    """Basisklasse. Unterklassen definieren Flags, Profile und Parser."""

    name: str = ""
    binary: str = ""
    # Immer erlaubte Flag-"Koepfe" (ohne angehaengten Wert).
    SAFE_FLAGS: frozenset[str] = frozenset()
    # Nur mit allow_aggressive erlaubt.
    AGGRESSIVE_FLAGS: frozenset[str] = frozenset()
    # Nie erlaubt (hat Vorrang) - Evasion, Spoofing, DoS, Dateiausgabe ...
    FORBIDDEN_FLAGS: frozenset[str] = frozenset()
    # Flags, deren naechstes Token ein Wert ist (wird separat validiert).
    VALUE_FLAGS: frozenset[str] = frozenset()

    # -- von Unterklassen zu implementieren --------------------------------

    def default_argv(self, target: str, ports: str | None, aggressive: bool) -> list[str]:
        raise NotImplementedError

    def parse(self, stdout: str, target: str) -> list[Finding]:
        return []

    def validate_value(self, flag: str, value: str) -> None:
        """Prueft den Wert eines VALUE_FLAG (Standard: Ports-Syntax fuer -p)."""
        if flag in {"-p", "-port", "--top-ports"} and not _PORTS_RE.match(value):
            raise ScannerError(f"Ungueltiger Portwert fuer {flag}: {value!r}")

    # -- gemeinsame Logik ---------------------------------------------------

    @staticmethod
    def _flag_head(token: str) -> str:
        if token.startswith("--"):
            return token.split("=", 1)[0]
        return token

    def _allowed_heads(self, policy: ScannerPolicy) -> set[str]:
        heads = set(self.SAFE_FLAGS)
        if policy.allow_aggressive:
            heads |= self.AGGRESSIVE_FLAGS
        return heads

    def validate_extra_args(self, args: list[str], policy: ScannerPolicy) -> None:
        """Strikte Allowlist-Pruefung zusaetzlicher Argumente (fail-closed).

        Reihenfolge:
          1. Ein *exakt* in scanners.<name>.extra_allowed_flags freigegebenes
             Token ist immer erlaubt (uebersteuert auch das Default-Verbot -
             aber nur fuer genau dieses Token, z. B. "--script=http-title").
          2. Sonst: gefaehrliche Flags sind blockiert.
          3. Sonst: nur Flags aus der Allowlist (SAFE + ggf. AGGRESSIVE).
        """
        allowed = self._allowed_heads(policy)
        explicit = set(policy.extra_allowed_flags)
        expect_value_for: str | None = None
        for token in args:
            if expect_value_for is not None:
                self.validate_value(expect_value_for, token)
                expect_value_for = None
                continue
            if not token.startswith("-"):
                raise ScannerError(
                    f"Unerwartetes Argument (kein Flag/Wert): {token!r}"
                )
            head = self._flag_head(token)
            if token in explicit:
                # Ausdruecklich freigegeben - auch wenn sonst verboten.
                if head in self.VALUE_FLAGS and "=" not in token:
                    expect_value_for = head
                continue
            if head in self.FORBIDDEN_FLAGS or token in self.FORBIDDEN_FLAGS:
                raise ScannerError(
                    f"Gefaehrliches Flag ist blockiert: {token!r} "
                    "(Evasion/Spoofing/DoS/Dateiausgabe)."
                )
            if head not in allowed and token not in allowed:
                if head in self.AGGRESSIVE_FLAGS:
                    raise ScannerError(
                        f"Aggressives Flag {token!r} erfordert "
                        "scanners.<name>.allow_aggressive: true."
                    )
                raise ScannerError(
                    f"Flag nicht in der Allowlist: {token!r}. "
                    "Nur ausdruecklich freigegebene Flags sind erlaubt."
                )
            if head in self.VALUE_FLAGS and "=" not in token:
                expect_value_for = head
        if expect_value_for is not None:
            raise ScannerError(f"Wert fuer {expect_value_for} fehlt.")

    def build_argv(
        self,
        target: str,
        policy: ScannerPolicy,
        ports: str | None = None,
        aggressive: bool = False,
        extra_args: list[str] | None = None,
    ) -> list[str]:
        if ports is not None and not _PORTS_RE.match(ports):
            raise ScannerError(f"Ungueltige Portangabe: {ports!r}")
        extra = list(extra_args or [])
        if extra:
            self.validate_extra_args(extra, policy)
        argv = [self.binary] + self.default_argv(target, ports, aggressive) + extra
        return argv

    def run(
        self,
        target: str,
        policy: ScannerPolicy,
        safety: SafetyPolicy,
        ports: str | None = None,
        aggressive: bool = False,
        extra_args: list[str] | None = None,
    ) -> ScannerResult:
        if not policy.enabled:
            raise ScannerError(
                f"Scanner '{self.name}' ist nicht freigegeben "
                f"(scanners.{self.name}.enabled: true in scope.yaml setzen)."
            )
        if aggressive and not policy.allow_aggressive:
            raise ScannerError(
                f"Aggressiver Modus fuer '{self.name}' nicht freigegeben "
                f"(scanners.{self.name}.allow_aggressive: true)."
            )
        # Ziel muss im Netzwerk-Scope liegen (kann ScopeViolation werfen).
        host = safety.check_target(target)

        argv = self.build_argv(host, policy, ports, aggressive, extra_args)
        result = ScannerResult(scanner=self.name, target=host, argv=argv)

        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=policy.timeout_seconds,
                shell=False,
                check=False,
            )
        except FileNotFoundError:
            result.error = f"Programm nicht installiert: {self.binary}"
            return result
        except subprocess.TimeoutExpired:
            result.error = f"Zeitlimit ({policy.timeout_seconds}s) ueberschritten."
            return result

        result.returncode = proc.returncode
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        if len(stdout) > policy.max_output_bytes:
            stdout = stdout[: policy.max_output_bytes]
            result.truncated = True
        result.stdout = stdout
        result.stderr = stderr[:10_000]
        try:
            result.findings = self.parse(stdout, host)
        except Exception as exc:  # Parser darf den Lauf nie zum Absturz bringen
            result.error = f"Parser-Fehler: {exc}"
        return result
