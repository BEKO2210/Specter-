"""Sicherer nikto-Wrapper (Webserver-Schwachstellen-Scan).

Nicht-destruktiv: Mutations-/Evasion-/DoS-Optionen und Dateiausgabe sind
blockiert. Ergebnisse werden als Findings uebernommen.
"""

from __future__ import annotations

from ..findings import Finding, Severity
from .base import Scanner, ScannerError

# Nikto -Tuning: '6' = Denial of Service. Immer verbieten.
_FORBIDDEN_TUNING = set("6")


class NiktoScanner(Scanner):
    name = "nikto"
    binary = "nikto"

    SAFE_FLAGS = frozenset({
        "-h", "-host", "-p", "-port", "-ssl", "-nossl", "-timeout",
        "-maxtime", "-Display", "-Tuning", "-nolookup", "-ask",
    })
    AGGRESSIVE_FLAGS = frozenset({"-Plugins"})
    FORBIDDEN_FLAGS = frozenset({
        # Mutation (raet/legt Ressourcen an), Evasion, Dateiausgabe, Update
        "-mutate", "-evasion", "-o", "-output", "-Save", "-update",
        "-Format", "-useproxy",
    })
    VALUE_FLAGS = frozenset({
        "-p", "-port", "-timeout", "-maxtime", "-Display", "-Tuning",
    })

    def validate_value(self, flag: str, value: str) -> None:
        if flag == "-Tuning":
            if any(c in _FORBIDDEN_TUNING for c in value):
                raise ScannerError(
                    "Nikto -Tuning 6 (Denial of Service) ist blockiert."
                )
            return
        if flag in {"-p", "-port"}:
            super().validate_value("-p", value)
            return
        if flag in {"-timeout", "-maxtime"} and not value.isdigit():
            raise ScannerError(f"Ungueltiger Zahlenwert fuer {flag}: {value!r}")

    def default_argv(self, target: str, ports: str | None, aggressive: bool) -> list[str]:
        args = ["-h", target, "-timeout", "10"]
        if ports:
            args += ["-port", ports]
        return args

    def parse(self, stdout: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for raw in stdout.splitlines():
            line = raw.strip()
            if not line.startswith("+ "):
                continue
            text = line[2:].strip()
            low = text.lower()
            # Reine Banner-/Statuszeilen erzeugen keine Findings.
            if low.startswith(("target ip", "target hostname", "target port",
                               "start time", "end time", "host(s) tested",
                               "server:")):
                continue
            category = "misconfiguration"
            severity = Severity.MITTEL
            if "header" in low and ("not present" in low or "missing" in low):
                category, severity = "misconfiguration", Severity.NIEDRIG
            if "outdated" in low or "is out of date" in low:
                category, severity = "outdated_component", Severity.HOCH
            if "sql" in low and "inject" in low:
                category, severity = "injection", Severity.HOCH
            findings.append(Finding(
                title=text[:120],
                category=category,
                severity=severity,
                asset=target,
                location=target,
                evidence=text,
                source="nikto",
                status="offen",
            ))
        return findings
