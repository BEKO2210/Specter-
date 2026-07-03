"""Sicherer nmap-Wrapper.

Standardmäßig nur unprivilegierte, nicht-intrusive Scans (TCP-Connect,
Service-/Versionserkennung). Rohe/aggressive Scans, Evasion und Spoofing sind
blockiert bzw. an allow_aggressive gebunden.
"""

from __future__ import annotations

import re

from ..findings import Finding, Severity
from .base import Scanner

_PORT_LINE = re.compile(r"^(\d{1,5})/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$")

# Dienste, die aus dem Internet erreichbar besonders kritisch sind.
_HIGH_RISK_PORTS = {
    3389: ("remote_access", "RDP aus dem Netz erreichbar"),
    445: ("exposed_service", "SMB aus dem Netz erreichbar"),
    139: ("exposed_service", "NetBIOS aus dem Netz erreichbar"),
    23: ("exposed_service", "Telnet (unverschlüsselt) erreichbar"),
    21: ("exposed_service", "FTP (oft unverschlüsselt) erreichbar"),
    3306: ("exposed_service", "MySQL direkt erreichbar"),
    1433: ("exposed_service", "MS-SQL direkt erreichbar"),
    5900: ("remote_access", "VNC erreichbar"),
    5432: ("exposed_service", "PostgreSQL direkt erreichbar"),
}


class NmapScanner(Scanner):
    name = "nmap"
    binary = "nmap"

    SAFE_FLAGS = frozenset({
        "-sT", "-sV", "-Pn", "-F", "-n", "-6", "-sC", "-r", "-v",
        "--open", "-p", "--top-ports", "--version-light",
    })
    AGGRESSIVE_FLAGS = frozenset({
        "-A", "-sS", "-sU", "-O", "-T4", "-T5", "--version-all",
    })
    FORBIDDEN_FLAGS = frozenset({
        # Evasion / Spoofing / gefährliche Skripte / Dateiausgabe
        "-D", "-S", "--spoof-mac", "-e", "-f", "--mtu", "--data",
        "--data-string", "--data-length", "--send-eth", "--send-ip", "-b",
        "--badsum", "-g", "--source-port", "--proxies", "--script",
        "--script-args", "--script-args-file", "--interactive",
        "-oN", "-oX", "-oA", "-oG", "-oS", "--iflist", "--resume",
    })
    VALUE_FLAGS = frozenset({"-p", "--top-ports"})

    def default_argv(self, target: str, ports: str | None, aggressive: bool) -> list[str]:
        # Immer -Pn (keine Ping-Vorprüfung) und TCP-Connect (kein root nötig).
        args = ["-sT", "-sV", "-Pn", "--open"]
        if aggressive:
            args.append("--version-all")
        if ports:
            args += ["-p", ports]
        else:
            args += ["--top-ports", "1000"]
        args.append(target)
        return args

    def parse(self, stdout: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in stdout.splitlines():
            m = _PORT_LINE.match(line.strip())
            if not m:
                continue
            port = int(m.group(1))
            proto = m.group(2)
            service = m.group(3)
            version = (m.group(4) or "").strip()
            category, note = _HIGH_RISK_PORTS.get(
                port, ("exposed_service", f"Dienst {service} erreichbar")
            )
            severity = Severity.HOCH if port in _HIGH_RISK_PORTS else Severity.MITTEL
            evidence = f"{port}/{proto} open {service}"
            if version:
                evidence += f" {version}"
            findings.append(Finding(
                title=note,
                category=category,
                severity=severity,
                asset=target,
                location=f"{target}:{port}",
                evidence=evidence,
                cwe="CWE-668",
                source="nmap",
                status="offen",
            ))
        return findings
