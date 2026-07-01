"""Tool: Code auf typische Sicherheitsmuster durchsuchen.

Statische, regelbasierte Vorfilterung (kein Ersatz fuer ein echtes SAST, aber
ein schneller Einstieg). Findet Kandidaten und legt sie - wie bei Esprit - als
strukturierte Findings automatisch im Store ab. Das Modell verifiziert und
ergaenzt sie anschliessend.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..audit import AuditLog
from ..config import Config
from ..findings import Finding, Severity
from ..safety import SafetyPolicy, ScopeViolation
from ..state import EngagementState
from .base import ToolResult


@dataclass
class Pattern:
    regex: re.Pattern[str]
    description: str
    severity: Severity
    category: str
    cwe: str


# Muster -> Beschreibung, Schweregrad, Finding-Kategorie, CWE.
PATTERNS: list[Pattern] = [
    Pattern(
        re.compile(r"""(?i)(password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*['"][^'"]{3,}['"]"""),
        "Moeglicherweise fest kodiertes Secret/Passwort", Severity.HOCH,
        "secret_exposure", "CWE-798"),
    Pattern(
        re.compile(r"(?i)aws_secret_access_key\s*[:=]"),
        "AWS-Secret im Klartext", Severity.HOCH, "secret_exposure", "CWE-798"),
    Pattern(
        re.compile(r"\beval\s*\(|\bexec\s*\("),
        "Dynamische Codeausfuehrung (eval/exec)", Severity.HOCH,
        "injection", "CWE-95"),
    Pattern(
        re.compile(r"subprocess\.(call|run|Popen)\([^)]*shell\s*=\s*True"),
        "Shell-Injection-Risiko (shell=True)", Severity.HOCH,
        "injection", "CWE-78"),
    Pattern(
        re.compile(r"""(?i)(SELECT|INSERT|UPDATE|DELETE)\b.*(\+|%|\.format\(|f['"])"""),
        "Moegliche SQL-Injection (String-Verkettung in Query)", Severity.HOCH,
        "injection", "CWE-89"),
    Pattern(
        re.compile(r"\bmd5\s*\(|\bsha1\s*\(|hashlib\.(md5|sha1)\b"),
        "Schwacher Hash-Algorithmus (MD5/SHA1)", Severity.MITTEL,
        "crypto_weakness", "CWE-327"),
    Pattern(
        re.compile(r"verify\s*=\s*False|CERT_NONE|InsecureRequestWarning"),
        "TLS-Zertifikatspruefung deaktiviert", Severity.MITTEL,
        "transport_security", "CWE-295"),
    Pattern(
        re.compile(r"(?i)pickle\.loads?\(|yaml\.load\((?!.*Loader)"),
        "Unsichere Deserialisierung (pickle/yaml.load)", Severity.MITTEL,
        "deserialization", "CWE-502"),
    Pattern(
        re.compile(r"DEBUG\s*=\s*True"),
        "Debug-Modus aktiviert (Produktionsrisiko)", Severity.NIEDRIG,
        "misconfiguration", "CWE-489"),
]

DEFAULT_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".php", ".rb", ".go",
    ".c", ".cpp", ".cs", ".yml", ".yaml", ".env", ".ini", ".conf", ".sh",
}


class CodeScanTool:
    name = "scan_code"
    active = False

    def __init__(
        self,
        config: Config,
        policy: SafetyPolicy,
        audit: AuditLog,
        state: EngagementState,
    ) -> None:
        self.config = config
        self.policy = policy
        self.audit = audit
        self.state = state

    @property
    def spec(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": (
                "Durchsucht ein Verzeichnis (innerhalb des Datei-Scopes) rekursiv "
                "nach typischen Sicherheitsmustern: fest kodierte Secrets, "
                "eval/exec, shell=True, moegliche SQL-Injection, schwache Hashes, "
                "deaktivierte TLS-Pruefung u. a. Fundstellen werden automatisch "
                "als Findings (mit Kategorie, Schweregrad, CWE) erfasst. "
                "Ergebnisse sind Kandidaten und muessen verifiziert werden."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Startverzeichnis (innerhalb des Scopes).",
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Obergrenze fuer Fundstellen (Standard 200).",
                    },
                },
                "required": ["path"],
            },
        }

    def run(self, arguments: dict[str, Any]) -> ToolResult:
        raw_path = str(arguments.get("path", "")).strip()
        max_results = int(arguments.get("max_results", 200))
        try:
            root = self.policy.check_path(raw_path)
        except ScopeViolation as exc:
            self.audit.record("scan_code.denied", path=raw_path, reason=str(exc))
            return ToolResult(f"VERWEIGERT: {exc}", is_error=True)

        files = [root] if root.is_file() else self._iter_files(root)
        lines: list[str] = []
        recorded = 0
        scanned = 0
        for file in files:
            if len(lines) >= max_results:
                break
            try:
                if file.stat().st_size > self.config.max_file_bytes:
                    continue
                text = file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            scanned += 1
            for lineno, line in enumerate(text.splitlines(), start=1):
                for pat in PATTERNS:
                    if pat.regex.search(line):
                        snippet = line.strip()[:160]
                        location = f"{file}:{lineno}"
                        lines.append(
                            f"[{pat.severity.label}] {location} - {pat.description}\n"
                            f"        {snippet}"
                        )
                        finding = Finding(
                            title=pat.description,
                            category=pat.category,
                            severity=pat.severity,
                            asset=str(file),
                            location=location,
                            evidence=snippet,
                            cwe=pat.cwe,
                            source="static_scan",
                            status="offen",
                        )
                        _, is_new = self.state.findings.add(finding)
                        recorded += int(is_new)
                        if len(lines) >= max_results:
                            break

        self.audit.record(
            "scan_code.ok", path=str(root), files=scanned,
            findings=len(lines), recorded=recorded,
        )
        if not lines:
            return ToolResult(
                f"Keine verdaechtigen Muster in {scanned} Datei(en) gefunden."
            )
        header = (
            f"{len(lines)} Fundstelle(n) in {scanned} Datei(en), "
            f"{recorded} neu als Finding erfasst:\n"
        )
        return ToolResult(header + "\n".join(lines))

    def _iter_files(self, root: Path):
        for path in sorted(root.rglob("*")):
            if path.is_file() and path.suffix.lower() in DEFAULT_EXTENSIONS:
                yield path
