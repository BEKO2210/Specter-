"""Tool: Code auf typische Sicherheitsmuster durchsuchen.

Statische, regelbasierte Vorfilterung (kein Ersatz fuer ein echtes SAST, aber
ein schneller Einstieg). Findet Kandidaten, die das Modell dann bewertet.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..audit import AuditLog
from ..config import Config
from ..safety import SafetyPolicy, ScopeViolation
from .base import ToolResult

# (Muster, Beschreibung, Schweregrad). Absichtlich konservativ gehalten.
PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"""(?i)(password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*['"][^'"]{3,}['"]"""),
     "Moeglicherweise fest kodiertes Secret/Passwort", "hoch"),
    (re.compile(r"""(?i)aws_secret_access_key\s*[:=]"""),
     "AWS-Secret im Klartext", "hoch"),
    (re.compile(r"\beval\s*\(|\bexec\s*\("),
     "Dynamische Codeausfuehrung (eval/exec)", "hoch"),
    (re.compile(r"subprocess\.(call|run|Popen)\([^)]*shell\s*=\s*True"),
     "Shell-Injection-Risiko (shell=True)", "hoch"),
    (re.compile(r"""(?i)(SELECT|INSERT|UPDATE|DELETE)\b.*(\+|%|\.format\(|f['"])"""),
     "Moegliche SQL-Injection (String-Verkettung in Query)", "hoch"),
    (re.compile(r"\bmd5\s*\(|\bsha1\s*\(|hashlib\.(md5|sha1)\b"),
     "Schwacher Hash-Algorithmus (MD5/SHA1)", "mittel"),
    (re.compile(r"verify\s*=\s*False|CERT_NONE|InsecureRequestWarning"),
     "TLS-Zertifikatspruefung deaktiviert", "mittel"),
    (re.compile(r"""(?i)pickle\.loads?\(|yaml\.load\((?!.*Loader)"""),
     "Unsichere Deserialisierung (pickle/yaml.load)", "mittel"),
    (re.compile(r"DEBUG\s*=\s*True"),
     "Debug-Modus aktiviert (Produktionsrisiko)", "niedrig"),
]

DEFAULT_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".php", ".rb", ".go",
    ".c", ".cpp", ".cs", ".yml", ".yaml", ".env", ".ini", ".conf", ".sh",
}


class CodeScanTool:
    name = "scan_code"
    active = False

    def __init__(self, config: Config, policy: SafetyPolicy, audit: AuditLog) -> None:
        self.config = config
        self.policy = policy
        self.audit = audit

    @property
    def spec(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": (
                "Durchsucht ein Verzeichnis (innerhalb des Datei-Scopes) rekursiv "
                "nach typischen Sicherheitsmustern: fest kodierte Secrets, "
                "eval/exec, shell=True, moegliche SQL-Injection, schwache Hashes, "
                "deaktivierte TLS-Pruefung u. a. Liefert Fundstellen mit Datei, "
                "Zeile und Schweregrad. Ergebnisse sind Kandidaten und muessen "
                "verifiziert werden."
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
        findings: list[str] = []
        scanned = 0
        for file in files:
            if len(findings) >= max_results:
                break
            try:
                if file.stat().st_size > self.config.max_file_bytes:
                    continue
                text = file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            scanned += 1
            for lineno, line in enumerate(text.splitlines(), start=1):
                for pattern, desc, severity in PATTERNS:
                    if pattern.search(line):
                        snippet = line.strip()[:160]
                        findings.append(
                            f"[{severity}] {file}:{lineno} - {desc}\n        {snippet}"
                        )
                        if len(findings) >= max_results:
                            break

        self.audit.record(
            "scan_code.ok", path=str(root), files=scanned, findings=len(findings)
        )
        if not findings:
            return ToolResult(
                f"Keine verdaechtigen Muster in {scanned} Datei(en) gefunden."
            )
        header = f"{len(findings)} Fundstelle(n) in {scanned} Datei(en):\n"
        return ToolResult(header + "\n".join(findings))

    def _iter_files(self, root: Path):
        for path in sorted(root.rglob("*")):
            if path.is_file() and path.suffix.lower() in DEFAULT_EXTENSIONS:
                yield path
