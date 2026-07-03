"""Tool: einen freigegebenen aktiven Scanner (nmap/nikto) sicher ausführen."""

from __future__ import annotations

from typing import Any, Callable

from ..audit import AuditLog
from ..config import Config
from ..safety import SafetyPolicy, ScopeViolation
from ..scanners import SCANNERS, ScannerError, get_scanner
from ..state import EngagementState
from .base import ToolResult

ApprovalFn = Callable[[str], bool]


class RunScannerTool:
    name = "run_scanner"
    active = True

    def __init__(
        self,
        config: Config,
        policy: SafetyPolicy,
        audit: AuditLog,
        state: EngagementState,
        approval_fn: ApprovalFn | None = None,
    ) -> None:
        self.config = config
        self.policy = policy
        self.audit = audit
        self.state = state
        self.approval_fn = approval_fn or (lambda _cmd: True)

    @property
    def spec(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": (
                "Führt einen freigegebenen aktiven Scanner sicher aus "
                f"({', '.join(SCANNERS)}). Nur gegen Ziele im Netzwerk-Scope und "
                "nur, wenn der Scanner in scope.yaml aktiviert ist. Argumente "
                "werden streng geprüft; gefährliche Flags sind blockiert. "
                "Ergebnisse werden als Findings übernommen."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "scanner": {"type": "string", "enum": list(SCANNERS)},
                    "target": {"type": "string", "description": "Ziel im Netzwerk-Scope."},
                    "ports": {"type": "string", "description": "z. B. '80,443' oder '1-1024'."},
                    "aggressive": {
                        "type": "boolean",
                        "description": "Nur wirksam, wenn allow_aggressive in scope.yaml gesetzt ist.",
                    },
                    "extra_args": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Zusätzliche, streng geprüfte Flags (Allowlist).",
                    },
                    "rationale": {"type": "string", "description": "Begründung."},
                },
                "required": ["scanner", "target"],
            },
        }

    def run(self, arguments: dict[str, Any]) -> ToolResult:
        name = str(arguments.get("scanner", "")).strip()
        target = str(arguments.get("target", "")).strip()
        ports = arguments.get("ports")
        ports = str(ports).strip() if ports else None
        aggressive = bool(arguments.get("aggressive", False))
        extra_args = arguments.get("extra_args") or []
        if not isinstance(extra_args, list):
            return ToolResult("extra_args muss eine Liste sein.", is_error=True)
        extra_args = [str(a) for a in extra_args]
        rationale = str(arguments.get("rationale", "")).strip()

        scanner = get_scanner(name)
        if scanner is None:
            return ToolResult(f"Unbekannter Scanner: {name}", is_error=True)

        policy = self.config.scanner_policy(name)

        # Vorab-Validierung (Freigabe/Scope/Argumente) OHNE Ausführung.
        try:
            if not policy.enabled:
                raise ScannerError(
                    f"Scanner '{name}' ist nicht freigegeben "
                    f"(scanners.{name}.enabled: true in scope.yaml)."
                )
            host = self.policy.check_target(target)
            if aggressive and not policy.allow_aggressive:
                raise ScannerError(
                    f"Aggressiver Modus für '{name}' nicht freigegeben."
                )
            argv = scanner.build_argv(host, policy, ports, aggressive, extra_args)
        except (ScannerError, ScopeViolation) as exc:
            self.audit.record("run_scanner.denied", scanner=name,
                              target=target, reason=str(exc))
            return ToolResult(f"VERWEIGERT: {exc}", is_error=True)

        command_str = " ".join(argv)
        if not self.approval_fn(command_str):
            self.audit.record("run_scanner.rejected_by_user", command=command_str)
            return ToolResult("Vom Benutzer abgelehnt.", is_error=True)

        self.audit.record("run_scanner.exec", scanner=name, command=command_str,
                          rationale=rationale)
        result = scanner.run(host, policy, self.policy, ports, aggressive, extra_args)

        recorded = self.state.findings.extend(result.findings)
        self.state.scanner_runs.append(result.to_dict())
        self.audit.record("run_scanner.done", scanner=name,
                          returncode=result.returncode, findings=len(result.findings),
                          recorded=recorded, error=result.error or None)

        if result.error:
            return ToolResult(
                f"Scanner '{name}' Lauf gegen {host}: {result.error}", is_error=True
            )
        lines = [
            f"Scanner '{name}' gegen {host} abgeschlossen (Exit {result.returncode}).",
            f"{len(result.findings)} Finding(s), {recorded} neu erfasst.",
        ]
        if result.truncated:
            lines.append("(Ausgabe gekürzt - Obergrenze erreicht.)")
        if result.findings:
            lines.append("Gefunden:")
            for f in result.findings[:20]:
                lines.append(f"  [{f.severity.label}] {f.title} ({f.location})")
        return ToolResult("\n".join(lines))
