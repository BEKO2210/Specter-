"""Tool: Terminal-Befehl ausfuehren (Netzwerk-Scan etc.) - die "Haende".

Streng abgesichert:
  * Nur Programme aus der Allowlist (commands.allowed_binaries).
  * Nur Ziele im Netzwerk-Scope (network.allowed_targets).
  * Kein shell=True; keine Shell-Metazeichen; hartes Timeout.
  * Optional Human-in-the-loop-Bestaetigung (runtime.require_approval).
"""

from __future__ import annotations

import subprocess
from typing import Any, Callable

from ..audit import AuditLog
from ..config import Config
from ..safety import SafetyPolicy, ScopeViolation
from .base import ToolResult

# Callback fuer manuelle Freigabe: (befehl) -> bool. Standard: automatisch True,
# wird von der CLI ueberschrieben, wenn require_approval aktiv ist.
ApprovalFn = Callable[[str], bool]


class RunCommandTool:
    name = "run_command"
    active = True

    def __init__(
        self,
        config: Config,
        policy: SafetyPolicy,
        audit: AuditLog,
        approval_fn: ApprovalFn | None = None,
    ) -> None:
        self.config = config
        self.policy = policy
        self.audit = audit
        self.approval_fn = approval_fn or (lambda _cmd: True)

    @property
    def spec(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": (
                "Fuehrt EINEN erlaubten Kommandozeilen-Befehl aus (z. B. einen "
                "Netzwerk-Scan mit nmap) und gibt stdout/stderr zurueck. "
                "Nur Programme aus der Allowlist und nur gegen freigegebene "
                "Ziele. Keine Pipes, keine Verkettung. Nutze dies fuer aktive, "
                "aber autorisierte Pruefungen."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": (
                            "Vollstaendiger Befehl, z. B. 'nmap -sV 127.0.0.1'."
                        ),
                    },
                    "rationale": {
                        "type": "string",
                        "description": "Kurze Begruendung, warum dieser Schritt noetig ist.",
                    },
                },
                "required": ["command"],
            },
        }

    def run(self, arguments: dict[str, Any]) -> ToolResult:
        command = str(arguments.get("command", "")).strip()
        rationale = str(arguments.get("rationale", "")).strip()

        try:
            argv = self.policy.check_command(command)
        except ScopeViolation as exc:
            self.audit.record("run_command.denied", command=command, reason=str(exc))
            return ToolResult(f"VERWEIGERT: {exc}", is_error=True)

        if not self.approval_fn(command):
            self.audit.record("run_command.rejected_by_user", command=command)
            return ToolResult(
                "Vom Benutzer abgelehnt. Schlage einen anderen Schritt vor.",
                is_error=True,
            )

        self.audit.record("run_command.exec", command=command, rationale=rationale)
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=self.config.command_timeout,
                shell=False,
                check=False,
            )
        except FileNotFoundError:
            msg = f"Programm nicht installiert: {argv[0]}"
            self.audit.record("run_command.not_installed", command=command)
            return ToolResult(msg, is_error=True)
        except subprocess.TimeoutExpired:
            self.audit.record("run_command.timeout", command=command)
            return ToolResult(
                f"Zeitlimit ({self.config.command_timeout}s) ueberschritten.",
                is_error=True,
            )

        out = (proc.stdout or "").strip()
        err = (proc.stderr or "").strip()
        self.audit.record(
            "run_command.done", command=command, returncode=proc.returncode
        )
        parts = [f"Exit-Code: {proc.returncode}"]
        if out:
            parts.append(f"--- stdout ---\n{out}")
        if err:
            parts.append(f"--- stderr ---\n{err}")
        return ToolResult("\n".join(parts))
