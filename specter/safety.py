"""Scope-Durchsetzung ("Rules of Engagement").

Diese Schicht steht zwischen dem Sprachmodell und der echten Welt. Sie ist
absichtlich streng und schlaegt im Zweifel fehl (fail-closed): Was nicht
explizit erlaubt ist, wird verweigert.

Drei Pruefungen:
  * check_path     - Datei liegt innerhalb der freigegebenen Verzeichnisse.
  * check_target   - Host/IP liegt im freigegebenen Netzwerk-Scope.
  * check_command  - Binary ist erlaubt und die Argumente zielen nur auf
                     freigegebene Hosts.
"""

from __future__ import annotations

import ipaddress
import shlex
from pathlib import Path
from urllib.parse import urlparse

from .config import Config


class ScopeViolation(Exception):
    """Wird ausgeloest, wenn eine Aktion den autorisierten Rahmen verlaesst."""


class SafetyPolicy:
    def __init__(self, config: Config) -> None:
        self.config = config

    # -- Dateisystem --------------------------------------------------------

    def check_path(self, raw_path: str) -> Path:
        """Loest einen Pfad auf und stellt sicher, dass er im Scope liegt."""
        if not self.config.allowed_paths:
            raise ScopeViolation(
                "Kein Datei-Scope konfiguriert (filesystem.allowed_paths ist leer)."
            )
        resolved = Path(raw_path).expanduser().resolve()
        for base in self.config.allowed_paths:
            if resolved == base or base in resolved.parents:
                return resolved
        raise ScopeViolation(
            f"Pfad ausserhalb des Scope: {resolved}. "
            f"Erlaubt sind nur: {', '.join(str(p) for p in self.config.allowed_paths)}"
        )

    # -- Netzwerk-Ziele -----------------------------------------------------

    def check_target(self, target: str) -> str:
        """Prueft einen einzelnen Host/eine IP gegen den Netzwerk-Scope."""
        host = self._normalize_host(target)

        # Verbotsliste hat immer Vorrang.
        for forbidden in self.config.forbidden_targets:
            if self._matches(host, forbidden):
                raise ScopeViolation(f"Ziel steht auf der Sperrliste: {host}")

        if not self.config.allowed_targets:
            raise ScopeViolation(
                "Kein Netzwerk-Scope konfiguriert (network.allowed_targets ist leer)."
            )
        for allowed in self.config.allowed_targets:
            if self._matches(host, allowed):
                return host
        raise ScopeViolation(
            f"Ziel ausserhalb des autorisierten Scope: {host}. "
            "Nur freigegebene Hosts/Netze duerfen aktiv geprueft werden."
        )

    # -- Terminal-Befehle ---------------------------------------------------

    def check_command(self, command: str) -> list[str]:
        """Zerlegt einen Befehl, prueft Binary und enthaltene Ziele.

        Gibt die Argumentliste (fuer subprocess ohne shell=True) zurueck.
        """
        try:
            argv = shlex.split(command)
        except ValueError as exc:
            raise ScopeViolation(f"Befehl nicht parsebar: {exc}") from exc
        if not argv:
            raise ScopeViolation("Leerer Befehl.")

        self._reject_shell_metacharacters(command)

        binary = Path(argv[0]).name
        if binary not in self.config.allowed_binaries:
            raise ScopeViolation(
                f"Programm '{binary}' ist nicht in der Allowlist. "
                f"Erlaubt: {', '.join(self.config.allowed_binaries) or '(keine)'}"
            )

        # Jedes Argument, das wie ein Host/eine URL aussieht, muss im Scope liegen.
        targets = [a for a in argv[1:] if self._looks_like_target(a)]
        if not targets:
            raise ScopeViolation(
                "Im Befehl wurde kein pruefbares Ziel gefunden. "
                "Aktive Befehle muessen ein freigegebenes Ziel benennen."
            )
        for tgt in targets:
            self.check_target(tgt)
        return argv

    # -- Hilfsfunktionen ----------------------------------------------------

    @staticmethod
    def _reject_shell_metacharacters(command: str) -> None:
        # Selbst ohne shell=True: keine Verkettungsversuche zulassen.
        forbidden = [";", "|", "&", "$(", "`", ">", "<", "\n"]
        for token in forbidden:
            if token in command:
                raise ScopeViolation(
                    f"Unerlaubtes Shell-Metazeichen im Befehl: '{token}'. "
                    "Nur einzelne Programmaufrufe sind erlaubt."
                )

    @staticmethod
    def _normalize_host(target: str) -> str:
        target = target.strip()
        if "://" in target:
            parsed = urlparse(target)
            return parsed.hostname or target
        # host:port abtrennen (aber IPv6 nicht kaputt machen)
        if target.count(":") == 1:
            return target.split(":", 1)[0]
        return target

    @staticmethod
    def _looks_like_target(arg: str) -> bool:
        if arg.startswith("-"):
            return False  # Flag, kein Ziel
        if "://" in arg or "." in arg or ":" in arg:
            return True
        return False

    @staticmethod
    def _matches(host: str, rule: str) -> bool:
        """True, wenn host der Regel entspricht (exakt, CIDR oder IP-in-Netz)."""
        if host == rule:
            return True
        try:
            net = ipaddress.ip_network(rule, strict=False)
        except ValueError:
            return False  # rule ist ein Hostname -> nur exakter Vergleich (oben)
        try:
            return ipaddress.ip_address(host) in net
        except ValueError:
            return False  # host ist ein Name, rule ein Netz -> kein Match
