"""Sichere Wrapper für aktive Scanner (nmap, nikto).

Jeder Scanner läuft nur, wenn er in scope.yaml ausdrücklich freigegeben ist,
gegen ein Ziel im Netzwerk-Scope, mit strikt geprüfter Argumentliste
(Allowlist + Blocklist gefährlicher Flags), ohne Shell, mit Timeout und
begrenzter Ausgabe. Ergebnisse werden strukturiert als Findings übernommen.
"""

from .base import Scanner, ScannerError, ScannerResult
from .nikto import NiktoScanner
from .nmap import NmapScanner

SCANNERS: dict[str, type[Scanner]] = {
    NmapScanner.name: NmapScanner,
    NiktoScanner.name: NiktoScanner,
}


def get_scanner(name: str) -> Scanner | None:
    cls = SCANNERS.get(name)
    return cls() if cls else None


__all__ = [
    "Scanner", "ScannerError", "ScannerResult",
    "NmapScanner", "NiktoScanner", "SCANNERS", "get_scanner",
]
