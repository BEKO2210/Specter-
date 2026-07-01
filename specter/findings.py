"""Strukturierte Findings mit Schweregrad, Kategorie, Evidenz und Owner.

Entspricht der "Findings-Analyse"-Stufe von Esprit/Trident: jede Schwachstelle
wird nicht als Freitext, sondern als nachvollziehbarer Datensatz erfasst -
mit Schweregrad, CWE-Bezug, betroffenem Asset, Beleg (Evidenz), Owner und
Empfehlung. Das ist die Grundlage fuer Reports und Angriffspfad-Korrelation.
"""

from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass
from typing import Any, Iterable


class Severity(enum.IntEnum):
    """Schweregrad, sortierbar (hoeher = kritischer)."""

    INFO = 0
    NIEDRIG = 1
    MITTEL = 2
    HOCH = 3
    KRITISCH = 4

    @property
    def label(self) -> str:
        return {
            Severity.INFO: "Info",
            Severity.NIEDRIG: "Niedrig",
            Severity.MITTEL: "Mittel",
            Severity.HOCH: "Hoch",
            Severity.KRITISCH: "Kritisch",
        }[self]

    @classmethod
    def parse(cls, value: str | int | "Severity") -> "Severity":
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        key = str(value).strip().lower()
        table = {
            "info": cls.INFO, "informational": cls.INFO,
            "niedrig": cls.NIEDRIG, "low": cls.NIEDRIG, "gering": cls.NIEDRIG,
            "mittel": cls.MITTEL, "medium": cls.MITTEL,
            "hoch": cls.HOCH, "high": cls.HOCH,
            "kritisch": cls.KRITISCH, "critical": cls.KRITISCH,
        }
        if key not in table:
            raise ValueError(f"Unbekannter Schweregrad: {value}")
        return table[key]


# Stabile Kategorie-Kennungen (technisch) mit deutscher Anzeige.
CATEGORIES: dict[str, str] = {
    "secret_exposure": "Offengelegtes Geheimnis (Secret/Passwort)",
    "injection": "Injection (SQL/Command/Code)",
    "auth_weakness": "Schwache Authentifizierung",
    "access_control": "Fehlerhafte Zugriffskontrolle (IDOR/Privesc)",
    "crypto_weakness": "Schwache Kryptographie",
    "misconfiguration": "Fehlkonfiguration",
    "cloud_storage": "Offener/fehlkonfigurierter Cloud-Speicher",
    "transport_security": "Unsichere Transportverschluesselung",
    "deserialization": "Unsichere Deserialisierung",
    "exposed_service": "Exponierter Dienst/Port",
    "sensitive_data": "Sensible Daten erreichbar",
    "other": "Sonstiges",
}


@dataclass
class Finding:
    """Ein einzelnes, nachvollziehbares Finding."""

    title: str
    category: str
    severity: Severity
    asset: str
    evidence: str = ""
    location: str = ""            # Datei:Zeile oder Host:Port
    cwe: str = ""                 # z. B. "CWE-89"
    owner: str = ""               # Verantwortlicher (Team/Person)
    remediation: str = ""         # Empfohlene Gegenmassnahme
    source: str = "agent"         # static_scan | network | agent | manual
    status: str = "offen"         # offen | bestaetigt | verworfen | behoben
    id: str = ""

    def __post_init__(self) -> None:
        self.severity = Severity.parse(self.severity)
        if self.category not in CATEGORIES:
            self.category = "other"
        if not self.id:
            self.id = self._make_id()

    def _make_id(self) -> str:
        basis = f"{self.category}|{self.asset}|{self.location}|{self.title}"
        digest = hashlib.sha1(basis.encode("utf-8")).hexdigest()[:8]
        return f"SPEC-{digest}"

    @property
    def category_label(self) -> str:
        return CATEGORIES.get(self.category, CATEGORIES["other"])

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "category_label": self.category_label,
            "severity": self.severity.label,
            "severity_rank": int(self.severity),
            "asset": self.asset,
            "location": self.location,
            "evidence": self.evidence,
            "cwe": self.cwe,
            "owner": self.owner,
            "remediation": self.remediation,
            "source": self.source,
            "status": self.status,
        }


class FindingsStore:
    """Sammelt Findings und dedupliziert ueber die stabile ID."""

    def __init__(self) -> None:
        self._by_id: dict[str, Finding] = {}

    def add(self, finding: Finding) -> tuple[Finding, bool]:
        """Fuegt ein Finding hinzu. Rueckgabe: (Finding, is_new)."""
        if finding.id in self._by_id:
            return self._by_id[finding.id], False
        self._by_id[finding.id] = finding
        return finding, True

    def get(self, finding_id: str) -> Finding | None:
        return self._by_id.get(finding_id)

    def all(self) -> list[Finding]:
        return sorted(
            self._by_id.values(),
            key=lambda f: (-int(f.severity), f.category, f.asset),
        )

    def by_severity(self, minimum: Severity) -> list[Finding]:
        return [f for f in self.all() if f.severity >= minimum]

    def counts(self) -> dict[str, int]:
        result = {sev.label: 0 for sev in reversed(Severity)}
        for f in self._by_id.values():
            result[f.severity.label] += 1
        return result

    def __len__(self) -> int:
        return len(self._by_id)

    def extend(self, findings: Iterable[Finding]) -> int:
        added = 0
        for f in findings:
            _, is_new = self.add(f)
            added += int(is_new)
        return added
