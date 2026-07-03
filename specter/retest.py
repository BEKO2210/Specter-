"""Re-Test-/Delta-Modus: Vergleich mit einem früheren Bericht.

Liest einen früheren JSON-Bericht ein und stellt ihn den aktuellen Findings
gegenüber:
  * behoben          - im alten Bericht, jetzt nicht mehr vorhanden
  * neu              - jetzt vorhanden, im alten Bericht nicht
  * weiterhin offen  - in beiden (mit Alter in Tagen)

Der Abgleich erfolgt über die stabile Finding-ID (Hash aus Kategorie, Asset,
Fundstelle und Titel), sodass identische Schwachstellen zuverlässig
wiedererkannt werden. Alles rein lokal - kein externer Dienst.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from typing import Any

from .findings import Finding, FindingsStore


@dataclass
class DeltaResult:
    resolved: list[dict[str, Any]] = field(default_factory=list)   # aus altem Bericht
    new: list[Finding] = field(default_factory=list)               # aktuell neu
    still_open: list[Finding] = field(default_factory=list)        # in beiden
    previous_date: str = ""
    aging_days: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "previous_date": self.previous_date,
            "aging_days": self.aging_days,
            "counts": {
                "resolved": len(self.resolved),
                "new": len(self.new),
                "still_open": len(self.still_open),
            },
            "resolved": [
                {"id": r.get("id"), "title": r.get("title"),
                 "severity": r.get("severity"), "asset": r.get("asset")}
                for r in self.resolved
            ],
            "new": [f.id for f in self.new],
            "still_open": [f.id for f in self.still_open],
        }


def _parse_date(value: Any) -> _dt.date | None:
    if not isinstance(value, str) or not value.strip():
        return None
    # Format des Berichts: "YYYY-MM-DD HH:MM" - nur der Datumsteil zählt.
    head = value.strip().split(" ", 1)[0]
    try:
        return _dt.date.fromisoformat(head)
    except ValueError:
        return None


def compute_delta(
    previous: dict[str, Any],
    current: FindingsStore,
    today: _dt.date | None = None,
) -> DeltaResult:
    """Vergleicht einen früheren JSON-Bericht mit den aktuellen Findings."""
    prev_findings = previous.get("findings") if isinstance(previous, dict) else None
    if not isinstance(prev_findings, list):
        prev_findings = []
    prev_by_id: dict[str, dict[str, Any]] = {}
    for entry in prev_findings:
        if isinstance(entry, dict) and entry.get("id"):
            prev_by_id[str(entry["id"])] = entry

    current_by_id = {f.id: f for f in current.all()}

    resolved = [prev_by_id[i] for i in prev_by_id if i not in current_by_id]
    new = [current_by_id[i] for i in current_by_id if i not in prev_by_id]
    still_open = [current_by_id[i] for i in current_by_id if i in prev_by_id]

    previous_date = ""
    aging_days: int | None = None
    if isinstance(previous, dict):
        previous_date = str(previous.get("generated_at", "")).strip()
    prev_date = _parse_date(previous_date)
    if prev_date is not None:
        ref = today or _dt.date.today()
        aging_days = max(0, (ref - prev_date).days)

    return DeltaResult(
        resolved=resolved, new=new, still_open=still_open,
        previous_date=previous_date, aging_days=aging_days,
    )
