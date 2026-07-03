"""Choke-Point-Analyse: die engsten Behebungsstellen.

Findet die kleinste Menge von Findings, deren Behebung möglichst viele (idealer-
weise alle) Angriffspfade unterbricht. Ein Pfad gilt als unterbrochen, sobald
mindestens eines seiner Findings behoben ist (Hitting-Set-Problem). Da das exakt
NP-schwer ist, wird eine deterministische Greedy-Näherung verwendet: wiederholt
das Finding wählen, das die meisten noch offenen Pfade bricht.

Nutzen für den Kunden: "Behebe zuerst X - das schließt N Angriffspfade auf
einmal", statt jede einzelne Schwachstelle gleich gewichtet abzuarbeiten.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .attack_paths import AttackPath


@dataclass
class ChokePoint:
    finding_id: str
    paths_broken: int                 # Anzahl Pfade, die dieses Finding enthält
    path_titles: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "paths_broken": self.paths_broken,
            "path_titles": self.path_titles,
        }


def compute_choke_points(paths: list[AttackPath]) -> list[ChokePoint]:
    """Greedy-Hitting-Set: minimale Findings-Menge, die alle Pfade bricht.

    Rückgabe: geordnete Liste von Choke Points (wichtigster zuerst). Nur Pfade
    mit mindestens einem Finding werden berücksichtigt.
    """
    # Pfade mit Findings indexieren.
    indexed = [(i, p) for i, p in enumerate(paths) if p.finding_ids]
    remaining = set(i for i, _ in indexed)
    if not remaining:
        return []

    # finding_id -> Menge der Pfad-Indizes, die es enthalten (Gesamtabdeckung).
    coverage: dict[str, set[int]] = {}
    for i, p in indexed:
        for fid in p.finding_ids:
            coverage.setdefault(fid, set()).add(i)

    result: list[ChokePoint] = []
    while remaining:
        # Wähle das Finding, das die meisten NOCH OFFENEN Pfade bricht.
        # Deterministischer Tie-Break: mehr neue Pfade, dann größere
        # Gesamtabdeckung, dann alphabetisch nach finding_id.
        best_fid = min(
            coverage.keys(),
            key=lambda fid: (
                -len(coverage[fid] & remaining),
                -len(coverage[fid]),
                fid,
            ),
        )
        # Invariante: jeder noch offene Pfad hat >=1 Finding in coverage,
        # daher deckt best_fid garantiert mindestens einen offenen Pfad ab.
        newly = coverage[best_fid] & remaining
        total = coverage[best_fid]
        titles: list[str] = []
        for i in sorted(total):
            title = paths[i].title
            if title not in titles:
                titles.append(title)
        result.append(ChokePoint(
            finding_id=best_fid,
            paths_broken=len(total),
            path_titles=titles,
        ))
        remaining -= newly
    return result
