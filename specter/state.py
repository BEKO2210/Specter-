"""Geteilter Engagement-Zustand für die Agenten-Sitzung.

Bündelt Asset-Graph, Findings-Store und die zuletzt korrelierten Angriffspfade,
damit alle Werkzeuge auf denselben Stand zugreifen.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .assets import AssetGraph
from .attack_paths import AttackPath
from .findings import FindingsStore


@dataclass
class EngagementState:
    assets: AssetGraph = field(default_factory=AssetGraph)
    findings: FindingsStore = field(default_factory=FindingsStore)
    attack_paths: list[AttackPath] = field(default_factory=list)
    # Strukturierte Ergebnisse aktiver Scanner (für den Bericht).
    scanner_runs: list[dict[str, Any]] = field(default_factory=list)
    # Ergebnis eines Re-Tests (Vergleich mit frührerem Bericht), optional.
    delta: Any = None
