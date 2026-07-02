#!/usr/bin/env python3
"""Erzeugt den Specter-Zielkunden-/Akquiseplan als HTML (zum PDF-Drucken).

Aufruf (aus dem Repo-Wurzelverzeichnis):
    python examples/build_acquisition_plan.py
    python examples/build_acquisition_plan.py "Ludwigsburg/Stuttgart"

Danach die Datei im Browser oeffnen und ueber "Drucken -> Als PDF speichern"
ein sauberes Handout erstellen.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from specter.acquisition import write_acquisition  # noqa: E402


def main() -> int:
    region = sys.argv[1] if len(sys.argv) > 1 else "Ludwigsburg/Stuttgart"
    out = write_acquisition(REPO_ROOT / "reports", region=region)
    print("=" * 70)
    print(" Specter - Zielkunden-/Akquiseplan erzeugt")
    print("=" * 70)
    print(f"[i] Datei: {out}")
    print(f"[i] Region: {region}")
    print("[i] Im Browser oeffnen und 'Drucken -> Als PDF speichern' waehlen.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
