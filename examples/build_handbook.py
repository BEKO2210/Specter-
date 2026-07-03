#!/usr/bin/env python3
"""Erzeugt das Specter-Lern-/Bedien-Handbuch als HTML (zum PDF-Drucken).

So aufrufen (aus dem Repo-Wurzelverzeichnis):
    python examples/build_handbook.py

Danach die erzeugte Datei im Browser öffnen und über
"Drucken -> Als PDF speichern" ein schönes PDF erstellen.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from specter.handbook import write_handbook  # noqa: E402


def main() -> int:
    out = write_handbook(REPO_ROOT / "reports", company_name="Specter Security")
    print("=" * 70)
    print(" Specter - Handbuch erzeugt")
    print("=" * 70)
    print(f"[i] Datei: {out}")
    print("[i] Im Browser öffnen und 'Drucken -> Als PDF speichern' wählen.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
