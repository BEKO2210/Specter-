#!/usr/bin/env python3
"""Erzeugt den Kunden-Vertrauens-/Sicherheits-One-Pager als HTML (zum PDF-Drucken).

So aufrufen (aus dem Repo-Wurzelverzeichnis):
    python examples/build_trust_onepager.py

Danach die erzeugte Datei im Browser öffnen und über
"Drucken -> Als PDF speichern" ein schönes Kunden-PDF erstellen.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from specter.trust import write_trust_onepager  # noqa: E402


def main() -> int:
    out = write_trust_onepager(REPO_ROOT / "reports", customer_name="Muster GmbH")
    print("=" * 70)
    print(" Specter - Vertrauens-/Sicherheits-One-Pager erzeugt")
    print("=" * 70)
    print(f"[i] Datei: {out}")
    print("[i] Im Browser öffnen und 'Drucken -> Als PDF speichern' wählen.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
