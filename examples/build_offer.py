#!/usr/bin/env python3
"""Erzeugt den Specter-Angebots-/Preis-One-Pager als HTML (zum PDF-Drucken).

Aufruf (aus dem Repo-Wurzelverzeichnis):
    python examples/build_offer.py
    python examples/build_offer.py "Muster GmbH" kontakt@example.de

Danach die Datei im Browser öffnen und über "Drucken -> Als PDF speichern"
ein sauberes Kunden-PDF erstellen.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from specter.offer import write_offer  # noqa: E402


def main() -> int:
    argv = sys.argv[1:]
    customer = argv[0] if argv else "Ihr Unternehmen"
    contact = argv[1] if len(argv) > 1 else "kontakt@example.de"
    out = write_offer(REPO_ROOT / "reports", customer_name=customer,
                      contact_email=contact)
    print("=" * 70)
    print(" Specter - Angebots-/Preis-One-Pager erzeugt")
    print("=" * 70)
    print(f"[i] Datei: {out}")
    print(f"[i] Kunde: {customer}  ·  Kontakt: {contact}")
    print("[i] Im Browser öffnen und 'Drucken -> Als PDF speichern' wählen.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
