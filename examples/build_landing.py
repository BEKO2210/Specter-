#!/usr/bin/env python3
"""Erzeugt die Specter-Landingpage als eigenstaendiges HTML.

So aufrufen (aus dem Repo-Wurzelverzeichnis):
    python examples/build_landing.py

Danach die Datei im Browser oeffnen (Vorschau) oder direkt hosten. Die
Kontaktadresse laesst sich anpassen:
    python examples/build_landing.py deine@mailadresse.de
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from specter.landing import write_landing  # noqa: E402


def main() -> int:
    contact = sys.argv[1] if len(sys.argv) > 1 else "kontakt@specter-security.de"
    out = write_landing(REPO_ROOT / "reports", contact_email=contact)
    print("=" * 70)
    print(" Specter - Landingpage erzeugt")
    print("=" * 70)
    print(f"[i] Datei: {out}")
    print(f"[i] Kontaktadresse: {contact}")
    print("[i] Im Browser oeffnen (Vorschau) oder auf deinem Webspace hochladen.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
