"""Reine Hilfsfunktionen für den Live-Datenbank-Check (Socket-Probe -> Export).

Der eigentliche Socket-Zugriff auf einen echten, selbst gestarteten Datenbank-
Container lebt bewusst im Labor-Runner (`examples/live_lab/run_db_lab.py`); hier
stehen nur die deterministischen, testbaren Bausteine: die Antwort eines echten
Redis-PING/AUTH-Probes interpretieren und daraus die Export-Struktur bauen, die
der Offline-Analyzer `analyze_database` erwartet.

So bleibt die Kernlogik testbar (offline, 100 % Coverage) und identisch zur
Kunden-Analyse - der Live-Check fuettert nur echte, selbst erhobene Daten ein.
Nur gegen eigene, selbst gestartete Systeme (defensiv, §202 StGB).
"""

from __future__ import annotations

from typing import Any


def redis_requires_auth(ping_response: str) -> bool:
    """Interpretiert die Antwort auf ein Redis-`PING` ohne vorherige Anmeldung.

    - `+PONG`  -> Server antwortet ohne Auth -> KEINE Authentifizierung nötig.
    - `-NOAUTH ...` / `-ERR ... auth ...` -> Auth wird verlangt.
    Bei leerer/unbekannter Antwort nehmen wir vorsichtshalber an, dass Auth greift
    (kein Fehlalarm).
    """
    r = str(ping_response).strip()
    if r.upper().startswith("+PONG"):
        return False
    low = r.lower()
    if "noauth" in low or "authentication" in low or "auth " in low:
        return True
    return True


def build_database_export(engine: str, host: str, port: int, *,
                          public: bool, ping_response: str,
                          tls: bool = False) -> dict[str, Any]:
    """Baut den Export für `analyze_database` aus einer echten Redis-Probe."""
    return {"databases": [{
        "engine": engine,
        "host": host,
        "port": port,
        "public": bool(public),
        "auth_required": redis_requires_auth(ping_response),
        "tls": bool(tls),
    }]}
