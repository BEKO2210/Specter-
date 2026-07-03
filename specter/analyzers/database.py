"""Defensive Analyse der Datenbank-Exposition aus einem bereitgestellten Export.

Wertet einen lokalen JSON-Export der Datenbank-Landschaft aus und erkennt die
klassischen, im Mittelstand häufigen Fehler, über die Datenbanken kompromittiert
werden: öffentlich erreichbare DB-Ports, fehlende Authentifizierung (typisch bei
Redis/MongoDB in Standardinstallationen), Standard-/Default-Zugangsdaten und
unverschlüsselter Transport - rein offline, ohne Live-Verbindung, ohne Ausnutzung.
Der Labor-Kollektor (`examples/live_lab/run_db_lab.py`) kann einen echten, selbst
gestarteten Datenbank-Container abtasten und in die hier erwartete Struktur bringen.

Erwartete Struktur (alle Felder optional):

    {
      "databases": [
        {
          "engine": "redis", "port": 6379,
          "public": true,            # aus dem Internet/fremden Netz erreichbar?
          "auth_required": false,    # verlangt der Dienst Authentifizierung?
          "tls": false,              # ist der Transport verschlüsselt?
          "default_creds": false     # sind Standard-Zugangsdaten aktiv?
        }
      ]
    }

Es werden keine bestehenden/neuen Kategorien erfunden - die Befunde nutzen die
etablierten Kategorien (exponierter Dienst, schwache Authentifizierung, Default-
Zugangsdaten, unsichere Transportverschlüsselung).
"""

from __future__ import annotations

from typing import Any

from ..findings import Finding, Severity

# Bekannte Datenbank-Standardports (nur für verständlichere Belege).
DB_PORTS: dict[int, str] = {
    3306: "MySQL/MariaDB", 5432: "PostgreSQL", 1433: "Microsoft SQL Server",
    1521: "Oracle", 27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch",
    5984: "CouchDB", 11211: "Memcached", 7000: "Cassandra", 8086: "InfluxDB",
}


def _mk(title, category, severity, asset, evidence, *, cwe="",
        owner="Datenbank-/IT-Team") -> Finding:
    return Finding(
        title=title, category=category, severity=severity, asset=asset,
        location=asset, evidence=evidence, cwe=cwe, owner=owner,
        source="database_analyzer", status="offen",
    )


def _label(db: dict[str, Any]) -> tuple[str, str]:
    """Liefert (Anzeigename, Ort) für eine Datenbank aus engine/port."""
    engine = str(db.get("engine", "")).strip()
    try:
        port = int(db.get("port", 0))
    except (TypeError, ValueError):
        port = 0
    if not engine and port in DB_PORTS:
        engine = DB_PORTS[port]
    name = engine or "Datenbank"
    loc = f"{name}:{port}" if port else name
    return name, loc


def _analyze_db(db: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    name, loc = _label(db)

    if db.get("public"):
        out.append(_mk(
            f"Datenbank öffentlich erreichbar: {name}", "exposed_service",
            Severity.HOCH, loc,
            "Der Datenbank-Port ist aus fremden Netzen erreichbar - gehört hinter "
            "Firewall/VPN, niemals offen ins Internet", cwe="CWE-668"))

    # auth_required kann explizit False sein; fehlt der Schlüssel, nicht bewerten.
    if db.get("auth_required") is False:
        out.append(_mk(
            f"Datenbank ohne Authentifizierung: {name}", "auth_weakness",
            Severity.HOCH, loc,
            "Der Dienst verlangt keine Anmeldung - jeder mit Netzzugang kann lesen/"
            "schreiben (typisch bei Redis/MongoDB-Standardinstallationen)",
            cwe="CWE-306"))

    if db.get("default_creds"):
        out.append(_mk(
            f"Standard-/Default-Zugangsdaten: {name}", "default_credentials",
            Severity.KRITISCH, loc,
            "Aktive Default-Zugangsdaten - sofort ändern; öffentlich bekannt und "
            "erstes Angriffsziel", cwe="CWE-798"))

    if db.get("tls") is False:
        out.append(_mk(
            f"Unverschlüsselter Datenbank-Transport: {name}", "transport_security",
            Severity.MITTEL, loc,
            "Verbindungen ohne TLS - Zugangsdaten und Daten sind im Netz mitlesbar",
            cwe="CWE-319"))
    return out


def analyze_database(data: dict[str, Any]) -> list[Finding]:
    """Führt alle Datenbank-Expositionsprüfungen aus und liefert die Findings."""
    if not isinstance(data, dict):
        return []
    databases = data.get("databases")
    if not isinstance(databases, list):
        return []
    findings: list[Finding] = []
    for db in databases:
        if isinstance(db, dict):
            findings += _analyze_db(db)
    return findings
