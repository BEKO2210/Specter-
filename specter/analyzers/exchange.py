"""Defensive Exchange-Analyse aus bereitgestellten Daten.

Wertet passiv erhobene Angaben zu einem Exchange-Server aus (Version/Build,
extern erreichbare Dienste, TLS-Konfiguration, HTTP-Header) und leitet
typische Risiken ab. Keine Live-Ausnutzung; aktive HTTP-Checks laufen ggf.
separat ueber den freigegebenen Scanner-/Kommandopfad.

Erwartete Struktur (alle Felder optional):

    {
      "host": "mail.example.de",
      "product": "Exchange 2016",
      "build": "15.1.2375.7",
      "external_services": ["OWA", "ECP", "Autodiscover"],
      "tls": {"protocols": ["TLSv1.0", "TLSv1.2"]},
      "headers": {"Strict-Transport-Security": null, "X-Frame-Options": "DENY"},
      "server_header": "Microsoft-IIS/10.0"
    }
"""

from __future__ import annotations

from typing import Any

from ..findings import Finding, Severity

# Heuristische Richtwerte fuer die dritte Build-Zahl je (major, minor).
# Unterhalb dieser Werte gilt der Server als ungepatcht (ProxyLogon/ProxyShell-Aera).
SAFE_BUILD_MIN = {
    (15, 2): 1544,   # Exchange 2019
    (15, 1): 2507,   # Exchange 2016
    (15, 0): 1497,   # Exchange 2013
}
WEAK_TLS = {"tlsv1.0", "tls1.0", "tlsv1.1", "tls1.1", "sslv3", "ssl3"}
SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
}


def _mk(title, category, severity, host, evidence, *, cwe="", owner="Messaging-Team",
        location="") -> Finding:
    return Finding(
        title=title, category=category, severity=severity, asset=host,
        location=location or host, evidence=evidence, cwe=cwe, owner=owner,
        source="exchange_analyzer", status="offen",
    )


def _parse_build(build: Any) -> tuple[int, int, int] | None:
    if not isinstance(build, str):
        return None
    parts = build.split(".")
    try:
        nums = [int(p) for p in parts[:3]]
    except ValueError:
        return None
    if len(nums) < 3:
        return None
    return nums[0], nums[1], nums[2]


def _analyze_version(product: Any, build: Any, host: str) -> list[Finding]:
    parsed = _parse_build(build)
    if parsed is None:
        return []
    major, minor, third = parsed
    if major < 15:
        return [_mk(
            f"End-of-Life Exchange erkannt (Build {build})", "outdated_component",
            Severity.KRITISCH, host,
            f"{product or 'Exchange'} Build {build} - keine Sicherheitsupdates mehr",
            cwe="CWE-1104",
        )]
    threshold = SAFE_BUILD_MIN.get((major, minor))
    if threshold is not None and third < threshold:
        return [_mk(
            f"Veraltete Exchange-Version (Build {build})", "outdated_component",
            Severity.KRITISCH, host,
            f"{product or 'Exchange'} Build {build} < Richtwert {major}.{minor}.{threshold} "
            "- moeglicherweise anfaellig fuer ProxyLogon (CVE-2021-26855) / "
            "ProxyShell (CVE-2021-34473)",
            cwe="CWE-1104",
        )]
    return []


def _analyze_services(services: Any, host: str) -> list[Finding]:
    out: list[Finding] = []
    svc = {str(s).strip().lower() for s in (services or [])}
    if "ecp" in svc:
        out.append(_mk(
            "Exchange-ECP (Admin-Oberflaeche) extern erreichbar", "misconfiguration",
            Severity.HOCH, host,
            "external_services enthaelt 'ECP' - Admin-Panel sollte nicht im Internet stehen",
            cwe="CWE-284", location=f"{host}/ecp",
        ))
    if "owa" in svc:
        out.append(_mk(
            "OWA extern erreichbar (Angriffsflaeche/Password-Spraying)",
            "exposed_service", Severity.MITTEL, host,
            "external_services enthaelt 'OWA'", location=f"{host}/owa",
        ))
    if "autodiscover" in svc:
        out.append(_mk(
            "Autodiscover extern erreichbar", "misconfiguration", Severity.NIEDRIG,
            host, "external_services enthaelt 'Autodiscover'",
            location=f"{host}/autodiscover",
        ))
    return out


def _analyze_tls(tls: Any, host: str) -> list[Finding]:
    protocols = {str(p).strip().lower() for p in ((tls or {}).get("protocols") or [])}
    weak = sorted(protocols & WEAK_TLS)
    if weak:
        return [_mk(
            f"Schwache TLS-Protokolle aktiv: {', '.join(weak)}", "transport_security",
            Severity.HOCH, host, f"tls.protocols enthaelt {weak}", cwe="CWE-327",
        )]
    return []


def _analyze_headers(headers: Any, server_header: Any, host: str) -> list[Finding]:
    out: list[Finding] = []
    if isinstance(headers, dict):
        present = {k.strip().lower(): v for k, v in headers.items()}
        for key, label in SECURITY_HEADERS.items():
            if not present.get(key):
                out.append(_mk(
                    f"Sicherheits-Header fehlt: {label}", "misconfiguration",
                    Severity.NIEDRIG, host, f"Header '{label}' nicht gesetzt",
                    cwe="CWE-693",
                ))
    if isinstance(server_header, str) and server_header.strip():
        out.append(_mk(
            "Server-Header gibt Produkt/Version preis", "misconfiguration",
            Severity.NIEDRIG, host, f"Server: {server_header}", cwe="CWE-200",
        ))
    return out


def analyze_exchange(data: dict[str, Any]) -> list[Finding]:
    """Fuehrt alle Exchange-Pruefungen aus und liefert die Findings."""
    if not isinstance(data, dict):
        return []
    host = str(data.get("host", "exchange-server"))
    findings: list[Finding] = []
    findings += _analyze_version(data.get("product"), data.get("build"), host)
    findings += _analyze_services(data.get("external_services"), host)
    findings += _analyze_tls(data.get("tls"), host)
    findings += _analyze_headers(data.get("headers"), data.get("server_header"), host)
    return findings
