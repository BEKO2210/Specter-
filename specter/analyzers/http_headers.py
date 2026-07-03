"""Defensive Analyse von HTTP-Security-Headern und Cookie-Flags.

Wertet die bereitgestellten HTTP-Antwort-Header (und optional die Cookies) eines
oder mehrerer Endpunkte aus und erkennt fehlende bzw. schwache Schutzmechanismen -
rein offline, ohne Live-Abfrage, ohne Ausnutzung. Der Live-Kollektor
(`examples/live_web_check.py`) kann die Header echter Server abgreifen und in die
hier erwartete Struktur bringen.

Erwartete Struktur (alle Felder optional):

    {
      "endpoints": [
        {
          "url": "https://portal.firma.de",
          "headers": {"Strict-Transport-Security": "max-age=31536000",
                      "Server": "Apache/2.4.29"},
          "cookies": [{"name": "SESSIONID", "secure": false,
                       "httponly": false, "samesite": "None"}]
        }
      ]
    }

Ein einzelner Endpunkt darf auch direkt (ohne `endpoints`-Liste) übergeben werden.
"""

from __future__ import annotations

import re
from typing import Any

from ..findings import Finding, Severity
from ._util import as_list

# HSTS gilt unter ~180 Tagen als zu kurz (Preload verlangt >= 1 Jahr).
MIN_HSTS_SECONDS = 15552000


def _mk(title, category, severity, asset, evidence, *, location="", cwe="",
        owner="Web-/IT-Team") -> Finding:
    return Finding(
        title=title, category=category, severity=severity, asset=asset,
        location=location or asset, evidence=evidence, cwe=cwe, owner=owner,
        source="http_headers_analyzer", status="offen",
    )


def _analyze_endpoint(ep: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    url = str(ep.get("url", "Endpunkt"))
    loc = f"{url}/headers"
    raw = ep.get("headers")
    headers = raw if isinstance(raw, dict) else {}
    h = {str(k).strip().lower(): str(v) for k, v in headers.items()}

    hsts = h.get("strict-transport-security", "").strip()
    if not hsts:
        out.append(_mk(
            f"Kein HSTS (Strict-Transport-Security): {url}", "transport_security",
            Severity.HOCH, url, "HSTS-Header fehlt - Downgrade-/MITM-Risiko",
            location=loc, cwe="CWE-319"))
    else:
        m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
        age = int(m.group(1)) if m else 0
        if age < MIN_HSTS_SECONDS:
            out.append(_mk(
                f"HSTS mit zu kurzer Gültigkeit ({age}s): {url}", "transport_security",
                Severity.NIEDRIG, url, f"max-age={age} - empfohlen >= {MIN_HSTS_SECONDS}",
                location=loc, cwe="CWE-319"))

    if not h.get("content-security-policy", "").strip():
        out.append(_mk(
            f"Keine Content-Security-Policy: {url}", "web_security", Severity.MITTEL,
            url, "CSP-Header fehlt - erschwert wirksamen XSS-Schutz",
            location=loc, cwe="CWE-1021"))

    if not h.get("x-frame-options", "").strip():
        out.append(_mk(
            f"Clickjacking-Schutz fehlt (X-Frame-Options): {url}", "web_security",
            Severity.MITTEL, url, "X-Frame-Options fehlt (alternativ CSP frame-ancestors)",
            location=loc, cwe="CWE-1021"))

    if h.get("x-content-type-options", "").strip().lower() != "nosniff":
        out.append(_mk(
            f"X-Content-Type-Options nicht 'nosniff': {url}", "web_security",
            Severity.NIEDRIG, url, "MIME-Sniffing möglich", location=loc, cwe="CWE-693"))

    if not h.get("referrer-policy", "").strip():
        out.append(_mk(
            f"Keine Referrer-Policy: {url}", "web_security", Severity.NIEDRIG, url,
            "Referrer-Policy-Header fehlt", location=loc, cwe="CWE-200"))

    if not h.get("permissions-policy", "").strip():
        out.append(_mk(
            f"Keine Permissions-Policy: {url}", "web_security", Severity.NIEDRIG, url,
            "Permissions-Policy-Header fehlt", location=loc, cwe="CWE-693"))

    server = h.get("server", "").strip()
    if server:
        out.append(_mk(
            f"Server-Banner verrät Software: {server}", "web_security",
            Severity.NIEDRIG, url, f"Server: {server}", location=loc, cwe="CWE-200"))
    xpb = h.get("x-powered-by", "").strip()
    if xpb:
        out.append(_mk(
            f"X-Powered-By verrät Software: {xpb}", "web_security", Severity.NIEDRIG,
            url, f"X-Powered-By: {xpb}", location=loc, cwe="CWE-200"))

    for c in as_list(ep.get("cookies")):
        if not isinstance(c, dict):
            continue
        name = str(c.get("name", "cookie"))
        if c.get("secure") is False:
            out.append(_mk(
                f"Cookie ohne Secure-Flag: {name}", "web_security", Severity.MITTEL,
                url, "secure=false - Übertragung auch unverschlüsselt möglich",
                location=loc, cwe="CWE-614"))
        if c.get("httponly") is False:
            out.append(_mk(
                f"Cookie ohne HttpOnly-Flag: {name}", "web_security", Severity.MITTEL,
                url, "httponly=false - per JavaScript auslesbar (XSS-Diebstahl)",
                location=loc, cwe="CWE-1004"))
        if str(c.get("samesite", "")).strip().lower() in ("", "none"):
            out.append(_mk(
                f"Cookie ohne SameSite-Schutz: {name}", "web_security", Severity.NIEDRIG,
                url, f"samesite={c.get('samesite') or '(fehlt)'} - CSRF-Risiko",
                location=loc, cwe="CWE-1275"))
    return out


def analyze_http_headers(data: dict[str, Any]) -> list[Finding]:
    """Führt alle HTTP-Header-/Cookie-Prüfungen aus und liefert die Findings."""
    if not isinstance(data, dict):
        return []
    endpoints = data.get("endpoints")
    if not isinstance(endpoints, list):
        endpoints = [data]
    findings: list[Finding] = []
    for ep in endpoints:
        if isinstance(ep, dict):
            findings += _analyze_endpoint(ep)
    return findings
