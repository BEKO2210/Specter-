"""Reine Parser für den Live-Web/TLS-Check (curl/openssl-Ausgabe -> Export).

Der eigentliche Netzwerkabruf lebt im Beispiel-Runner (`examples/live_web_check.py`
bzw. `examples/live_lab/run_lab.py`); hier stehen nur die deterministischen,
testbaren Bausteine, die echte `curl`-/`openssl`-Ausgaben in die Export-Strukturen
bringen, die die Offline-Analyzer `analyze_http_headers` und `analyze_tls` erwarten.

So bleibt die Kernlogik offline testbar (100 % Coverage) und identisch zur
Kundenanalyse - der Live-Check füttert nur echte, selbst erhobene Daten ein. Der
Ablauf (`days_until`) bekommt das Bezugsdatum übergeben und ruft selbst keine
Systemuhr ab (Determinismus).
"""

from __future__ import annotations

import datetime as _dt
import re
from typing import Any

_MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}


# -- HTTP-Header (aus `curl -sSI`) -----------------------------------------

def parse_header_lines(raw: str) -> tuple[dict[str, str], list[str]]:
    """Zerlegt einen HTTP-Antwortkopf in (Header-Dict, Set-Cookie-Liste)."""
    headers: dict[str, str] = {}
    cookies: list[str] = []
    for line in str(raw).replace("\r", "").split("\n"):
        line = line.strip()
        if not line or line.upper().startswith("HTTP/"):
            continue
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        name, value = name.strip(), value.strip()
        if name.lower() == "set-cookie":
            cookies.append(value)
        else:
            headers[name] = value
    return headers, cookies


def parse_cookie(value: str) -> dict[str, Any]:
    """Parst einen Set-Cookie-Wert zu {name, secure, httponly, samesite}."""
    parts = [p.strip() for p in str(value).split(";") if p.strip()]
    name = parts[0].split("=", 1)[0].strip() if parts else "cookie"
    attrs = parts[1:]
    secure = any(p.lower() == "secure" for p in attrs)
    httponly = any(p.lower() == "httponly" for p in attrs)
    samesite = ""
    for p in attrs:
        if p.lower().startswith("samesite="):
            samesite = p.split("=", 1)[1].strip()
    return {"name": name, "secure": secure, "httponly": httponly, "samesite": samesite}


def build_headers_export(url: str, raw: str) -> dict[str, Any]:
    """Baut den Export für `analyze_http_headers` aus einer rohen curl-Antwort."""
    headers, cookie_values = parse_header_lines(raw)
    return {"url": url, "headers": headers,
            "cookies": [parse_cookie(c) for c in cookie_values]}


# -- TLS (aus `openssl s_client` + `openssl x509`) -------------------------

def parse_s_client(text: str) -> tuple[str, str]:
    """Zieht (Protokoll, Cipher) aus einer `openssl s_client`-Ausgabe."""
    protocol, cipher = "", ""
    for line in str(text).replace("\r", "").split("\n"):
        s = line.strip()
        m = re.match(r"Protocol\s*:\s*(\S+)", s, re.IGNORECASE)
        if m:
            protocol = m.group(1)
        m = re.match(r"Cipher\s*:\s*(\S+)", s, re.IGNORECASE)
        if m:
            cipher = m.group(1)
    return protocol, cipher


def parse_x509(text: str) -> dict[str, Any]:
    """Zieht Zertifikatsfelder aus einer `openssl x509 -text -enddate`-Ausgabe."""
    t = str(text)
    out: dict[str, Any] = {"not_after": "", "signature_algorithm": "",
                           "key_type": "", "key_bits": 0, "self_signed": False}
    m = re.search(r"notAfter=(.+)", t)
    if m:
        out["not_after"] = m.group(1).strip()
    m = re.search(r"Signature Algorithm:\s*(\S+)", t)
    if m:
        out["signature_algorithm"] = m.group(1).strip()
    m = re.search(r"Public-Key:\s*\((\d+) bit\)", t)
    if m:
        out["key_bits"] = int(m.group(1))
    if "id-ecPublicKey" in t:
        out["key_type"] = "EC"
    elif "rsaEncryption" in t:
        out["key_type"] = "RSA"
    subj = re.search(r"Subject:\s*(.+)", t)
    iss = re.search(r"Issuer:\s*(.+)", t)
    if subj and iss and subj.group(1).strip() == iss.group(1).strip():
        out["self_signed"] = True
    return out


def days_until(not_after: str, today: str) -> int | None:
    """Tage von `today` (YYYY-MM-DD) bis zum openssl-Datum; None bei Parsefehler."""
    m = re.search(r"([A-Za-z]{3})\s+(\d{1,2})\s+\d{2}:\d{2}:\d{2}\s+(\d{4})",
                  str(not_after))
    if not m:
        return None
    month = _MONTHS.get(m.group(1).lower())
    if month is None:
        return None
    expiry = _dt.date(int(m.group(3)), month, int(m.group(2)))
    year, mon, day = str(today).split("-")
    reference = _dt.date(int(year), int(mon), int(day))
    return (expiry - reference).days


def build_tls_export(host: str, s_client_text: str, x509_text: str,
                     today: str) -> dict[str, Any]:
    """Baut den Export für `analyze_tls` aus echten openssl-Ausgaben."""
    protocol, cipher = parse_s_client(s_client_text)
    x = parse_x509(x509_text)
    cert: dict[str, Any] = {
        "signature_algorithm": x["signature_algorithm"],
        "key_type": x["key_type"], "key_bits": x["key_bits"],
        "self_signed": x["self_signed"],
    }
    days = days_until(x["not_after"], today)
    if days is not None:
        cert["days_until_expiry"] = days
    return {"endpoints": [{
        "host": host, "certificate": cert,
        "protocols": [protocol] if protocol else [],
        "ciphers": [cipher] if cipher else [],
    }]}
