"""Defensive TLS-/Zertifikatsanalyse aus bereitgestelltem Export.

Wertet einen lokalen JSON-Export der TLS-Konfiguration eines oder mehrerer
Endpunkte aus (Zertifikat, unterstützte Protokolle, Cipher-Suites) und leitet
typische Transport-/Krypto-Risiken ab - ohne jede Live-Verbindung (kein
Handshake, keine Abfrage), ohne Ausnutzung.

Damit die Analyse **deterministisch und offline** bleibt, liefert der Export das
Feld `days_until_expiry` (negativ = bereits abgelaufen) bzw. `expired` mit -
gemessen zum Erhebungszeitpunkt durch das bereitstellende Collector-Skript. Der
Analyzer ruft selbst keine Systemuhr ab.

Erwartete Struktur (alle Felder optional):

    {
      "endpoints": [
        {
          "host": "portal.firma.de:443",
          "certificate": {
            "subject": "portal.firma.de", "days_until_expiry": -3,
            "signature_algorithm": "sha1WithRSAEncryption",
            "key_type": "RSA", "key_bits": 1024, "self_signed": false
          },
          "protocols": ["TLSv1.0", "TLSv1.2", "SSLv3"],
          "ciphers": ["ECDHE-RSA-AES256-GCM-SHA384", "RC4-SHA"]
        }
      ]
    }

Ein einzelner Endpunkt darf auch direkt (ohne `endpoints`-Liste) übergeben
werden.
"""

from __future__ import annotations

from typing import Any

from ..findings import Finding, Severity

# Ablauf-Schwellen (Tage).
EXPIRY_WARN_DAYS = 30
# Veraltete Protokolle -> Schweregrad.
_WEAK_PROTOCOLS = {
    "sslv2": Severity.HOCH, "sslv3": Severity.HOCH,
    "tlsv1.0": Severity.MITTEL, "tls1.0": Severity.MITTEL,
    "tlsv1.1": Severity.MITTEL, "tls1.1": Severity.MITTEL,
}
# Teilstrings, die eine schwache Cipher-Suite kennzeichnen.
_WEAK_CIPHER_MARKERS = ("rc4", "3des", "des-", "des_", "null", "export", "md5", "anon")
MIN_RSA_BITS = 2048


def _mk(title, category, severity, asset, evidence, *, location="", cwe="",
        owner="IT-/Infrastruktur-Team") -> Finding:
    return Finding(
        title=title, category=category, severity=severity, asset=asset,
        location=location or asset, evidence=evidence, cwe=cwe, owner=owner,
        source="tls_analyzer", status="offen",
    )


def _analyze_certificate(cert: dict[str, Any], host: str) -> list[Finding]:
    out: list[Finding] = []
    loc = f"{host}/certificate"
    try:
        days = int(cert.get("days_until_expiry"))
        has_days = True
    except (TypeError, ValueError):
        days, has_days = 0, False

    if cert.get("expired") or (has_days and days < 0):
        out.append(_mk(
            f"TLS-Zertifikat abgelaufen: {host}", "transport_security",
            Severity.HOCH, loc,
            f"days_until_expiry={cert.get('days_until_expiry')} - "
            "abgelaufenes Zertifikat, Warnungen/MITM-Risiko", location=loc, cwe="CWE-298",
        ))
    elif has_days and 0 <= days <= EXPIRY_WARN_DAYS:
        out.append(_mk(
            f"TLS-Zertifikat läuft in {days} Tagen ab: {host}",
            "transport_security", Severity.MITTEL, loc,
            f"days_until_expiry={days} - rechtzeitig erneuern", location=loc, cwe="CWE-298",
        ))

    sig = str(cert.get("signature_algorithm", "")).strip().lower()
    if "md5" in sig or "sha1" in sig:
        out.append(_mk(
            f"TLS-Zertifikat mit schwacher Signatur: {host}", "crypto_weakness",
            Severity.HOCH, loc, f"signature_algorithm={cert.get('signature_algorithm')} "
            "- SHA-1/MD5 gelten als gebrochen", location=loc, cwe="CWE-327",
        ))

    key_type = str(cert.get("key_type", "")).strip().lower()
    try:
        bits = int(cert.get("key_bits", 0))
    except (TypeError, ValueError):
        bits = 0
    if key_type in ("rsa", "dsa") and 0 < bits < MIN_RSA_BITS:
        out.append(_mk(
            f"TLS-Zertifikat mit zu kurzem Schlüssel ({bits} Bit): {host}",
            "crypto_weakness", Severity.HOCH, loc,
            f"key_type={cert.get('key_type')}, key_bits={bits} - mindestens {MIN_RSA_BITS}",
            location=loc, cwe="CWE-326",
        ))

    if cert.get("self_signed"):
        out.append(_mk(
            f"Selbstsigniertes TLS-Zertifikat: {host}", "misconfiguration",
            Severity.MITTEL, loc, "self_signed=true - kein vertrauenswürdiger "
            "Aussteller, Nutzer werden an Warnungen gewöhnt", location=loc, cwe="CWE-295",
        ))
    return out


def _analyze_protocols(protocols: Any, host: str) -> list[Finding]:
    out: list[Finding] = []
    loc = f"{host}/protocols"
    for proto in (protocols or []):
        key = str(proto).strip().lower().replace(" ", "")
        sev = _WEAK_PROTOCOLS.get(key)
        if sev is not None:
            out.append(_mk(
                f"Veraltetes TLS-/SSL-Protokoll aktiv ({proto}): {host}",
                "transport_security", sev, loc,
                f"{proto} unterstützt - deaktivieren, nur TLS 1.2/1.3 zulassen",
                location=loc, cwe="CWE-327",
            ))
    return out


def _analyze_ciphers(ciphers: Any, host: str) -> list[Finding]:
    out: list[Finding] = []
    loc = f"{host}/ciphers"
    for cipher in (ciphers or []):
        text = str(cipher).strip().lower()
        if any(marker in text for marker in _WEAK_CIPHER_MARKERS):
            out.append(_mk(
                f"Schwache Cipher-Suite angeboten ({cipher}): {host}",
                "crypto_weakness", Severity.MITTEL, loc,
                f"{cipher} - schwache/veraltete Cipher, aus der Liste entfernen",
                location=loc, cwe="CWE-327",
            ))
    return out


def _analyze_endpoint(ep: dict[str, Any]) -> list[Finding]:
    host = str(ep.get("host", "TLS-Endpunkt"))
    findings: list[Finding] = []
    cert = ep.get("certificate")
    if isinstance(cert, dict):
        findings += _analyze_certificate(cert, host)
    findings += _analyze_protocols(ep.get("protocols"), host)
    findings += _analyze_ciphers(ep.get("ciphers"), host)
    return findings


def analyze_tls(data: dict[str, Any]) -> list[Finding]:
    """Führt alle TLS-/Zertifikatsprüfungen aus und liefert die Findings."""
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
