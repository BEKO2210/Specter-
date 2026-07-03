"""Reine Hilfsfunktionen für den Live-E-Mail-Check (DNS-over-HTTPS -> Export).

Der eigentliche Netzwerkabruf lebt bewusst im Beispiel-Runner
(`examples/live_email_check.py`); hier stehen nur die deterministischen,
testbaren Bausteine: DoH-Antwort auswerten, RSA-Schlüssellänge schätzen,
Einträge auswählen und daraus die Export-Struktur bauen, die der bestehende
Offline-Analyzer `analyze_email_security` erwartet.

So bleibt die Kernlogik testbar (offline, 100 % Coverage) und identisch zur
Kunden-Analyse - der Live-Check fuettert nur echte, öffentliche DNS-Daten ein.
Reine Leseabfragen öffentlicher DNS-Einträge, kein Eingriff.
"""

from __future__ import annotations

import base64
from typing import Any

# Gaengige DKIM-Selector-Namen zum Abtasten, wenn der Kunde keinen nennt.
COMMON_DKIM_SELECTORS = (
    "google", "selector1", "selector2", "default", "k1", "k2", "s1", "s2",
    "dkim", "mail", "smtp", "s1024", "key1", "mandrill", "everlytickey1",
)
# Uebliche RSA-Schlüssellängen zum Runden der Schätzung.
_STD_KEY_BITS = (512, 768, 1024, 2048, 3072, 4096)


def extract_txt(doh_response: Any) -> list[str]:
    """Zieht die TXT-Strings aus einer geparsten dns.google-Antwort."""
    if not isinstance(doh_response, dict):
        return []
    out: list[str] = []
    for ans in doh_response.get("Answer", []):
        if isinstance(ans, dict) and ans.get("type") == 16:
            out.append(str(ans.get("data", "")).replace('"', "").strip())
    return out


def select_record(prefix: str, txts: list[str]) -> str:
    """Erster TXT-Eintrag, der mit dem Praefix beginnt (case-insensitive)."""
    pref = prefix.lower()
    for t in txts:
        if t.lower().startswith(pref):
            return t
    return ""


def rsa_bits_from_der(p_b64: str) -> int:
    """Schätzt die RSA-Schlüssellänge aus dem DKIM-p=-Feld (DER)."""
    raw = "".join(str(p_b64).split())
    try:
        der = base64.b64decode(raw + "=" * (-len(raw) % 4), validate=True)
    except (ValueError, TypeError):
        return 0
    best = 0
    i, n = 0, len(der)
    while i < n:
        tag = der[i]
        i += 1
        if i >= n:
            break
        length = der[i]
        i += 1
        if length & 0x80:
            num = length & 0x7F
            length = int.from_bytes(der[i:i + num], "big")
            i += num
        if tag == 0x02:  # INTEGER -> Kandidat für den Modulus
            stripped = der[i:i + length].lstrip(b"\x00")
            best = max(best, len(stripped) * 8)
            i += length
        elif tag == 0x30:  # SEQUENCE -> hineingehen
            continue
        elif tag == 0x03:  # BIT STRING -> unused-bits-Byte überspringen, hineingehen
            i += 1
        else:
            i += length
    for std in _STD_KEY_BITS:
        if abs(best - std) <= 16:
            return std
    return best


def dkim_entry(selector: str, txts: list[str]) -> dict[str, Any] | None:
    """Baut aus den TXT-Strings eines Selectors einen DKIM-Eintrag (oder None)."""
    joined = "".join(txts).strip()
    if "p=" not in joined:
        return None
    key = ""
    for token in joined.replace(";", " ").split():
        if token.startswith("p="):
            key = token[2:]
    entry: dict[str, Any] = {"selector": selector, "present": True}
    bits = rsa_bits_from_der(key) if key else 0
    if bits:
        entry["key_bits"] = bits
    return entry


def build_email_export(domain: str, apex_txts: list[str], dmarc_txts: list[str],
                       dkim_by_selector: dict[str, list[str]]) -> dict[str, Any]:
    """Setzt die Export-Struktur für `analyze_email_security` zusammen."""
    dkim: list[dict[str, Any]] = []
    for selector, txts in dkim_by_selector.items():
        entry = dkim_entry(selector, txts)
        if entry:
            dkim.append(entry)
    return {
        "domain": domain,
        "spf": select_record("v=spf1", apex_txts),
        "dmarc": select_record("v=dmarc1", dmarc_txts),
        "dkim": dkim,
    }
