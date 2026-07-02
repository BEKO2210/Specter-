#!/usr/bin/env python3
"""LIVE-E-Mail-Sicherheits-Check fuer eine echte Domain (Kunden-Tueroeffner).

Holt die tatsaechlichen SPF-/DKIM-/DMARC-Eintraege einer Domain ueber
DNS-over-HTTPS (dns.google) und wertet sie mit demselben Offline-Analyzer aus,
der auch im Kundenauftrag laeuft (`analyze_email_security`). Ideal als
kostenloser Erst-Check: es werden ausschliesslich *oeffentliche* DNS-Eintraege
gelesen - kein Zugriff auf Systeme, kein Mailversand, kein Eingriff.

Aufruf (aus dem Repo-Wurzelverzeichnis):
    python examples/live_email_check.py kunde-domain.de
    python examples/live_email_check.py kunde-domain.de --selectors s1,s2,intern

Ohne --selectors werden gaengige DKIM-Selector-Namen abgetastet. DKIM-Selektoren
sind pro Anbieter unterschiedlich; findet der Check keinen, heisst das *nicht*
zwingend, dass kein DKIM existiert - dann den Selector beim Kunden erfragen.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from specter.analyzers.dns_security import analyze_dns  # noqa: E402
from specter.analyzers.email_security import analyze_email_security  # noqa: E402
from specter.dns_live import build_dns_export  # noqa: E402
from specter.email_live import (  # noqa: E402
    COMMON_DKIM_SELECTORS, build_email_export, extract_txt,
)


def doh(name: str, rtype: str = "TXT") -> dict:
    """Fragt DNS-Eintraege eines Namens per DNS-over-HTTPS ab (nur lesend)."""
    try:
        raw = subprocess.run(
            ["curl", "-s", "--max-time", "15",
             f"https://dns.google/resolve?name={name}&type={rtype}&do=1"],
            capture_output=True, text=True, timeout=20).stdout
        return json.loads(raw)
    except (subprocess.SubprocessError, json.JSONDecodeError, OSError):
        return {}


def parse_args(argv: list[str]) -> tuple[str, list[str]]:
    domain = ""
    selectors: list[str] = []
    i = 0
    while i < len(argv):
        if argv[i] == "--selectors" and i + 1 < len(argv):
            selectors = [s.strip() for s in argv[i + 1].split(",") if s.strip()]
            i += 2
        else:
            domain = argv[i].strip()
            i += 1
    return domain, selectors


def main() -> int:
    domain, extra = parse_args(sys.argv[1:])
    if not domain:
        print("Aufruf: python examples/live_email_check.py <domain> "
              "[--selectors s1,s2]")
        return 2

    selectors = list(dict.fromkeys(list(COMMON_DKIM_SELECTORS) + extra))
    apex = extract_txt(doh(domain))
    dmarc = extract_txt(doh("_dmarc." + domain))
    dkim_by_selector = {}
    for sel in selectors:
        txts = extract_txt(doh(f"{sel}._domainkey.{domain}"))
        if txts:
            dkim_by_selector[sel] = txts

    export = build_email_export(domain, apex, dmarc, dkim_by_selector)
    findings = analyze_email_security(export)

    # DNS-Sicherheit derselben Domain real mitziehen (DNSSEC-AD-Flag + CAA).
    dns_export = build_dns_export(domain, doh(domain, "SOA"), doh(domain, "CAA"))
    dns_findings = analyze_dns(dns_export)

    print("=" * 74)
    print(f" LIVE-E-Mail-Sicherheits-Check: {domain}")
    print("=" * 74)
    print(f"  SPF   : {export['spf'] or '(kein SPF-Eintrag gefunden)'}")
    print(f"  DMARC : {export['dmarc'] or '(kein DMARC-Eintrag gefunden)'}")
    if export["dkim"]:
        sel = ", ".join(f"{d['selector']}({d.get('key_bits', '?')} Bit)"
                        for d in export["dkim"])
    else:
        sel = "(ueber gaengige Selektoren keiner gefunden - beim Kunden erfragen)"
    print(f"  DKIM  : {sel}")
    print(f"  DNSSEC: {'aktiv (AD-Flag)' if dns_export['dnssec'] else 'NICHT aktiv'}")
    print(f"  CAA   : {', '.join(dns_export['caa']) or '(keine CAA-Records gefunden)'}")

    print("-" * 74)
    alle = findings + dns_findings
    if alle:
        print(f" {len(alle)} Befund(e):")
        for f in alle:
            print(f"   [{f.severity.label}] {f.title}")
            print(f"        Empfehlung: {f.evidence}")
    else:
        print(" Keine Befunde - E-Mail- und DNS-Schutz dieser Domain sind vorbildlich.")
    print("=" * 74)
    print(" Hinweis: nur oeffentliche DNS-Eintraege gelesen; kein Eingriff. "
          "DKIM-Selektoren\n variieren je Anbieter - fehlender DKIM-Treffer ist "
          "kein sicherer Beleg fuer\n fehlendes DKIM.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
