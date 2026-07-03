#!/usr/bin/env python3
"""Erzeugt eine personalisierte Erstkontakt-Mail auf Basis des Live-E-Mail-Checks.

Kombiniert den Live-Check (echte SPF/DKIM/DMARC-Einträge per DNS-over-HTTPS)
mit der Erstkontakt-Vorlage zu einer fertigen, individuellen Mail.

Aufruf (aus dem Repo-Wurzelverzeichnis):
    python examples/build_outreach_email.py kunde-domain.de
    python examples/build_outreach_email.py kunde-domain.de "Belkis Aslani" belkis@example.de

RECHTLICHER HINWEIS: Unaufgeforderte Werbe-E-Mails an Unternehmen sind in
Deutschland nach dem UWG heikel (i. d. R. ist eine vorherige Einwilligung oder
ein sachlicher Anknüpfungspunkt nötig). Nutzen Sie diese Vorlage für einen
individuellen Erstkontakt - idealerweise nach einem Telefonat, einer Empfehlung,
einem Messekontakt oder über LinkedIn - nicht für Massenversand.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from specter.analyzers.email_security import analyze_email_security  # noqa: E402
from specter.email_live import (  # noqa: E402
    COMMON_DKIM_SELECTORS, build_email_export, extract_txt,
)
from specter.outreach import build_outreach_email  # noqa: E402


def doh(name: str) -> dict:
    try:
        raw = subprocess.run(
            ["curl", "-s", "--max-time", "15",
             f"https://dns.google/resolve?name={name}&type=TXT"],
            capture_output=True, text=True, timeout=20).stdout
        return json.loads(raw)
    except (subprocess.SubprocessError, json.JSONDecodeError, OSError):
        return {}


def main() -> int:
    argv = sys.argv[1:]
    if not argv:
        print("Aufruf: python examples/build_outreach_email.py <domain> "
              "[Absendername] [Kontakt-E-Mail]")
        return 2
    domain = argv[0].strip()
    sender = argv[1] if len(argv) > 1 else ""
    contact = argv[2] if len(argv) > 2 else "kontakt@specter-security.de"

    apex = extract_txt(doh(domain))
    dmarc = extract_txt(doh("_dmarc." + domain))
    dkim = {}
    for sel in COMMON_DKIM_SELECTORS:
        txts = extract_txt(doh(f"{sel}._domainkey.{domain}"))
        if txts:
            dkim[sel] = txts

    export = build_email_export(domain, apex, dmarc, dkim)
    findings = analyze_email_security(export)
    mail = build_outreach_email(domain, findings, sender_name=sender,
                                contact_email=contact)

    print("=" * 74)
    print(f"BETREFF: {mail['subject']}")
    print("=" * 74)
    print(mail["body"])
    print("=" * 74)
    print("RECHTLICHER HINWEIS: Kein Massenversand. Unaufgeforderte Werbung an")
    print("Unternehmen ist nach UWG heikel - für individuellen Erstkontakt nutzen")
    print("(idealerweise nach Telefonat/Empfehlung/LinkedIn). Bei Unsicherheit")
    print("vorab kurz rechtlich abklären.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
