#!/usr/bin/env python3
"""Erzeugt einen realistischen BEISPIEL-Sicherheitsbericht (Muster GmbH) als HTML.

Fuettert die echten Offline-Analyzer mit den mitgelieferten Beispiel-Exporten
(examples/data/*.example.json), korreliert daraus Angriffspfade und rendert den
markengerechten HTML-Report. So entsteht ein authentischer Beispielbericht als
Vertrauensbeweis fuer Interessenten - ohne echte Kundendaten.

So aufrufen (aus dem Repo-Wurzelverzeichnis):
    python examples/build_sample_report.py

Danach die erzeugte HTML-Datei im Browser oeffnen und ueber
"Drucken -> Als PDF speichern" ein PDF erstellen (oder per Chromium rendern).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from specter.analyzers import (                                   # noqa: E402
    analyze_ad, analyze_aws, analyze_azure, analyze_backup, analyze_container,
    analyze_database, analyze_dependencies, analyze_dns, analyze_email_security,
    analyze_entra, analyze_exchange, analyze_firewall, analyze_http_headers,
    analyze_tls,
)
from specter.assets import AssetGraph                             # noqa: E402
from specter.attack_paths import correlate                        # noqa: E402
from specter.config import Config, Engagement                     # noqa: E402
from specter.findings import FindingsStore                        # noqa: E402
from specter.report_export import build_html                      # noqa: E402

DATA = REPO_ROOT / "examples" / "data"

# Reihenfolge = Aufbau des Berichts (alle vierzehn Offline-Analyzer).
ANALYZERS = [
    (analyze_email_security, "email_security.example.json"),
    (analyze_dns, "dns.example.json"),
    (analyze_http_headers, "http_headers.example.json"),
    (analyze_tls, "tls.example.json"),
    (analyze_firewall, "firewall.example.json"),
    (analyze_backup, "backup.example.json"),
    (analyze_ad, "ad_export.example.json"),
    (analyze_entra, "entra_export.example.json"),
    (analyze_aws, "aws_export.example.json"),
    (analyze_azure, "azure_export.example.json"),
    (analyze_exchange, "exchange.example.json"),
    (analyze_dependencies, "dependencies.example.json"),
    (analyze_database, "database.example.json"),
    (analyze_container, "container.example.json"),
]


def _load(name: str) -> dict:
    return json.loads((DATA / name).read_text(encoding="utf-8"))


def build_config() -> Config:
    eng = Engagement(
        name="Muster GmbH",
        authorized_by="Geschaeftsfuehrung Muster GmbH",
        authorization_ref="BEISPIEL-2026-0001 (fiktiv)",
    )
    return Config(
        engagement=eng,
        allowed_targets=["203.0.113.0/24", "muster-gmbh.de"],
        forbidden_targets=[], allowed_paths=[DATA.resolve()],
        max_file_bytes=1_000_000, allowed_binaries=["curl"],
        command_timeout=20, require_approval=True, max_iterations=20,
        model="claude-sonnet-5",
    )


def main() -> int:
    config = build_config()

    assets = AssetGraph()
    assets.add_asset("domain", "muster-gmbh.de", note="Hauptdomain")
    assets.add_asset("host", "203.0.113.10", note="Terminalserver (RDP)")
    assets.add_asset("endpoint", "portal.muster-gmbh.de", note="Kundenportal")
    assets.add_asset("cloud", "Microsoft-365-Tenant", note="muster.onmicrosoft.com")

    findings = FindingsStore()
    for fn, name in ANALYZERS:
        findings.extend(fn(_load(name)))

    paths = correlate(findings, assets)

    html = build_html(config, assets, findings, paths,
                      generated_at="2026-07-02 09:00")
    out = REPO_ROOT / "reports" / "specter-beispielbericht.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")

    counts = findings.counts()
    print("=" * 70)
    print(" Specter - Beispielbericht erzeugt")
    print("=" * 70)
    print(f"[i] Datei: {out}")
    print(f"[i] {len(findings)} Findings (Kritisch {counts.get('Kritisch',0)}, "
          f"Hoch {counts.get('Hoch',0)}, Mittel {counts.get('Mittel',0)}) "
          f"ueber {len(assets)} Assets, {len(paths)} Angriffspfade.")
    print("[i] Im Browser oeffnen und 'Drucken -> Als PDF speichern' waehlen.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
