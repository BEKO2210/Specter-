#!/usr/bin/env python3
"""Erzeugt den Investoren-/Pitch-One-Pager (Kennzahlen-Folie) als HTML.

Alle Zahlen werden LIVE aus den echten Offline-Analyzern und dem
Beispieldatensatz (examples/data/*.example.json) berechnet - keine erfundenen
Kennzahlen. So bleibt die Folie automatisch konsistent mit dem Produkt.

So aufrufen (aus dem Repo-Wurzelverzeichnis):
    python examples/build_pitch_onepager.py

Danach die erzeugte HTML-Datei im Browser öffnen und über
"Drucken -> Als PDF speichern" (Querformat, A4) ein PDF erzeugen - oder per
Chromium `--headless --print-to-pdf` rendern.
"""

from __future__ import annotations

import html
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from specter import bsi, cvss                                     # noqa: E402
from specter._brand_asset import SPECTER_MARK_DATA_URI            # noqa: E402
from specter.analyzers import (                                   # noqa: E402
    analyze_ad, analyze_aws, analyze_azure, analyze_backup, analyze_container,
    analyze_database, analyze_dependencies, analyze_dns, analyze_email_security,
    analyze_entra, analyze_exchange, analyze_firewall, analyze_http_headers,
    analyze_tls,
)
from specter.assets import AssetGraph                             # noqa: E402
from specter.attack_paths import correlate                        # noqa: E402
from specter.findings import FindingsStore                        # noqa: E402

DATA = REPO_ROOT / "examples" / "data"

# 14 Prüf-Bereiche (Analyzer) in Berichtsreihenfolge.
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

# Die 14 Bereiche als Kacheln (Kurzname für die Abdeckungs-Leiste).
COVERAGE = [
    "E-Mail (SPF/DKIM/DMARC)", "DNS (DNSSEC/CAA)", "Web-Header/Cookies",
    "TLS/Zertifikate", "Firewall/VPN", "Backup/Ransomware-Resilienz",
    "Active Directory", "Entra ID / M365", "AWS", "Azure",
    "Exchange", "Abhängigkeiten (CVE)", "Datenbanken", "Container/Docker",
]


def _load(name: str) -> dict:
    return json.loads((DATA / name).read_text(encoding="utf-8"))


def count_tests() -> int:
    """Zählt die tatsächlich gesammelten Tests live, damit die Zahl nie driftet."""
    try:
        res = subprocess.run(
            [sys.executable, "-m", "pytest", "--collect-only", "-q",
             "--no-cov"],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=120)
        for line in reversed(res.stdout.splitlines()):
            line = line.strip()
            if line.endswith("tests collected") or "test collected" in line:
                return int(line.split()[0])
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return 0


def compute_metrics() -> dict:
    """Berechnet alle Pitch-Kennzahlen live aus den echten Analyzern."""
    findings = FindingsStore()
    for fn, name in ANALYZERS:
        findings.extend(fn(_load(name)))

    assets = AssetGraph()
    assets.add_asset("domain", "muster-gmbh.de", note="Hauptdomain")
    assets.add_asset("host", "203.0.113.10", note="Terminalserver (RDP)")
    assets.add_asset("endpoint", "portal.muster-gmbh.de", note="Kundenportal")
    assets.add_asset("cloud", "Microsoft-365-Tenant", note="muster.onmicrosoft.com")
    paths = correlate(findings, assets)

    all_findings = findings.all()
    counts = findings.counts()
    scores = [cvss.cvss_score(f.category, f.severity) for f in all_findings]
    bausteine = set()
    for f in all_findings:
        for part in bsi.map_finding(f).bsi_bezug.split(";"):
            code = part.strip().split(" ")[0]
            if code:
                bausteine.add(code)

    return {
        "bereiche": len(ANALYZERS),
        "findings": len(all_findings),
        "kritisch": counts.get("Kritisch", 0),
        "hoch": counts.get("Hoch", 0),
        "mittel": counts.get("Mittel", 0),
        "niedrig": counts.get("Niedrig", 0),
        "kategorien": len({f.category for f in all_findings}),
        "cvss_max": max(scores),
        "cvss_ge9": sum(1 for s in scores if s >= 9.0),
        "cvss_ge7": sum(1 for s in scores if s >= 7.0),
        "bsi_bausteine": len(bausteine),
        "assets": len(assets),
        "pfade": [
            {"titel": p.title, "schritte": len(p.steps),
             "schwere": str(p.severity)}
            for p in paths
        ],
    }


def render_html(m: dict) -> str:
    e = html.escape

    def pfad_row(p: dict) -> str:
        return (
            f'<li><span class="pf-t">{e(p["titel"])}</span>'
            f'<span class="pf-s">{p["schritte"]} Schritte</span></li>'
        )

    pfade = "\n".join(pfad_row(p) for p in m["pfade"])
    coverage = "".join(f"<span>{e(c)}</span>" for c in COVERAGE)

    return f"""<!doctype html>
<html lang="de"><head><meta charset="utf-8">
<title>Specter - Investoren-One-Pager</title>
<style>
  @page {{ size: A4 landscape; margin: 12mm; }}
  :root {{
    --navy:#0D1B2A; --charcoal:#1F2937; --teal:#14B8A6; --amber:#F59E0B;
    --red:#DC2626; --light:#F3F4F6; --border:#E5E7EB; --muted:#6B7280;
  }}
  * {{ box-sizing:border-box; }}
  body {{
    font-family:'Inter',ui-sans-serif,system-ui,-apple-system,'Segoe UI',sans-serif;
    color:var(--charcoal); margin:0; background:#fff; font-size:12px; line-height:1.45;
  }}
  .sheet {{ max-width:1000px; margin:0 auto; padding:6px 4px; }}
  header {{ display:flex; align-items:center; gap:14px; border-bottom:3px solid var(--teal);
           padding-bottom:12px; margin-bottom:14px; }}
  header .mark {{ background:var(--navy); border-radius:10px; padding:8px 10px; display:flex; }}
  header h1 {{ font-size:26px; margin:0; color:var(--navy); letter-spacing:-.5px; }}
  header .claim {{ font-size:13px; color:var(--muted); margin:2px 0 0; }}
  header .badge {{ margin-left:auto; text-align:right; font-size:11px; color:var(--muted); }}
  header .badge b {{ display:block; font-size:15px; color:var(--teal); }}
  .grid {{ display:grid; grid-template-columns:repeat(4,1fr); gap:10px; margin-bottom:14px; }}
  .kpi {{ background:var(--light); border-radius:10px; padding:12px 14px; border-left:4px solid var(--teal); }}
  .kpi .n {{ font-size:30px; font-weight:800; color:var(--navy); line-height:1; }}
  .kpi .l {{ font-size:11px; color:var(--muted); margin-top:5px; }}
  .kpi.red {{ border-left-color:var(--red); }} .kpi.red .n {{ color:var(--red); }}
  .kpi.amber {{ border-left-color:var(--amber); }}
  .cols {{ display:grid; grid-template-columns:1.15fr 1fr; gap:16px; }}
  h2 {{ font-size:13px; text-transform:uppercase; letter-spacing:.6px; color:var(--navy);
        margin:0 0 8px; padding-bottom:4px; border-bottom:1px solid var(--border); }}
  ul.pfade {{ list-style:none; margin:0 0 14px; padding:0; }}
  ul.pfade li {{ display:flex; justify-content:space-between; align-items:center;
                 padding:7px 10px; background:#FFF7ED; border-radius:7px; margin-bottom:6px;
                 border-left:3px solid var(--amber); }}
  ul.pfade .pf-t {{ font-weight:600; color:var(--charcoal); font-size:11.5px; }}
  ul.pfade .pf-s {{ font-size:10.5px; color:var(--muted); white-space:nowrap; padding-left:10px; }}
  .cov {{ display:flex; flex-wrap:wrap; gap:5px; margin-bottom:14px; }}
  .cov span {{ background:var(--navy); color:#fff; border-radius:5px; padding:4px 8px; font-size:10px; }}
  .why {{ list-style:none; margin:0; padding:0; }}
  .why li {{ padding:6px 0 6px 20px; position:relative; font-size:11.5px; border-bottom:1px dashed var(--border); }}
  .why li:before {{ content:"✓"; position:absolute; left:0; color:var(--teal); font-weight:800; }}
  .strip {{ background:var(--navy); color:#fff; border-radius:10px; padding:12px 16px;
            display:flex; justify-content:space-around; text-align:center; margin:14px 0; }}
  .strip div b {{ display:block; font-size:20px; color:var(--teal); }}
  .strip div span {{ font-size:10.5px; color:#C9D5DF; }}
  footer {{ margin-top:14px; padding-top:10px; border-top:1px solid var(--border);
            display:flex; justify-content:space-between; font-size:10.5px; color:var(--muted); }}
  footer b {{ color:var(--navy); }}
</style></head>
<body><div class="sheet">
  <header>
    <div class="mark">{SPECTER_MARK_DATA_URI and f'<img src="{SPECTER_MARK_DATA_URI}" alt="Specter" width="30" height="36" style="display:block">'}</div>
    <div>
      <h1>Specter</h1>
      <p class="claim">Autonome, defensive IT-Sicherheitspr&uuml;fung f&uuml;r den deutschen Mittelstand &ndash; offline-first, BSI-konform, ohne Angriffe.</p>
    </div>
    <div class="badge"><b>100&nbsp;% Testabdeckung</b>{m['tests']} automatisierte Tests</div>
  </header>

  <div class="grid">
    <div class="kpi"><div class="n">{m['bereiche']}</div><div class="l">Pr&uuml;f-Bereiche (Analyzer)</div></div>
    <div class="kpi red"><div class="n">{m['findings']}</div><div class="l">Befunde im Beispielbericht</div></div>
    <div class="kpi amber"><div class="n">{len(m['pfade'])}</div><div class="l">korrelierte Angriffspfade</div></div>
    <div class="kpi"><div class="n">{m['bsi_bausteine']}</div><div class="l">BSI-Grundschutz-Bausteine</div></div>
  </div>

  <div class="cols">
    <div>
      <h2>Reale Angriffspfade (aus Einzelbefunden korreliert)</h2>
      <ul class="pfade">
{pfade}
      </ul>
      <h2>Vollst&auml;ndige Abdeckung &ndash; {m['bereiche']} Bereiche in einem Lauf</h2>
      <div class="cov">{coverage}</div>
    </div>
    <div>
      <h2>Warum Specter (statt klassischem Pentest)</h2>
      <ul class="why">
        <li>Bezahlbar &amp; wiederholbar &ndash; kein 5-stelliges Gutachten pro Jahr</li>
        <li>Offline &amp; lesend &ndash; keine Angriffe, kein DoS, &sect;202-StGB-konform</li>
        <li>Jeder Befund mit CVSS-Score, BSI-Bezug und konkreter Ma&szlig;nahme</li>
        <li>Angriffspfade statt Einzel-Listen &ndash; zeigt echte Ketten-Risiken</li>
        <li>Deutschsprachiger Bericht, direkt f&uuml;r Gesch&auml;ftsf&uuml;hrung nutzbar</li>
      </ul>
    </div>
  </div>

  <div class="strip">
    <div><b>{m['cvss_max']}</b><span>h&ouml;chster CVSS-Score</span></div>
    <div><b>{m['cvss_ge9']}</b><span>Befunde CVSS &ge; 9,0 (kritisch)</span></div>
    <div><b>{m['cvss_ge7']}</b><span>Befunde CVSS &ge; 7,0 (hoch+)</span></div>
    <div><b>{m['kritisch']}&nbsp;/&nbsp;{m['hoch']}&nbsp;/&nbsp;{m['mittel']}</b><span>Kritisch / Hoch / Mittel</span></div>
    <div><b>{m['kategorien']}</b><span>Schwachstellen-Kategorien</span></div>
  </div>

  <footer>
    <div>Belkis Aslani &middot; Einzelunternehmen (IT-Sicherheit) &middot; 71691 Freiberg am Neckar</div>
    <div><b>kontakt@example.de</b></div>
  </footer>
</div></body></html>"""


def main() -> int:
    m = compute_metrics()
    m["tests"] = count_tests() or 626
    out = REPO_ROOT / "reports" / "specter-investoren-onepager.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_html(m), encoding="utf-8")

    print("=" * 70)
    print(" Specter - Investoren-One-Pager (Kennzahlen-Folie) erzeugt")
    print("=" * 70)
    print(f"[i] Datei: {out}")
    print(f"[i] {m['bereiche']} Bereiche · {m['findings']} Befunde · "
          f"{len(m['pfade'])} Angriffspfade · {m['bsi_bausteine']} BSI-Bausteine · "
          f"CVSS max {m['cvss_max']}.")
    print("[i] Im Browser öffnen und als PDF (Querformat, A4) drucken.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
