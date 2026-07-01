"""Markengerechter, druckoptimierter HTML-Report (kundentaugliche Übergabe).

Erzeugt einen eigenständigen HTML-Bericht im Specter-Branding. Im Browser lässt
er sich über "Drucken -> Als PDF speichern" verlustfrei in ein professionelles
PDF überführen - ohne zusätzliche Abhängigkeit und in jeder Umgebung zuverlässig.
"""

from __future__ import annotations

import datetime as _dt
import html
from pathlib import Path
from typing import Any

from ._brand_asset import SPECTER_MARK_DATA_URI
from .assets import AssetGraph
from .attack_paths import AttackPath
from .bsi import map_findings
from .choke_points import compute_choke_points
from .config import Config
from .cvss import cvss_rating, cvss_score
from .findings import FindingsStore, Severity
from .remediation import remediation_for
from .report import _long_term, _quick_wins, _top_risks

# Exaktes Specter-Mark (aus dem Brand-Board) inline eingebettet - self-contained.
_MARK_IMG = (
    f'<img src="{SPECTER_MARK_DATA_URI}" alt="Specter" '
    'width="38" height="46" style="display:block">'
)

# Schweregrad -> CSS-Klasse (Farbcode im Report).
_SEV_CLASS = {
    Severity.KRITISCH: "sev-krit",
    Severity.HOCH: "sev-hoch",
    Severity.MITTEL: "sev-mittel",
    Severity.NIEDRIG: "sev-niedrig",
    Severity.INFO: "sev-info",
}

_CSS = """
:root {
  --navy: #0D1B2A; --charcoal: #1F2937; --teal: #14B8A6;
  --light: #F3F4F6; --white: #FFFFFF; --border: #E5E7EB;
}
* { box-sizing: border-box; }
body {
  font-family: 'Inter', ui-sans-serif, system-ui, -apple-system, 'Segoe UI', sans-serif;
  color: var(--charcoal); margin: 0; padding: 0; line-height: 1.5;
  background: var(--white);
}
.wrap { max-width: 900px; margin: 0 auto; padding: 40px 32px; }
header.brand {
  display: flex; align-items: center; gap: 14px;
  border-bottom: 3px solid var(--teal); padding-bottom: 16px; margin-bottom: 8px;
}
header.brand .name { font-size: 26px; font-weight: 740; color: var(--navy); letter-spacing: -0.5px; }
header.brand .sub { color: var(--teal); font-size: 13px; font-weight: 600; }
.meta { color: #6B7280; font-size: 13px; margin: 8px 0 28px; }
h2 { color: var(--navy); font-size: 20px; margin: 32px 0 12px; border-left: 4px solid var(--teal); padding-left: 10px; }
h3 { color: var(--navy); font-size: 15px; margin: 18px 0 6px; }
table { border-collapse: collapse; width: 100%; font-size: 13px; margin: 8px 0; }
th, td { border: 1px solid var(--border); padding: 7px 10px; text-align: left; vertical-align: top; }
th { background: var(--light); color: var(--navy); font-weight: 600; }
.badge { display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 11px; font-weight: 700; color: #fff; }
.sev-krit { background: #7F1D1D; } .sev-hoch { background: #B91C1C; }
.sev-mittel { background: #B45309; } .sev-niedrig { background: #2563EB; }
.sev-info { background: #4B5563; }
.finding { border: 1px solid var(--border); border-radius: 8px; padding: 14px 16px; margin: 12px 0; }
.finding .head { display: flex; justify-content: space-between; align-items: center; gap: 12px; }
.evidence { background: #0D1B2A; color: #E5E7EB; padding: 10px 12px; border-radius: 6px; font-family: ui-monospace, monospace; font-size: 12px; white-space: pre-wrap; word-break: break-word; margin: 8px 0; }
.reco { background: var(--light); border-left: 3px solid var(--teal); padding: 8px 12px; border-radius: 0 6px 6px 0; font-size: 13px; }
ul { margin: 6px 0; padding-left: 20px; } li { margin: 3px 0; }
.muted { color: #6B7280; font-style: italic; }
footer { margin-top: 36px; padding-top: 16px; border-top: 1px solid var(--border); color: #6B7280; font-size: 12px; }
@media print {
  .wrap { max-width: none; padding: 0 12mm; }
  h2 { page-break-after: avoid; }
  .finding, table { page-break-inside: avoid; }
  a { color: inherit; text-decoration: none; }
}
"""


def _e(text: Any) -> str:
    return html.escape(str(text))


def _now_iso() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d %H:%M")


def _badge(sev: Severity) -> str:
    return f'<span class="badge {_SEV_CLASS[sev]}">{_e(sev.label)}</span>'


def build_html(
    config: Config,
    assets: AssetGraph,
    findings: FindingsStore,
    paths: list[AttackPath],
    generated_at: str | None = None,
    scanner_runs: list[dict[str, Any]] | None = None,
    delta: Any = None,
) -> str:
    eng = config.engagement
    ts = generated_at or _now_iso()
    scanner_runs = scanner_runs or []
    counts = findings.counts()
    p: list[str] = []

    p.append("<!doctype html><html lang='de'><head><meta charset='utf-8'>")
    p.append(f"<title>Sicherheitsbericht - {_e(eng.name)}</title>")
    p.append(f"<style>{_CSS}</style></head><body><div class='wrap'>")

    # Kopf
    p.append("<header class='brand'>" + _MARK_IMG +
             "<div><div class='name'>Specter</div>"
             "<div class='sub'>Defensive Security Intelligence</div></div></header>")
    p.append(f"<div class='meta'>Sicherheitsbericht &middot; <strong>{_e(eng.name)}</strong><br>"
             f"Erstellt: {_e(ts)} &middot; Autorisiert durch: {_e(eng.authorized_by)} "
             f"&middot; Referenz: {_e(eng.authorization_ref)}</div>")

    # Executive Summary
    p.append("<h2>Executive Summary</h2>")
    p.append(f"<p>Im autorisierten Prüfumfang wurden <strong>{len(findings)} Finding(s)</strong> "
             f"und <strong>{len(paths)} Angriffspfad(e)</strong> über "
             f"<strong>{len(assets)} Asset(s)</strong> identifiziert, davon "
             f"<strong>{counts.get('Kritisch', 0)} kritische</strong> und "
             f"<strong>{counts.get('Hoch', 0)} hohe</strong> Risiken.</p>")
    top = _top_risks(findings)
    if top:
        p.append("<p><strong>Wichtigste Risiken:</strong></p><ul>")
        for f in top:
            p.append(f"<li>{_badge(f.severity)} {_e(f.title)} <span class='muted'>({_e(f.asset)})</span></li>")
        p.append("</ul>")

    # Re-Test / Delta
    if delta is not None:
        seit = f" seit {_e(delta.previous_date)}" if delta.previous_date else ""
        alter = f" (vor {delta.aging_days} Tagen)" if delta.aging_days is not None else ""
        p.append(f"<h2>Re-Test / Veränderung{seit}{alter}</h2>")
        p.append(f"<p><strong>Behoben:</strong> {len(delta.resolved)} &middot; "
                 f"<strong>Neu:</strong> {len(delta.new)} &middot; "
                 f"<strong>Weiterhin offen:</strong> {len(delta.still_open)}</p>")
        if delta.resolved:
            p.append("<p><strong>Behoben seit dem letzten Bericht:</strong></p><ul>")
            for r in delta.resolved:
                p.append(f"<li>{_e(r.get('title', r.get('id')))} "
                         f"<span class='muted'>({_e(r.get('severity', ''))})</span></li>")
            p.append("</ul>")
        if delta.new:
            p.append("<p><strong>Neu hinzugekommen:</strong></p><ul>")
            for f in delta.new:
                p.append(f"<li>{_badge(f.severity)} {_e(f.title)} "
                         f"<span class='muted'>({_e(f.asset)})</span></li>")
            p.append("</ul>")

    # Risiko-Einstufung
    p.append("<h2>Risiko-Einstufung</h2><table><tr><th>Schweregrad</th><th>Anzahl</th></tr>")
    for sev in reversed(Severity):
        p.append(f"<tr><td>{_badge(sev)}</td><td>{counts.get(sev.label, 0)}</td></tr>")
    p.append("</table>")

    # Angriffspfade
    p.append("<h2>Angriffspfade (toxische Kombinationen)</h2>")
    if not paths:
        p.append("<p class='muted'>Keine korrelierten Angriffspfade.</p>")
    for i, path in enumerate(paths, start=1):
        extra = f" &middot; {path.instances} Kombinationen" if path.instances > 1 else ""
        p.append(f"<h3>AP-{i}: {_e(path.title)} {_badge(path.severity)}{extra}</h3><ol>")
        for step in path.steps:
            p.append(f"<li>{_e(step)}</li>")
        p.append("</ol>")
        if path.rationale:
            p.append(f"<p class='muted'>{_e(path.rationale)}</p>")

    # Choke Points
    p.append("<h2>Choke Points (engste Behebungsstellen)</h2>")
    chokes = compute_choke_points(paths)
    if not chokes:
        p.append("<p class='muted'>Keine Choke Points (keine korrelierten Angriffspfade).</p>")
    else:
        p.append("<p>Diese Findings zuerst beheben &ndash; jedes bricht mehrere "
                 "Angriffspfade auf einmal:</p><ul>")
        for cp in chokes:
            f = findings.get(cp.finding_id)
            titel = _e(f.title) if f else _e(cp.finding_id)
            asset = f" ({_e(f.asset)})" if f else ""
            p.append(f"<li><strong>{titel}</strong>{asset} "
                     f"&rarr; bricht {cp.paths_broken} Angriffspfad(e)</li>")
        p.append("</ul>")

    # Quick Wins
    p.append("<h2>Quick Wins (kurzfristig, hohe Wirkung)</h2>")
    wins = _quick_wins(findings)
    if not wins:
        p.append("<p class='muted'>Keine unmittelbaren Quick Wins identifiziert.</p>")
    else:
        p.append("<ul>")
        for f in wins:
            p.append(f"<li><strong>{_e(f.title)}</strong> ({_e(f.asset)}): {_e(remediation_for(f))}</li>")
        p.append("</ul>")

    # Langfristige Maßnahmen
    p.append("<h2>Langfristige Maßnahmen</h2>")
    measures = _long_term(findings)
    if not measures:
        p.append("<p class='muted'>Keine strategischen Maßnahmen abgeleitet.</p>")
    else:
        p.append("<ul>")
        for m in measures:
            p.append(f"<li>{_e(m)}</li>")
        p.append("</ul>")

    # Technische Findings
    p.append("<h2>Technische Findings</h2>")
    if len(findings) == 0:
        p.append("<p class='muted'>Keine Findings erfasst.</p>")
    for f in findings.all():
        cwe = f" &middot; {_e(f.cwe)}" if f.cwe else ""
        score = cvss_score(f.category, f.severity)
        p.append("<div class='finding'>")
        p.append(f"<div class='head'><h3>{_e(f.id)}: {_e(f.title)}</h3>{_badge(f.severity)}</div>")
        p.append(f"<div class='muted'>CVSS-Lite: {score:.1f} ({_e(cvss_rating(score))}) &middot; "
                 f"Kategorie: {_e(f.category_label)}{cwe} &middot; "
                 f"Asset: {_e(f.asset)} &middot; Fundstelle: {_e(f.location or 'n/a')} &middot; "
                 f"Quelle: {_e(f.source)}</div>")
        if f.evidence:
            p.append(f"<div class='evidence'>{_e(f.evidence.strip())}</div>")
        p.append(f"<div class='reco'><strong>Gegenmaßnahme:</strong> {_e(remediation_for(f))}</div>")
        p.append("</div>")

    # BSI-Mapping
    p.append("<h2>BSI-IT-Grundschutz-Mapping</h2>")
    mappings = map_findings(findings.all())
    if not mappings:
        p.append("<p class='muted'>Keine Findings zum Mappen.</p>")
    else:
        p.append("<table><tr><th>Finding</th><th>Risiko</th><th>Bereich</th>"
                 "<th>BSI-Bezug</th><th>Priorität</th></tr>")
        for m in mappings:
            p.append(f"<tr><td>{_e(m.finding_id)}</td><td>{_e(m.risiko)}</td>"
                     f"<td>{_e(m.bereich)}</td><td>{_e(m.bsi_bezug)}</td>"
                     f"<td>{_e(m.prioritaet)}</td></tr>")
        p.append("</table>")

    # Scanner-Ergebnisse
    p.append("<h2>Scanner-Ergebnisse</h2>")
    if not scanner_runs:
        p.append("<p class='muted'>Keine aktiven Scanner ausgeführt.</p>")
    else:
        p.append("<table><tr><th>Scanner</th><th>Ziel</th><th>Findings</th>"
                 "<th>Exit</th><th>Hinweis</th></tr>")
        for run in scanner_runs:
            hinweis = run.get("error") or ("gekürzt" if run.get("truncated") else "-")
            p.append(f"<tr><td>{_e(run.get('scanner'))}</td><td>{_e(run.get('target'))}</td>"
                     f"<td>{_e(run.get('finding_count', 0))}</td><td>{_e(run.get('returncode'))}</td>"
                     f"<td>{_e(hinweis)}</td></tr>")
        p.append("</table>")

    # Scope & Limitierungen
    targets = ", ".join(config.allowed_targets) or "(keine)"
    scan_enabled = ", ".join(n for n, sp in config.scanners.items() if sp.enabled) or "(keine)"
    p.append("<h2>Scope-Hinweise &amp; Limitierungen</h2><ul>")
    p.append(f"<li>Freigegebene Netzwerk-Ziele: {_e(targets)}</li>")
    p.append(f"<li>Aktive Scanner freigegeben: {_e(scan_enabled)}</li>")
    p.append("<li>Aktionen außerhalb des Rahmens wurden technisch verweigert (fail-closed).</li>")
    p.append("<li>Momentaufnahme zum Prüfzeitpunkt; statische Treffer sind zu verifizieren.</li>")
    p.append("<li>AD-/Exchange-/Entra-Bewertungen aus bereitgestellten Exportdaten; keine Ausnutzung.</li>")
    p.append("</ul>")

    # Nächste Schritte
    p.append("<h2>Nächste Schritte</h2><ol>"
             "<li>Kritische/hohe Findings und Quick Wins kurzfristig beheben.</li>"
             "<li>Angriffspfade priorisiert schließen.</li>"
             "<li>Strategische Maßnahmen einplanen.</li>"
             "<li>Nach Behebung gezielten Nachtest (Re-Test) durchführen.</li></ol>")

    p.append("<footer>Erstellt mit Specter (autorisierte, defensive Sicherheitsprüfung). "
             "Zur PDF-Übergabe im Browser öffnen und &bdquo;Drucken &rarr; Als PDF "
             "speichern&ldquo; wählen. Personenbezogene Daten sind gemäß DSGVO und "
             "BSI IT-Grundschutz zu schützen.</footer>")
    p.append("</div></body></html>")
    return "".join(p)


def write_html(
    config: Config,
    assets: AssetGraph,
    findings: FindingsStore,
    paths: list[AttackPath],
    directory: str | Path = "reports",
    scanner_runs: list[dict[str, Any]] | None = None,
    delta: Any = None,
) -> Path:
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    html_path = out / f"specter-report-{stamp}.html"
    html_path.write_text(
        build_html(config, assets, findings, paths, _now_iso(), scanner_runs, delta),
        encoding="utf-8",
    )
    return html_path
