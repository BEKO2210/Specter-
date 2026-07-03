"""Produktionsreifer Sicherheitsbericht (Markdown + JSON), auf Deutsch.

Aufbau (kundentauglich für den Mittelstand):
  Executive Summary, Risiko-Einstufung, Angriffspfade, Quick Wins,
  langfristige Maßnahmen, technische Findings mit Evidenz, BSI-IT-Grundschutz-
  Mapping, Scanner-Ergebnisse, Scope-Hinweise, Limitierungen, nächste Schritte.
"""

from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path
from typing import Any

from .assets import AssetGraph
from .attack_paths import AttackPath
from .bsi import map_findings, priority_label
from .choke_points import compute_choke_points
from .config import Config
from .cvss import cvss_rating, cvss_score
from .findings import Finding, FindingsStore, Severity
from .remediation import remediation_for

# Kategorien, die typischerweise schnell behebbar sind (Quick Wins).
QUICK_WIN_CATEGORIES = {
    "default_credentials", "secret_exposure", "misconfiguration",
    "transport_security", "outdated_component", "remote_access",
}

# Langfristige, strategische Maßnahmen je vorkommender Kategorie.
LONG_TERM_MEASURES: dict[str, str] = {
    "outdated_component": "Patch- und Schwachstellenmanagement etablieren (BSI OPS.1.1.3), inkl. Software-Inventar (SBOM).",
    "auth_weakness": "Identitäts- und Berechtigungsmanagement härten, MFA flächendeckend (BSI ORP.4).",
    "access_control": "Least-Privilege und regelmäßige Berechtigungs-Rezertifizierung (BSI ORP.4).",
    "default_credentials": "Zentrales Passwort-/Secret-Management und MFA (BSI ORP.4).",
    "secret_exposure": "Secret-Management (Vault) und Entfernen von Secrets aus Code/Repos (BSI ORP.4).",
    "personal_data": "Datenschutz-Managementsystem und Verschlüsselungskonzept (DSGVO, BSI CON.2).",
    "sensitive_data": "Datenklassifizierung und Zugriffskontrolle für sensible Daten (BSI CON.2).",
    "injection": "Sicheren Entwicklungsprozess mit SAST/DAST und Code-Reviews (BSI APP.3.1).",
    "deserialization": "Sichere Datenverarbeitung und Eingabevalidierung (BSI APP.3.1).",
    "exposed_service": "Netzsegmentierung und striktes Firewall-Regelwerk (BSI NET.1.1).",
    "remote_access": "Zero-Trust-Fernzugang mit MFA statt offenem RDP/VPN (BSI OPS.1.2.5).",
    "crypto_weakness": "Kryptokonzept nach BSI CON.1 umsetzen.",
    "transport_security": "TLS-Härtung und Kryptokonzept (BSI CON.1).",
    "cloud_storage": "Cloud-Sicherheitskonzept und sichere Grundkonfiguration (BSI OPS.2.2).",
}


def _now_iso() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d %H:%M")


def _top_risks(findings: FindingsStore, limit: int = 5) -> list[Finding]:
    return [f for f in findings.all() if f.severity >= Severity.HOCH][:limit]


def _quick_wins(findings: FindingsStore) -> list[Finding]:
    return [
        f for f in findings.all()
        if f.severity >= Severity.HOCH and f.category in QUICK_WIN_CATEGORIES
    ]


def _long_term(findings: FindingsStore) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for f in findings.all():
        measure = LONG_TERM_MEASURES.get(f.category)
        if measure and measure not in seen:
            seen.add(measure)
            out.append(measure)
    return out


# ------------------------------- Abschnitte -------------------------------

def _section_header(config: Config, ts: str) -> list[str]:
    eng = config.engagement
    return [
        f"# Sicherheitsbericht - {eng.name}",
        "",
        f"- **Erstellt:** {ts}",
        f"- **Autorisiert durch:** {eng.authorized_by}",
        f"- **Referenz:** {eng.authorization_ref}",
        "- **Werkzeug:** Specter (autorisierte, defensive Sicherheitsprüfung)",
        "",
    ]


def _section_executive(config: Config, assets: AssetGraph, findings: FindingsStore,
                       paths: list[AttackPath]) -> list[str]:
    counts = findings.counts()
    total = len(findings)
    krit = counts.get("Kritisch", 0)
    hoch = counts.get("Hoch", 0)
    lines = ["## Executive Summary (Management-Zusammenfassung)", ""]
    lines.append(
        f"Im autorisierten Prüfumfang wurden **{total} Finding(s)** und "
        f"**{len(paths)} Angriffspfad(e)** über **{len(assets)} Asset(s)** "
        f"identifiziert, davon **{krit} kritische** und **{hoch} hohe** Risiken."
    )
    lines.append("")
    top = _top_risks(findings)
    if top:
        lines.append("**Wichtigste Risiken:**")
        for f in top:
            lines.append(f"- [{f.severity.label}] {f.title} ({f.asset})")
        lines.append("")
    if krit or hoch:
        lines.append(
            "> Handlungsempfehlung: Kritische und hohe Risiken sowie die unten "
            "genannten Quick Wins kurzfristig beheben, danach die strategischen "
            "Maßnahmen umsetzen."
        )
        lines.append("")
    return lines


def _section_risk_rating(findings: FindingsStore) -> list[str]:
    counts = findings.counts()
    lines = ["## Risiko-Einstufung", "", "| Schweregrad | Anzahl |", "|---|---|"]
    for sev in reversed(Severity):
        lines.append(f"| {sev.label} | {counts.get(sev.label, 0)} |")
    lines.append("")
    return lines


def _section_attack_paths(paths: list[AttackPath]) -> list[str]:
    lines = ["## Angriffspfade (toxische Kombinationen)", ""]
    if not paths:
        lines += ["_Keine korrelierten Angriffspfade._", ""]
        return lines
    for i, p in enumerate(paths, start=1):
        suffix = f"  ·  {p.instances} Kombinationen" if p.instances > 1 else ""
        lines.append(
            f"### AP-{i}: {p.title}  ·  Schweregrad: {p.severity.label}{suffix}"
        )
        lines.append("")
        for step_no, step in enumerate(p.steps, start=1):
            lines.append(f"{step_no}. {step}")
        lines.append("")
        if p.rationale:
            lines.append(f"> {p.rationale}")
        if p.finding_ids:
            lines.append(f"> Findings: {', '.join(p.finding_ids)}")
        lines.append("")
    return lines


def _section_delta(delta: Any) -> list[str]:
    if delta is None:
        return []
    seit = f" seit {delta.previous_date}" if delta.previous_date else ""
    alter = f" (vor {delta.aging_days} Tagen)" if delta.aging_days is not None else ""
    lines = [f"## Re-Test / Veränderung{seit}{alter}", ""]
    lines.append(
        f"- **Behoben:** {len(delta.resolved)}  ·  **Neu:** {len(delta.new)}  "
        f"·  **Weiterhin offen:** {len(delta.still_open)}"
    )
    lines.append("")
    if delta.resolved:
        lines.append("**Behoben seit dem letzten Bericht:**")
        for r in delta.resolved:
            lines.append(f"- {r.get('title', r.get('id'))} ({r.get('severity', '')})")
        lines.append("")
    if delta.new:
        lines.append("**Neu hinzugekommen:**")
        for f in delta.new:
            lines.append(f"- [{f.severity.label}] {f.title} ({f.asset})")
        lines.append("")
    return lines


def _section_choke_points(findings: FindingsStore, paths: list[AttackPath]) -> list[str]:
    lines = ["## Choke Points (engste Behebungsstellen)", ""]
    chokes = compute_choke_points(paths)
    if not chokes:
        lines += ["_Keine Choke Points (keine korrelierten Angriffspfade)._", ""]
        return lines
    lines.append(
        "Diese Findings zuerst beheben - jedes bricht mehrere Angriffspfade auf "
        "einmal (nach Wirkung geordnet):"
    )
    lines.append("")
    for cp in chokes:
        f = findings.get(cp.finding_id)
        titel = f.title if f else cp.finding_id
        asset = f" ({f.asset})" if f else ""
        lines.append(
            f"- **{titel}**{asset} [`{cp.finding_id}`] → bricht "
            f"{cp.paths_broken} Angriffspfad(e)"
        )
    lines.append("")
    return lines


def _section_quick_wins(findings: FindingsStore) -> list[str]:
    lines = ["## Quick Wins (kurzfristig, hohe Wirkung)", ""]
    wins = _quick_wins(findings)
    if not wins:
        lines += ["_Keine unmittelbaren Quick Wins identifiziert._", ""]
        return lines
    for f in wins:
        lines.append(f"- **{f.title}** ({f.asset}): {remediation_for(f)}")
    lines.append("")
    return lines


def _section_long_term(findings: FindingsStore) -> list[str]:
    lines = ["## Langfristige Maßnahmen", ""]
    measures = _long_term(findings)
    if not measures:
        lines += ["_Keine strategischen Maßnahmen abgeleitet._", ""]
        return lines
    for m in measures:
        lines.append(f"- {m}")
    lines.append("")
    return lines


def _section_findings(findings: FindingsStore) -> list[str]:
    lines = ["## Technische Findings (nach Schweregrad)", ""]
    if len(findings) == 0:
        lines += ["_Keine Findings erfasst._", ""]
        return lines
    for f in findings.all():
        cwe = f" · {f.cwe}" if f.cwe else ""
        score = cvss_score(f.category, f.severity)
        lines.append(f"### {f.id}: {f.title}")
        lines.append("")
        lines.append(
            f"- **Schweregrad:** {f.severity.label}{cwe}  ·  "
            f"**CVSS-Lite:** {score:.1f} ({cvss_rating(score)})  ·  "
            f"**Kategorie:** {f.category_label}  ·  **Status:** {f.status}"
        )
        lines.append(f"- **Asset:** {f.asset}  ·  **Fundstelle:** {f.location or 'n/a'}")
        lines.append(f"- **Owner:** {f.owner or 'noch zuzuweisen'}  ·  **Quelle:** {f.source}")
        if f.evidence:
            lines += ["", "**Beleg:**", "```", f.evidence.strip(), "```"]
        lines += ["", f"**Gegenmaßnahme:** {remediation_for(f)}", ""]
    return lines


def _section_bsi(findings: FindingsStore) -> list[str]:
    lines = [
        "## BSI-IT-Grundschutz-Mapping", "",
        "Zuordnung der Findings zu Bausteinen des BSI IT-Grundschutz-Kompendiums "
        "(sachkundige Orientierung, kein zertifizierter Konformitätsnachweis).",
        "",
    ]
    mappings = map_findings(findings.all())
    if not mappings:
        lines += ["_Keine Findings zum Mappen._", ""]
        return lines
    lines.append("| Finding | Risiko | Bereich | BSI-Bezug | Priorität |")
    lines.append("|---|---|---|---|---|")
    for m in mappings:
        risiko = m.risiko.replace("|", "/")
        bereich = m.bereich.replace("|", "/")
        lines.append(
            f"| {m.finding_id} | {risiko} | {bereich} | {m.bsi_bezug} | {m.priorität} |"
        )
    lines.append("")
    return lines


def _section_scanners(scanner_runs: list[dict[str, Any]]) -> list[str]:
    lines = ["## Scanner-Ergebnisse", ""]
    if not scanner_runs:
        lines += ["_Keine aktiven Scanner ausgeführt._", ""]
        return lines
    lines.append("| Scanner | Ziel | Findings | Exit | Hinweis |")
    lines.append("|---|---|---|---|---|")
    for run in scanner_runs:
        hinweis = run.get("error") or ("gekürzt" if run.get("truncated") else "-")
        lines.append(
            f"| {run.get('scanner')} | {run.get('target')} | "
            f"{run.get('finding_count', 0)} | {run.get('returncode')} | {hinweis} |"
        )
    lines.append("")
    return lines


def _section_scope(config: Config) -> list[str]:
    targets = ", ".join(config.allowed_targets) or "(keine)"
    paths = ", ".join(p.name for p in config.allowed_paths) or "(keine)"
    enabled_scanners = [n for n, p in config.scanners.items() if p.enabled] or ["(keine)"]
    return [
        "## Scope-Hinweise", "",
        f"- **Freigegebene Netzwerk-Ziele:** {targets}",
        f"- **Freigegebene Datei-Bereiche:** {paths}",
        f"- **Aktive Scanner freigegeben:** {', '.join(enabled_scanners)}",
        "- Aktionen außerhalb dieses Rahmens wurden technisch verweigert (fail-closed).",
        "",
    ]


def _section_limitations() -> list[str]:
    return [
        "## Limitierungen", "",
        "- Die Ergebnisse sind eine Momentaufnahme zum Prüfzeitpunkt.",
        "- Statische Code-Treffer sind Kandidaten und manuell zu verifizieren.",
        "- AD-/Exchange-Bewertungen beruhen auf bereitgestellten Exportdaten "
        "(kein Live-Abgleich); es erfolgte keine Ausnutzung von Schwachstellen.",
        "- Es wurden keine destruktiven Tests, keine Credential-Nutzung und keine "
        "Angriffe gegen produktive Systeme durchgeführt.",
        "",
    ]


def _section_next_steps() -> list[str]:
    return [
        "## Nächste Schritte", "",
        "1. Kritische/hohe Findings und Quick Wins kurzfristig beheben.",
        "2. Angriffspfade priorisiert schließen (an der schwächsten Stelle beginnen).",
        "3. Strategische (langfristige) Maßnahmen einplanen.",
        "4. Nach der Behebung gezielten Nachtest (Re-Test) durchführen.",
        "",
        "---",
        "_Dieser Bericht dokumentiert eine autorisierte, defensive Prüfung. "
        "Findings sind nach Stand der Technik zu beheben; personenbezogene Daten "
        "sind gemäß DSGVO und BSI IT-Grundschutz zu schützen._",
    ]


# ------------------------------- Aufbau -----------------------------------

def build_markdown(
    config: Config,
    assets: AssetGraph,
    findings: FindingsStore,
    paths: list[AttackPath],
    generated_at: str | None = None,
    scanner_runs: list[dict[str, Any]] | None = None,
    delta: Any = None,
) -> str:
    ts = generated_at or _now_iso()
    scanner_runs = scanner_runs or []
    lines: list[str] = []
    lines += _section_header(config, ts)
    lines += _section_executive(config, assets, findings, paths)
    lines += _section_delta(delta)
    lines += _section_risk_rating(findings)
    lines += _section_attack_paths(paths)
    lines += _section_choke_points(findings, paths)
    lines += _section_quick_wins(findings)
    lines += _section_long_term(findings)
    lines += _section_findings(findings)
    lines += _section_bsi(findings)
    lines += _section_scanners(scanner_runs)
    lines += _section_scope(config)
    lines += _section_limitations()
    lines += _section_next_steps()
    return "\n".join(lines)


def build_json(
    config: Config,
    assets: AssetGraph,
    findings: FindingsStore,
    paths: list[AttackPath],
    generated_at: str | None = None,
    scanner_runs: list[dict[str, Any]] | None = None,
    delta: Any = None,
) -> dict[str, Any]:
    eng = config.engagement
    scanner_runs = scanner_runs or []
    return {
        "engagement": {
            "name": eng.name,
            "authorized_by": eng.authorized_by,
            "authorization_ref": eng.authorization_ref,
        },
        "generated_at": generated_at or _now_iso(),
        "summary": {
            "assets": len(assets),
            "findings": len(findings),
            "attack_paths": len(paths),
            "severity_counts": findings.counts(),
            "quick_wins": len(_quick_wins(findings)),
            "max_cvss": max(
                (cvss_score(f.category, f.severity) for f in findings.all()),
                default=0.0,
            ),
        },
        "assets": [a.to_dict() for a in assets.assets()],
        "edges": [e.to_dict() for e in assets.edges()],
        "findings": [
            {
                **f.to_dict(),
                "cvss": cvss_score(f.category, f.severity),
                "cvss_rating": cvss_rating(cvss_score(f.category, f.severity)),
            }
            for f in findings.all()
        ],
        "attack_paths": [p.to_dict() for p in paths],
        "choke_points": [c.to_dict() for c in compute_choke_points(paths)],
        "quick_wins": [f.id for f in _quick_wins(findings)],
        "long_term_measures": _long_term(findings),
        "bsi_mapping": [m.to_dict() for m in map_findings(findings.all())],
        "scanner_runs": scanner_runs,
        "scope": {
            "allowed_targets": config.allowed_targets,
            "allowed_paths": [str(p) for p in config.allowed_paths],
            "enabled_scanners": [n for n, p in config.scanners.items() if p.enabled],
        },
        "retest": delta.to_dict() if delta is not None else None,
    }


def write_reports(
    config: Config,
    assets: AssetGraph,
    findings: FindingsStore,
    paths: list[AttackPath],
    directory: str | Path = "reports",
    scanner_runs: list[dict[str, Any]] | None = None,
    delta: Any = None,
) -> dict[str, Path]:
    """Schreibt Markdown- und JSON-Report und gibt die Pfade zurück."""
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    ts = _now_iso()

    md_path = out / f"specter-report-{stamp}.md"
    json_path = out / f"specter-report-{stamp}.json"

    md_path.write_text(
        build_markdown(config, assets, findings, paths, ts, scanner_runs, delta),
        encoding="utf-8",
    )
    json_path.write_text(
        json.dumps(
            build_json(config, assets, findings, paths, ts, scanner_runs, delta),
            ensure_ascii=False, indent=2,
        ),
        encoding="utf-8",
    )
    return {"markdown": md_path, "json": json_path}
