"""Report-Generierung (Markdown + JSON), auf Deutsch und auditierbar.

Fasst Asset-Graph, Findings und Angriffspfade zu einem Bericht zusammen -
das Deliverable der Pruefung. An deutschen Rahmenwerken orientiert
(BSI IT-Grundschutz, DSGVO-Hinweise), severity-sortiert und mit Evidenz.
"""

from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path
from typing import Any

from .assets import AssetGraph
from .attack_paths import AttackPath
from .config import Config
from .findings import FindingsStore, Severity
from .remediation import remediation_for


def _now_iso() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d %H:%M")


def build_markdown(
    config: Config,
    assets: AssetGraph,
    findings: FindingsStore,
    paths: list[AttackPath],
    generated_at: str | None = None,
) -> str:
    eng = config.engagement
    ts = generated_at or _now_iso()
    counts = findings.counts()
    total = len(findings)

    lines: list[str] = []
    lines.append(f"# Sicherheitsbericht - {eng.name}")
    lines.append("")
    lines.append(f"- **Erstellt:** {ts}")
    lines.append(f"- **Autorisiert durch:** {eng.authorized_by}")
    lines.append(f"- **Referenz:** {eng.authorization_ref}")
    lines.append(f"- **Werkzeug:** Specter (autorisierte Sicherheitspruefung)")
    lines.append("")

    # Management Summary
    lines.append("## Management-Zusammenfassung")
    lines.append("")
    lines.append(
        f"Es wurden **{total} Finding(s)** und **{len(paths)} Angriffspfad(e)** "
        f"ueber **{len(assets)} Asset(s)** identifiziert."
    )
    lines.append("")
    lines.append("| Schweregrad | Anzahl |")
    lines.append("|---|---|")
    for sev in reversed(Severity):
        lines.append(f"| {sev.label} | {counts.get(sev.label, 0)} |")
    lines.append("")

    # Angriffspfade zuerst - das ist der Kern (toxische Kombinationen).
    lines.append("## Angriffspfade (toxische Kombinationen)")
    lines.append("")
    if not paths:
        lines.append("_Keine korrelierten Angriffspfade._")
    else:
        for i, p in enumerate(paths, start=1):
            lines.append(f"### AP-{i}: {p.title}  ·  Schweregrad: {p.severity.label}")
            lines.append("")
            for step_no, step in enumerate(p.steps, start=1):
                lines.append(f"{step_no}. {step}")
            lines.append("")
            if p.rationale:
                lines.append(f"> {p.rationale}")
            if p.finding_ids:
                lines.append(f"> Findings: {', '.join(p.finding_ids)}")
            lines.append("")

    # Findings
    lines.append("## Findings (nach Schweregrad)")
    lines.append("")
    if total == 0:
        lines.append("_Keine Findings erfasst._")
    for f in findings.all():
        cwe = f" · {f.cwe}" if f.cwe else ""
        lines.append(f"### {f.id}: {f.title}")
        lines.append("")
        lines.append(
            f"- **Schweregrad:** {f.severity.label}{cwe}  ·  "
            f"**Kategorie:** {f.category_label}  ·  **Status:** {f.status}"
        )
        lines.append(f"- **Asset:** {f.asset}  ·  **Fundstelle:** {f.location or 'n/a'}")
        lines.append(f"- **Owner:** {f.owner or 'noch zuzuweisen'}  ·  **Quelle:** {f.source}")
        if f.evidence:
            lines.append("")
            lines.append("**Beleg:**")
            lines.append("```")
            lines.append(f.evidence.strip())
            lines.append("```")
        lines.append("")
        lines.append(f"**Gegenmassnahme:** {remediation_for(f)}")
        lines.append("")

    lines.append("---")
    lines.append(
        "_Hinweis: Dieser Bericht dokumentiert eine autorisierte Pruefung. "
        "Findings sind nach Stand der Technik zu beheben; sensible Daten sind "
        "gemaess DSGVO und BSI IT-Grundschutz zu schuetzen._"
    )
    return "\n".join(lines)


def build_json(
    config: Config,
    assets: AssetGraph,
    findings: FindingsStore,
    paths: list[AttackPath],
    generated_at: str | None = None,
) -> dict[str, Any]:
    eng = config.engagement
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
        },
        "assets": [a.to_dict() for a in assets.assets()],
        "edges": [e.to_dict() for e in assets.edges()],
        "findings": [f.to_dict() for f in findings.all()],
        "attack_paths": [p.to_dict() for p in paths],
    }


def write_reports(
    config: Config,
    assets: AssetGraph,
    findings: FindingsStore,
    paths: list[AttackPath],
    directory: str | Path = "reports",
) -> dict[str, Path]:
    """Schreibt Markdown- und JSON-Report und gibt die Pfade zurueck."""
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    ts = _now_iso()

    md_path = out / f"specter-report-{stamp}.md"
    json_path = out / f"specter-report-{stamp}.json"

    md_path.write_text(
        build_markdown(config, assets, findings, paths, ts), encoding="utf-8"
    )
    json_path.write_text(
        json.dumps(
            build_json(config, assets, findings, paths, ts),
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    return {"markdown": md_path, "json": json_path}
