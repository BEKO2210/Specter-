#!/usr/bin/env python3
"""Specter-Benchmark-Läufer: misst die Analyzer gegen die Ground Truth.

    python examples/benchmark/run.py            # farbige Scorecard
    python examples/benchmark/run.py --json      # maschinenlesbares Ergebnis
    python examples/benchmark/run.py --details   # zusätzlich jede Zeile einzeln

Der Läufer ist zugleich ein **Gate**: Unterschreitet die Erkennung 100 %, gibt
es einen Fehlalarm oder stimmt ein Schweregrad nicht, endet der Prozess mit
Exit-Code 1 (praktisch für CI und für die eigene Nachprüfung).

Ehrlichkeitsprinzip: Es wird ausschließlich gegen den offengelegten Korpus
(`examples/benchmark/corpus.py`) gemessen. Keine externen Ziele, keine
geschätzten Quoten — jeder kann die Zahl auf dem eigenen Rechner reproduzieren.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
_EXAMPLES = _REPO_ROOT / "examples"
if str(_EXAMPLES) not in sys.path:
    sys.path.insert(0, str(_EXAMPLES))

from benchmark import (  # noqa: E402
    ANALYZER_LABELS, KIND_LABELS, SCENARIOS, aggregate, aggregate_by, score_all,
)
from benchmark.model import Aggregate, ScenarioResult  # noqa: E402
from specter.cvss import cvss_rating, cvss_score  # noqa: E402
from specter.findings import Severity  # noqa: E402

# Schwellen, ab denen der Lauf als bestanden gilt (streng — ein Gate, kein Ziel).
MIN_RECALL = 1.0
MIN_PRECISION = 1.0
MIN_SEVERITY_ACCURACY = 1.0


def _gate_ok(agg: Aggregate) -> bool:
    return (
        agg.recall >= MIN_RECALL
        and agg.precision >= MIN_PRECISION
        and agg.severity_accuracy >= MIN_SEVERITY_ACCURACY
        and agg.missed == 0
        and agg.false_alarms == 0
    )


def _pct(x: float) -> str:
    return f"{x * 100:.1f}%"


# ---------------------------------------------------------------- rich-Ausgabe

def _render_rich(results: list[ScenarioResult], agg: Aggregate, elapsed: float,
                 details: bool) -> None:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import box

    con = Console()
    teal = "#14B8A6"
    ok = _gate_ok(agg)

    con.print()
    con.rule(f"[bold {teal}]Specter-Benchmark — Erkennung gegen markierte Ground Truth")
    con.print()

    # Kopf-Kennzahlen.
    head = Table.grid(expand=True, padding=(0, 2))
    for _ in range(4):
        head.add_column(justify="center", ratio=1)
    head.add_row(
        f"[bold {teal}]{_pct(agg.recall)}[/]", f"[bold {teal}]{_pct(agg.precision)}[/]",
        f"[bold {teal}]{_pct(agg.f1)}[/]", f"[bold {teal}]{_pct(agg.specificity)}[/]",
    )
    head.add_row(
        "[dim]Erkennung (Recall)[/]", "[dim]Präzision[/]",
        "[dim]F1[/]", "[dim]Spezifität[/]",
    )
    con.print(Panel(head, border_style=teal, box=box.ROUNDED))

    summary = (
        f"[bold]{agg.detected}/{agg.expected}[/] gepflanzte Lücken erkannt   ·   "
        f"[bold]{agg.false_alarms}[/] Fehlalarme   ·   "
        f"[bold]{agg.severity_correct}/{agg.severity_total}[/] Schweregrade korrekt   ·   "
        f"[bold]{agg.negative_clean}/{agg.negative_scenarios}[/] gehärtete Szenarien sauber"
    )
    con.print(summary, justify="center")
    con.print()

    # Je Analyzer.
    by_an = aggregate_by(results, lambda r: r.scenario.analyzer)
    t = Table(title="Nach Prüfbereich", box=box.SIMPLE_HEAVY, title_style=f"bold {teal}",
              header_style=f"bold {teal}", expand=True)
    t.add_column("Bereich")
    t.add_column("Szen.", justify="right")
    t.add_column("Erkannt", justify="right")
    t.add_column("Fehlalarm", justify="right")
    t.add_column("Recall", justify="right")
    t.add_column("Präzision", justify="right")
    for key in sorted(by_an, key=lambda k: ANALYZER_LABELS.get(k, k)):
        a = by_an[key]
        t.add_row(
            ANALYZER_LABELS.get(key, key), str(a.scenarios),
            f"{a.detected}/{a.expected}", str(a.false_alarms),
            _pct(a.recall), _pct(a.precision),
        )
    con.print(t)

    # Je Szenario-Art.
    by_kind = aggregate_by(results, lambda r: r.scenario.kind)
    t2 = Table(title="Nach Szenario-Art", box=box.SIMPLE_HEAVY, title_style=f"bold {teal}",
               header_style=f"bold {teal}", expand=True)
    t2.add_column("Art")
    t2.add_column("Szenarien", justify="right")
    t2.add_column("Erwartet", justify="right")
    t2.add_column("Erkannt", justify="right")
    t2.add_column("Fehlalarme", justify="right")
    for key in ("vuln", "hardened", "boundary", "confuser"):
        if key not in by_kind:
            continue
        a = by_kind[key]
        t2.add_row(KIND_LABELS[key], str(a.scenarios), str(a.expected),
                   str(a.detected), str(a.false_alarms))
    con.print(t2)

    # Je Schweregrad (aus den erwarteten, erkannten Funden).
    sev_counts = {s: 0 for s in (Severity.KRITISCH, Severity.HOCH, Severity.MITTEL, Severity.NIEDRIG)}
    for r in results:
        for f in r.findings:
            if r.scenario.expect and any(e.matches(f) for e in r.scenario.expect):
                sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    t3 = Table(title="Erkannte Funde nach Schweregrad (mit CVSS-Lite-Band)",
               box=box.SIMPLE_HEAVY, title_style=f"bold {teal}",
               header_style=f"bold {teal}", expand=True)
    t3.add_column("Schweregrad")
    t3.add_column("Anzahl", justify="right")
    t3.add_column("CVSS-Lite (Beispiel)", justify="right")
    example_cat = {Severity.KRITISCH: "default_credentials", Severity.HOCH: "remote_access",
                   Severity.MITTEL: "transport_security", Severity.NIEDRIG: "web_security"}
    for sev in (Severity.KRITISCH, Severity.HOCH, Severity.MITTEL, Severity.NIEDRIG):
        score = cvss_score(example_cat[sev], sev)
        t3.add_row(sev.label, str(sev_counts.get(sev, 0)),
                   f"{score:.1f} ({cvss_rating(score)})")
    con.print(t3)

    if details:
        con.print()
        dt = Table(title="Szenarien im Detail", box=box.MINIMAL, header_style=f"bold {teal}",
                   expand=True)
        dt.add_column("ID")
        dt.add_column("Art")
        dt.add_column("Erw.", justify="right")
        dt.add_column("Funde", justify="right")
        dt.add_column("Status")
        for r in results:
            status = "[green]sauber[/]" if r.clean else "[red]FEHLER[/]"
            dt.add_row(r.scenario.id, KIND_LABELS[r.scenario.kind],
                       str(r.expected_total), str(len(r.findings)), status)
        con.print(dt)

    # Fehler explizit auflisten.
    problems = [r for r in results if not r.clean]
    if problems:
        con.print()
        con.print("[bold red]Abweichungen von der Ground Truth:[/]")
        for r in problems:
            con.print(f"  [red]•[/] {r.scenario.id} ({r.scenario.analyzer})")
            for e in r.missed:
                con.print(f"      [yellow]verfehlt[/]: {e.describe()}")
            for f in r.false_alarms:
                con.print(f"      [red]Fehlalarm[/]: {f.category} [{f.severity.label}] {f.title}")
            for e in r.ambiguous:
                con.print(f"      [magenta]unscharf[/]: {e.describe()} traf mehrere Funde")

    con.print()
    verdict = (f"[bold green]✓ BESTANDEN[/]" if ok
               else "[bold red]✗ DURCHGEFALLEN[/]")
    con.print(Panel(
        f"{verdict}   ·   {agg.scenarios} Szenarien in {elapsed * 1000:.0f} ms   ·   "
        f"Korpus: examples/benchmark/corpus.py",
        border_style=(teal if ok else "red"), box=box.ROUNDED,
    ))
    con.print()


def _render_plain(results: list[ScenarioResult], agg: Aggregate, elapsed: float) -> None:
    line = "=" * 70
    print(line)
    print(" Specter-Benchmark — Erkennung gegen markierte Ground Truth")
    print(line)
    print(f" Recall (Erkennung): {_pct(agg.recall)}   Präzision: {_pct(agg.precision)}   "
          f"F1: {_pct(agg.f1)}")
    print(f" Erkannt: {agg.detected}/{agg.expected}   Fehlalarme: {agg.false_alarms}   "
          f"Schweregrade: {agg.severity_correct}/{agg.severity_total}")
    print(f" Gehärtete Szenarien ohne Fehlalarm: {agg.negative_clean}/{agg.negative_scenarios}")
    print(line)
    by_an = aggregate_by(results, lambda r: r.scenario.analyzer)
    for key in sorted(by_an, key=lambda k: ANALYZER_LABELS.get(k, k)):
        a = by_an[key]
        print(f"  {ANALYZER_LABELS.get(key, key):<28} "
              f"erkannt {a.detected}/{a.expected:<3} fehlalarm {a.false_alarms}")
    print(line)
    for r in results:
        if not r.clean:
            print(f"  FEHLER {r.scenario.id}: verfehlt={len(r.missed)} "
                  f"fehlalarm={len(r.false_alarms)}")
    verdict = "BESTANDEN" if _gate_ok(agg) else "DURCHGEFALLEN"
    print(f" Ergebnis: {verdict}  ({agg.scenarios} Szenarien, {elapsed * 1000:.0f} ms)")
    print(line)


def _emit_json(results: list[ScenarioResult], agg: Aggregate, elapsed: float) -> None:
    by_an = aggregate_by(results, lambda r: r.scenario.analyzer)
    payload = {
        "passed": _gate_ok(agg),
        "scenarios": agg.scenarios,
        "expected": agg.expected,
        "detected": agg.detected,
        "missed": agg.missed,
        "false_alarms": agg.false_alarms,
        "recall": round(agg.recall, 6),
        "precision": round(agg.precision, 6),
        "f1": round(agg.f1, 6),
        "severity_accuracy": round(agg.severity_accuracy, 6),
        "specificity": round(agg.specificity, 6),
        "severity_total": agg.severity_total,
        "severity_correct": agg.severity_correct,
        "elapsed_ms": round(elapsed * 1000, 1),
        "by_analyzer": {
            k: {"scenarios": a.scenarios, "expected": a.expected,
                "detected": a.detected, "false_alarms": a.false_alarms,
                "recall": round(a.recall, 6), "precision": round(a.precision, 6)}
            for k, a in by_an.items()
        },
        "problems": [
            {"id": r.scenario.id, "analyzer": r.scenario.analyzer,
             "missed": [e.describe() for e in r.missed],
             "false_alarms": [f"{f.category}/{f.severity.label}/{f.title}"
                              for f in r.false_alarms]}
            for r in results if not r.clean
        ],
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Specter-Benchmark ausführen.")
    parser.add_argument("--json", action="store_true", help="Ergebnis als JSON ausgeben")
    parser.add_argument("--details", action="store_true", help="jede Zeile einzeln zeigen")
    parser.add_argument("--plain", action="store_true", help="ohne Farben/rich ausgeben")
    args = parser.parse_args(argv)

    start = time.monotonic()
    results = score_all(SCENARIOS)
    agg = aggregate(results)
    elapsed = time.monotonic() - start

    if args.json:
        _emit_json(results, agg, elapsed)
    elif args.plain:
        _render_plain(results, agg, elapsed)
    else:
        try:
            _render_rich(results, agg, elapsed, args.details)
        except ImportError:
            _render_plain(results, agg, elapsed)

    return 0 if _gate_ok(agg) else 1


if __name__ == "__main__":
    raise SystemExit(main())
