"""Datenmodell und Bewertungslogik der Specter-Benchmark.

Die Benchmark misst die Analyzer *gegen eine markierte Wahrheit* (Ground Truth):
Jedes Szenario ist ein realistischer Export, für den exakt bekannt ist, welche
Findings herauskommen müssen — und, ebenso wichtig, welche NICHT. Daraus wird
eine vollständige Konfusionsmatrix (TP/FP/FN) je Analyzer, je Kategorie und je
Schweregrad gebildet.

Warum das ehrlich ist: Es gibt keine erfundene „Erkennungsquote". Gemessen wird
ausschließlich gegen einen offengelegten, reproduzierbaren Korpus, den jeder auf
dem eigenen Rechner nachrechnen kann (`python examples/benchmark/run.py`).

Kernbegriffe
------------
* **Expect**  — eine erwartete Fund-Signatur: (Kategorie, Titel-Teilstring,
  optional Schweregrad). Bewusst **kein** stabiler Fund-Code, denn den gibt es
  im Modell nicht (die Finding-`id` ist ein Hash aus Kategorie/Asset/Ort/Titel).
  Genau wie die Labor-Harnesse matchen wir über Kategorie + Titel-Teilstring.
* **Scenario** — ein Analyzer-Input plus die *vollständige* Liste erwarteter
  Funde. „Vollständig" heißt: Jeder tatsächliche Fund, der zu keinem Expect
  passt, zählt als Fehlalarm (False Positive). Härtungs-Szenarien haben eine
  leere Erwartungsliste — dort ist **jeder** Fund ein Fehlalarm.
* **kind** — `vuln` (gepflanzte Lücke), `hardened` (sauberer Soll-Zustand,
  null Funde), `boundary` (Wert exakt auf der Schwelle) oder `confuser`
  (sieht gefährlich aus, ist es aber nicht — oder umgekehrt).
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

# Repo-Wurzel in den Importpfad, damit `specter` importierbar ist, egal von wo
# das Skript gestartet wird.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from datetime import date  # noqa: E402

from specter.analyzers import (  # noqa: E402
    analyze_ad, analyze_aws, analyze_azure, analyze_backup, analyze_container,
    analyze_database, analyze_dependencies, analyze_dns, analyze_email_security,
    analyze_entra, analyze_exchange, analyze_firewall, analyze_http_headers,
    analyze_tls,
)
from specter.aws_raw import normalize_aws_bundle  # noqa: E402
from specter.container_live import coerce_container_export  # noqa: E402
from specter.findings import Finding, Severity  # noqa: E402

# Festes Referenzdatum für zeitabhängige Roh-Ableitungen (Schlüssel-Alter),
# damit der Korpus auch in Jahren noch exakt dasselbe Ergebnis liefert.
_RAW_REFERENCE_DATE = date(2026, 7, 1)


def _analyze_container_raw(data: dict) -> list[Finding]:
    """Roh-Route: echte `docker inspect`-Ausgabe durch den Produktiv-Normalisierer."""
    return analyze_container(coerce_container_export(data))


def _analyze_aws_raw(data: dict) -> list[Finding]:
    """Roh-Route: echtes AWS-CLI-Bündel durch den Produktiv-Normalisierer."""
    return analyze_aws(normalize_aws_bundle(data, now=_RAW_REFERENCE_DATE))


# Registry: stabiler Schlüssel -> öffentliche Analyzer-Funktion. Die *_raw-
# Routen messen zusätzlich die Normalisierung echter Vendor-Formate — dieselben
# Code-Pfade, die auch die Kundenanalyse benutzt.
ANALYZERS: dict[str, Callable[[dict], list[Finding]]] = {
    "email": analyze_email_security,
    "dns": analyze_dns,
    "http": analyze_http_headers,
    "tls": analyze_tls,
    "database": analyze_database,
    "container": analyze_container,
    "container_raw": _analyze_container_raw,
    "dependency": analyze_dependencies,
    "backup": analyze_backup,
    "firewall": analyze_firewall,
    "aws": analyze_aws,
    "aws_raw": _analyze_aws_raw,
    "azure": analyze_azure,
    "ad": analyze_ad,
    "entra": analyze_entra,
    "exchange": analyze_exchange,
}

# Anzeigenamen der Analyzer für die Scorecard.
ANALYZER_LABELS: dict[str, str] = {
    "email": "E-Mail (SPF/DKIM/DMARC)",
    "dns": "DNS-Sicherheit",
    "http": "HTTP-Header/Cookies",
    "tls": "TLS/Zertifikate",
    "database": "Datenbanken",
    "container": "Container/Docker",
    "container_raw": "Container (roh: docker inspect)",
    "dependency": "Abhängigkeiten (SCA)",
    "backup": "Backup-Resilienz",
    "firewall": "Firewall/VPN",
    "aws": "AWS",
    "aws_raw": "AWS (roh: CLI-Bündel)",
    "azure": "Azure",
    "ad": "Active Directory",
    "entra": "Entra-ID/M365",
    "exchange": "Exchange",
}

KIND_LABELS: dict[str, str] = {
    "vuln": "Gepflanzte Lücke",
    "hardened": "Gehärtet (Soll: 0 Funde)",
    "boundary": "Schwellenwert",
    "confuser": "Täuschung",
}


@dataclass(frozen=True)
class Expect:
    """Eine erwartete Fund-Signatur (Ground-Truth-Eintrag)."""

    category: str
    title_contains: str
    severity: Optional[Severity] = None
    note: str = ""

    def matches(self, finding: Finding) -> bool:
        if finding.category != self.category:
            return False
        return self.title_contains in finding.title

    def describe(self) -> str:
        sev = f" [{self.severity.label}]" if self.severity is not None else ""
        return f"{self.category}{sev} ~ \"{self.title_contains}\""


@dataclass(frozen=True)
class Scenario:
    """Ein Analyzer-Input mit vollständiger Ground Truth."""

    id: str
    analyzer: str
    kind: str
    label: str
    data: dict
    expect: tuple[Expect, ...] = ()
    description: str = ""

    def __post_init__(self) -> None:
        if self.analyzer not in ANALYZERS:
            raise ValueError(f"Unbekannter Analyzer: {self.analyzer}")
        if self.kind not in KIND_LABELS:
            raise ValueError(f"Unbekannte Szenario-Art: {self.kind}")


@dataclass
class ScenarioResult:
    """Bewertetes Ergebnis eines Szenarios."""

    scenario: Scenario
    findings: list[Finding]
    detected: int                       # erfüllte Expects (True Positives)
    missed: list[Expect]                # nicht erfüllte Expects (False Negatives)
    false_alarms: list[Finding]         # Funde ohne passenden Expect (FP)
    severity_total: int                 # Expects mit Soll-Schweregrad, die trafen
    severity_correct: int               # davon mit korrektem Schweregrad
    ambiguous: list[Expect]             # Expects, die >1 Fund trafen (unscharf)

    @property
    def expected_total(self) -> int:
        return len(self.scenario.expect)

    @property
    def covered_findings(self) -> int:
        return len(self.findings) - len(self.false_alarms)

    @property
    def clean(self) -> bool:
        """Sauber = alle Erwartungen erfüllt, kein Fehlalarm, Schweregrad passt."""
        return (
            not self.missed
            and not self.false_alarms
            and self.severity_total == self.severity_correct
            and not self.ambiguous
        )


def score_scenario(scenario: Scenario) -> ScenarioResult:
    """Führt den Analyzer aus und gleicht die Funde mit der Ground Truth ab."""
    findings = ANALYZERS[scenario.analyzer](scenario.data)

    # Für jeden Expect: welche Funde trifft er? Für jeden Fund: welche Expects?
    expect_hits: list[list[int]] = [[] for _ in scenario.expect]
    finding_cover: list[list[int]] = [[] for _ in findings]
    for fi, finding in enumerate(findings):
        for ei, expect in enumerate(scenario.expect):
            if expect.matches(finding):
                expect_hits[ei].append(fi)
                finding_cover[fi].append(ei)

    detected = sum(1 for hits in expect_hits if hits)
    missed = [scenario.expect[ei] for ei, hits in enumerate(expect_hits) if not hits]
    false_alarms = [findings[fi] for fi, cov in enumerate(finding_cover) if not cov]
    ambiguous = [
        scenario.expect[ei] for ei, hits in enumerate(expect_hits) if len(hits) > 1
    ]

    severity_total = 0
    severity_correct = 0
    for ei, expect in enumerate(scenario.expect):
        if expect.severity is None or not expect_hits[ei]:
            continue
        severity_total += 1
        if all(findings[fi].severity == expect.severity for fi in expect_hits[ei]):
            severity_correct += 1

    return ScenarioResult(
        scenario=scenario,
        findings=findings,
        detected=detected,
        missed=missed,
        false_alarms=false_alarms,
        severity_total=severity_total,
        severity_correct=severity_correct,
        ambiguous=ambiguous,
    )


@dataclass
class Aggregate:
    """Summierte Kennzahlen über eine Menge von Szenario-Ergebnissen."""

    expected: int = 0
    detected: int = 0
    missed: int = 0
    false_alarms: int = 0
    covered_findings: int = 0
    severity_total: int = 0
    severity_correct: int = 0
    scenarios: int = 0
    clean_scenarios: int = 0
    # „Negative" Szenarien (leere Erwartung): Spezifitäts-Basis.
    negative_scenarios: int = 0
    negative_clean: int = 0

    def add(self, result: ScenarioResult) -> None:
        self.scenarios += 1
        self.expected += result.expected_total
        self.detected += result.detected
        self.missed += len(result.missed)
        self.false_alarms += len(result.false_alarms)
        self.covered_findings += result.covered_findings
        self.severity_total += result.severity_total
        self.severity_correct += result.severity_correct
        if result.clean:
            self.clean_scenarios += 1
        if result.expected_total == 0:
            self.negative_scenarios += 1
            if not result.false_alarms:
                self.negative_clean += 1

    @property
    def recall(self) -> float:
        return 1.0 if self.expected == 0 else self.detected / self.expected

    @property
    def precision(self) -> float:
        denom = self.covered_findings + self.false_alarms
        return 1.0 if denom == 0 else self.covered_findings / denom

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 0.0 if (p + r) == 0 else 2 * p * r / (p + r)

    @property
    def severity_accuracy(self) -> float:
        if self.severity_total == 0:
            return 1.0
        return self.severity_correct / self.severity_total

    @property
    def specificity(self) -> float:
        """Anteil der gehärteten Szenarien ohne jeden Fehlalarm."""
        if self.negative_scenarios == 0:
            return 1.0
        return self.negative_clean / self.negative_scenarios


def score_all(scenarios: list[Scenario]) -> list[ScenarioResult]:
    return [score_scenario(s) for s in scenarios]


def aggregate(results: list[ScenarioResult]) -> Aggregate:
    agg = Aggregate()
    for r in results:
        agg.add(r)
    return agg


def aggregate_by(
    results: list[ScenarioResult], key: Callable[[ScenarioResult], str]
) -> dict[str, Aggregate]:
    out: dict[str, Aggregate] = {}
    for r in results:
        out.setdefault(key(r), Aggregate()).add(r)
    return out
