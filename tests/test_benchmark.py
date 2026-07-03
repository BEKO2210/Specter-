"""CI-Gate für die Specter-Benchmark (examples/benchmark).

Diese Tests machen aus der Benchmark einen *stehenden Regressionswächter*: Sie
laufen bei jedem Commit mit und schlagen fehl, sobald

* eine gepflanzte Lücke nicht mehr erkannt wird (Recall < 100 %),
* ein gehärtetes/Schwellen-/Täuschungs-Szenario plötzlich einen Fehlalarm
  erzeugt (Präzision < 100 %) oder
* sich ein Schweregrad verschiebt.

So kann niemand versehentlich eine Regel lockern und dabei die Falsch-Positiv-
Rate hochziehen, ohne dass die CI es meldet. Der Benchmark-Code selbst liegt
bewusst unter `examples/` (nicht unter `specter/`) — er ist ein Prüfwerkzeug,
kein Produktivcode.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# examples/ in den Importpfad aufnehmen, damit `benchmark` importierbar ist.
_EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
if str(_EXAMPLES) not in sys.path:
    sys.path.insert(0, str(_EXAMPLES))

from benchmark import (  # noqa: E402
    ANALYZERS, SCENARIOS, aggregate, aggregate_by, score_all, score_scenario,
)
from benchmark.model import Expect, Scenario  # noqa: E402
from specter.findings import Severity  # noqa: E402


@pytest.fixture(scope="module")
def results():
    return score_all(SCENARIOS)


@pytest.fixture(scope="module")
def agg(results):
    return aggregate(results)


# ----------------------------- Die harten Gates -----------------------------

def test_full_recall(agg):
    """Jede gepflanzte Lücke muss erkannt werden."""
    assert agg.missed == 0, "Nicht erkannte, aber erwartete Funde"
    assert agg.recall == 1.0
    assert agg.detected == agg.expected


def test_zero_false_alarms(agg, results):
    """Kein Szenario darf einen Fund erzeugen, der nicht in der Ground Truth steht."""
    offenders = [
        (r.scenario.id, [f"{f.category}/{f.severity.label}/{f.title}"
                         for f in r.false_alarms])
        for r in results if r.false_alarms
    ]
    assert not offenders, f"Fehlalarme: {offenders}"
    assert agg.false_alarms == 0
    assert agg.precision == 1.0


def test_severity_accuracy(agg):
    """Jeder erkannte Fund trägt den erwarteten Schweregrad."""
    assert agg.severity_correct == agg.severity_total
    assert agg.severity_accuracy == 1.0


def test_no_ambiguous_matches(results):
    """Jeder Expect trifft genau einen Fund (scharfe Ground Truth)."""
    ambiguous = [(r.scenario.id, [e.describe() for e in r.ambiguous])
                 for r in results if r.ambiguous]
    assert not ambiguous, f"Unscharfe Erwartungen: {ambiguous}"


def test_specificity_on_hardened(agg):
    """Gehärtete Szenarien (leere Erwartung) bleiben zu 100 % fehlalarmfrei."""
    assert agg.specificity == 1.0
    assert agg.negative_scenarios >= 10  # es gibt genügend negative Kontrollen


def test_all_scenarios_clean(results):
    dirty = [r.scenario.id for r in results if not r.clean]
    assert not dirty, f"Nicht saubere Szenarien: {dirty}"


# --------------------------- Struktur des Korpus ---------------------------

def test_every_analyzer_is_exercised():
    """Alle 14 Analyzer sind mit mindestens einem Szenario abgedeckt."""
    covered = {s.analyzer for s in SCENARIOS}
    assert covered == set(ANALYZERS), f"Fehlend: {set(ANALYZERS) - covered}"


def test_each_analyzer_has_a_hardened_baseline():
    """Jeder Analyzer hat mindestens ein gehärtetes Null-Funde-Szenario."""
    hardened = {s.analyzer for s in SCENARIOS if s.kind == "hardened"}
    assert hardened == set(ANALYZERS), f"Ohne Härtungs-Baseline: {set(ANALYZERS) - hardened}"


def test_corpus_has_adversarial_scenarios():
    """Der Korpus enthält echte Härtefälle (Schwellen und Täuschungen)."""
    kinds = {s.kind for s in SCENARIOS}
    assert "boundary" in kinds
    assert "confuser" in kinds
    assert sum(s.kind in ("boundary", "confuser") for s in SCENARIOS) >= 15


def test_scenario_ids_unique():
    ids = [s.id for s in SCENARIOS]
    assert len(ids) == len(set(ids))


def test_corpus_size_is_substantial(agg):
    assert agg.scenarios >= 40
    assert agg.expected >= 120  # >= 120 markierte Funde


# --------------- Gezielte Regressionsanker (dokumentieren die Absicht) -------

def test_numeric_version_comparison_not_string():
    """`internal-lib 2.9.0` unter `<2.10.0` MUSS als verwundbar gelten.

    Ein String-Vergleich (`"2.9.0" > "2.10.0"`) würde die Lücke übersehen — genau
    das darf nie passieren.
    """
    scn = next(s for s in SCENARIOS if s.id == "dep-vuln")
    res = score_scenario(scn)
    titles = [f.title for f in res.findings]
    assert any("internal-lib 2.9.0" in t for t in titles)
    assert not res.missed


def test_upper_bound_is_exclusive():
    """`2.10.0` ist NICHT `<2.10.0` — die gepatchte Version darf nicht anschlagen."""
    scn = next(s for s in SCENARIOS if s.id == "dep-patched")
    res = score_scenario(scn)
    assert res.findings == []


def test_disabled_ca_policy_does_not_protect():
    """Eine deaktivierte Conditional-Access-Richtlinie darf keinen Schutz vortäuschen."""
    scn = next(s for s in SCENARIOS if s.id == "entra-ca-disabled")
    res = score_scenario(scn)
    assert any("Keine MFA-Erzwingung" in f.title for f in res.findings)


def test_public_web_port_is_not_flagged():
    """Ein öffentlich erreichbarer Webserver auf 443/80 ist legitim — kein Fund."""
    scn = next(s for s in SCENARIOS if s.id == "fw-hardened")
    res = score_scenario(scn)
    assert res.findings == []


def test_ec_key_not_treated_like_short_rsa():
    """256-Bit-EC ist stark und darf nicht wie ein 1024-Bit-RSA gemeldet werden."""
    scn = next(s for s in SCENARIOS if s.id == "tls-ec-key")
    res = score_scenario(scn)
    assert res.findings == []


def test_missing_db_flags_are_not_assumed_insecure():
    """Ein DB-Datensatz nur mit engine/port darf keinen Fund erzeugen."""
    scn = next(s for s in SCENARIOS if s.id == "db-minimal")
    res = score_scenario(scn)
    assert res.findings == []


# ------------------------- Modell-Selbsttests (leichtgewichtig) -------------

def test_expect_matches_on_category_and_title():
    from specter.findings import Finding
    f = Finding(title="Kein SPF-Eintrag für x.de", category="email_security",
                severity=Severity.HOCH, asset="x.de")
    assert Expect("email_security", "Kein SPF-Eintrag").matches(f)
    assert not Expect("dns_security", "Kein SPF-Eintrag").matches(f)
    assert not Expect("email_security", "DMARC").matches(f)


def test_scenario_rejects_unknown_analyzer():
    with pytest.raises(ValueError):
        Scenario("x", "does-not-exist", "vuln", "y", {})


def test_scenario_rejects_unknown_kind():
    with pytest.raises(ValueError):
        Scenario("x", "email", "nonsense", "y", {})
