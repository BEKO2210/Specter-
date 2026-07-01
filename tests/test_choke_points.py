"""Tests fuer die Choke-Point-Analyse (Greedy-Hitting-Set)."""

from __future__ import annotations

from specter.attack_paths import AttackPath, correlate
from specter.assets import AssetGraph
from specter.choke_points import ChokePoint, compute_choke_points
from specter.findings import Finding, FindingsStore, Severity


def _p(title, sev, fids):
    return AttackPath(title, sev, ["Schritt"], fids)


def test_empty_paths():
    assert compute_choke_points([]) == []


def test_paths_without_findings_ignored():
    assert compute_choke_points([_p("x", Severity.HOCH, [])]) == []


def test_single_finding_covers_all():
    paths = [_p("P1", Severity.KRITISCH, ["F1"]), _p("P2", Severity.HOCH, ["F1"])]
    cps = compute_choke_points(paths)
    assert len(cps) == 1
    assert cps[0].finding_id == "F1"
    assert cps[0].paths_broken == 2
    assert cps[0].path_titles == ["P1", "P2"]


def test_greedy_minimal_set():
    paths = [
        _p("P1", Severity.KRITISCH, ["F1", "F3"]),
        _p("P2", Severity.HOCH, ["F1"]),
        _p("P3", Severity.HOCH, ["F2"]),
    ]
    cps = compute_choke_points(paths)
    # F1 bricht 2 Pfade -> zuerst; danach F2 fuer den Rest. F3 unnoetig.
    assert [c.finding_id for c in cps] == ["F1", "F2"]
    assert cps[0].paths_broken == 2
    assert cps[1].paths_broken == 1


def test_deterministic_tie_break():
    # Zwei Findings brechen je 1 Pfad -> alphabetische Reihenfolge (A vor B).
    paths = [_p("P1", Severity.HOCH, ["B"]), _p("P2", Severity.HOCH, ["A"])]
    cps = compute_choke_points(paths)
    assert [c.finding_id for c in cps] == ["A", "B"]


def test_all_paths_covered():
    paths = [
        _p("P1", Severity.KRITISCH, ["F1", "F2"]),
        _p("P2", Severity.HOCH, ["F2", "F3"]),
        _p("P3", Severity.HOCH, ["F3", "F4"]),
    ]
    cps = compute_choke_points(paths)
    covered = set()
    for c in cps:
        covered.add(c.finding_id)
    # Jeder Pfad muss von mindestens einem gewaehlten Finding getroffen werden.
    for p in paths:
        assert covered & set(p.finding_ids)


def test_to_dict():
    cp = ChokePoint("F1", 3, ["P1", "P2", "P3"])
    d = cp.to_dict()
    assert d == {"finding_id": "F1", "paths_broken": 3,
                 "path_titles": ["P1", "P2", "P3"]}


def test_choke_points_from_real_correlation():
    # Mehrere Secrets + ein Dienst -> aggregierter Pfad; Choke Point = Dienst
    # oder Secret, das den Sammelpfad bricht.
    store = FindingsStore()
    store.add(Finding("K1", "secret_exposure", "hoch", "app", location="a:1"))
    store.add(Finding("K2", "secret_exposure", "hoch", "app", location="a:2"))
    store.add(Finding("SSH", "exposed_service", "hoch", "host", location="h:22"))
    paths = correlate(store, AssetGraph())
    cps = compute_choke_points(paths)
    assert cps                                   # es gibt Choke Points
    assert cps[0].paths_broken >= 1
