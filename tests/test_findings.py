"""Tests für das Findings-Modell und den Store."""

from __future__ import annotations

import pytest

from specter.findings import Finding, FindingsStore, Severity


def test_severity_parse_de_and_en():
    assert Severity.parse("hoch") is Severity.HOCH
    assert Severity.parse("critical") is Severity.KRITISCH
    assert Severity.parse(2) is Severity.MITTEL
    with pytest.raises(ValueError):
        Severity.parse("banane")


def test_severity_ordering():
    assert Severity.KRITISCH > Severity.HOCH > Severity.MITTEL > Severity.NIEDRIG


def test_finding_stable_id_and_dedup():
    f1 = Finding("SQLi", "injection", "hoch", "app", location="a.py:1")
    f2 = Finding("SQLi", "injection", "hoch", "app", location="a.py:1")
    assert f1.id == f2.id  # gleiche Basis -> gleiche ID
    store = FindingsStore()
    _, new1 = store.add(f1)
    _, new2 = store.add(f2)
    assert new1 is True and new2 is False
    assert len(store) == 1


def test_unknown_category_falls_back():
    f = Finding("x", "nichtvorhanden", "mittel", "app")
    assert f.category == "other"


def test_store_sorted_by_severity():
    store = FindingsStore()
    store.add(Finding("low", "misconfiguration", "niedrig", "a"))
    store.add(Finding("crit", "injection", "kritisch", "b"))
    store.add(Finding("mid", "crypto_weakness", "mittel", "c"))
    order = [f.severity for f in store.all()]
    assert order == sorted(order, reverse=True)


def test_counts():
    store = FindingsStore()
    store.add(Finding("a", "injection", "kritisch", "x"))
    store.add(Finding("b", "injection", "kritisch", "y"))
    store.add(Finding("c", "misconfiguration", "niedrig", "z"))
    counts = store.counts()
    assert counts["Kritisch"] == 2
    assert counts["Niedrig"] == 1
    assert counts["Hoch"] == 0
