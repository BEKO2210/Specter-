"""Tests fuer Remediation und Draft-PR-Generierung."""

from __future__ import annotations

from specter.findings import Finding
from specter.remediation import DEFAULT_REMEDIATION, draft_pr, remediation_for


def test_custom_remediation_wins():
    f = Finding("x", "injection", "hoch", "app", remediation="Mach dies konkret.")
    assert remediation_for(f) == "Mach dies konkret."


def test_default_remediation_per_category():
    f = Finding("x", "secret_exposure", "hoch", "app")
    assert remediation_for(f) == DEFAULT_REMEDIATION["secret_exposure"]


def test_unknown_category_uses_other():
    f = Finding("x", "nichtvorhanden", "mittel", "app")  # -> other
    assert remediation_for(f) == DEFAULT_REMEDIATION["other"]


def test_draft_pr_structure():
    f = Finding("SQL-Injection", "injection", "kritisch", "api",
                location="api.py:9", evidence="q = 'SELECT '+x", cwe="CWE-89",
                owner="Team API")
    pr = draft_pr(f)
    assert pr["title"].startswith("fix(security):")
    assert "Kritisch" in pr["title"]
    assert f.id in pr["body"]
    assert "CWE-89" in pr["body"]
    assert "Team API" in pr["body"]
    assert "api.py:9" in pr["body"]


def test_draft_pr_without_evidence_or_owner():
    f = Finding("Debug an", "misconfiguration", "niedrig", "app")
    pr = draft_pr(f)
    assert "(keine Evidenz erfasst)" in pr["body"]
    assert "noch zuzuweisen" in pr["body"]
