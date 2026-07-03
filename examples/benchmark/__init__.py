"""Specter-Benchmark: Analyzer gegen markierte Ground Truth messen.

Öffentliche API:
    from benchmark import SCENARIOS, score_all, aggregate
"""

from __future__ import annotations

from .corpus import SCENARIOS
from .model import (
    ANALYZER_LABELS, ANALYZERS, KIND_LABELS, Aggregate, Expect, Scenario,
    ScenarioResult, aggregate, aggregate_by, score_all, score_scenario,
)

__all__ = [
    "SCENARIOS", "Scenario", "Expect", "ScenarioResult", "Aggregate",
    "ANALYZERS", "ANALYZER_LABELS", "KIND_LABELS",
    "score_scenario", "score_all", "aggregate", "aggregate_by",
]
