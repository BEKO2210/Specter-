"""Bewusst UNAUFFAELLIGE Datei - darf KEINE Findings ausloesen (Falsch-Positiv-Test)."""

from __future__ import annotations


def add(a: int, b: int) -> int:
    return a + b


def format_name(first: str, last: str) -> str:
    return f"{last}, {first}"


def is_even(n: int) -> bool:
    return n % 2 == 0
