"""Kleine, defensive Hilfsfunktionen zum robusten Parsen von Export-Daten.

Reale Exporte aus Fremdsystemen sind nicht immer sauber typisiert: ein Feld,
das eine Liste sein sollte, kommt als Zahl, ein Objekt kommt als String. Ohne
Schutz wirft schon `for x in daten["ports"]` einen TypeError, wenn `ports` eine
einzelne Zahl ist. Diese Helfer normalisieren solche Werte, sodass ein Analyzer
im Zweifel einen Wert überspringt statt mit einem Stacktrace abzustürzen.
"""

from __future__ import annotations

from typing import Any


def as_list(value: Any) -> list:
    """Gibt ``value`` zurück, wenn es eine Liste ist, sonst eine leere Liste."""
    return value if isinstance(value, list) else []


def as_dict(value: Any) -> dict:
    """Gibt ``value`` zurück, wenn es ein dict ist, sonst ein leeres dict."""
    return value if isinstance(value, dict) else {}
