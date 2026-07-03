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


def as_str_list(value: Any) -> list[str]:
    """Normalisiert ein Feld, das eine Liste von Namen sein sollte.

    Reale Exporte liefern statt ``["Domain Admins"]`` gern auch den nackten
    String ``"Domain Admins"`` — oder Müll (Zahl, ``None``). Listen werden
    elementweise zu Strings, ein nicht-leerer String wird zur Ein-Element-
    Liste, alles andere zur leeren Liste (= nicht bewertbar, kein Absturz).
    """
    if isinstance(value, list):
        return [str(x) for x in value if str(x).strip()]
    if isinstance(value, str) and value.strip():
        return [value]
    return []


# Zeichenketten, die in realen Exporten für Wahr/Falsch stehen (CSV, YAML,
# PowerShell-Ausgaben, handgepflegte Fragebögen).
_TRUE_WORDS = {"true", "yes", "ja", "1", "on", "enabled", "aktiv", "aktiviert"}
_FALSE_WORDS = {"false", "no", "nein", "0", "off", "disabled", "inaktiv",
                "deaktiviert"}


def as_bool(value: Any, default: Any = None) -> Any:
    """Toleranter Bool-Parser für Export-Felder.

    Reale Exporte liefern statt ``true``/``false`` oft Strings ("false",
    "nein", "0") oder Zahlen (0/1). Eine naive Truthiness-Prüfung wertet den
    String ``"false"`` als wahr — das erzeugt Fehlalarme bzw. übersieht Funde.

    Rückgabe: ``True``/``False`` bei eindeutigem Wert, sonst ``default``
    (Standard ``None`` = „nicht bewertbar", damit fehlende Angaben weiterhin
    nicht bewertet werden).
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        if value == 0:
            return False
        if value == 1:
            return True
        return default
    if isinstance(value, str):
        word = value.strip().lower()
        if word in _TRUE_WORDS:
            return True
        if word in _FALSE_WORDS:
            return False
    return default


def as_int(value: Any, default: Any = None) -> Any:
    """Toleranter Int-Parser für Export-Felder.

    Akzeptiert ``int``, ganzzahlige ``float`` und numerische Strings ("8",
    " 8 ", "8.0"). ``bool`` wird bewusst NICHT als Zahl gewertet, und alles
    Unparsebare liefert ``default`` (Standard ``None`` = „nicht bewertbar").
    """
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if value.is_integer() else default
    if isinstance(value, str):
        text = value.strip()
        try:
            return int(text, 10)
        except ValueError:
            try:
                number = float(text)
            except ValueError:
                return default
            return int(number) if number.is_integer() else default
    return default
