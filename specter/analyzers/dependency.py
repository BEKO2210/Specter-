"""Defensive SCA-/Abhängigkeits-Analyse (Software Composition Analysis).

Wertet einen lokalen JSON-Export der eingesetzten Abhängigkeiten (z. B. aus
requirements.txt, pip freeze, package.json, npm ls oder einer SBOM) gegen eine
ebenfalls lokal bereitgestellte Advisory-/CVE-Liste aus. Ziel: bekannte
verwundbare Komponenten (Log4Shell-Klasse), nicht mehr gepflegte Pakete und
ungepinnte Versionen erkennen - rein offline, ohne Abfrage von Paket-Registries
oder CVE-Feeds, ohne jede Ausnutzung.

Das ist im Mittelstand ein Haupteinfallstor: veraltete Bibliotheken mit
öffentlich bekannten Lücken (OWASP A06:2021 "Vulnerable and Outdated
Components").

Erwartete Struktur (alle Felder optional):

    {
      "project": "portal-backend",
      "dependencies": [
        {"name": "log4j-core", "version": "2.14.1", "ecosystem": "maven"},
        {"name": "django", "version": "2.2.0", "ecosystem": "pypi"},
        {"name": "lodash", "version": "4.17.11", "ecosystem": "npm",
         "deprecated": true},
        {"name": "requests", "version": "*", "ecosystem": "pypi"}
      ],
      "advisories": [
        {"name": "log4j-core", "ecosystem": "maven", "vulnerable": "<2.15.0",
         "fixed": "2.17.1", "cve": "CVE-2021-44228", "severity": "kritisch",
         "title": "Log4Shell Remote Code Execution"}
      ]
    }

Die Advisory-Liste ist die vom Betreiber/Prüfer bereitgestellte lokale
Wissensbasis - so bleibt die Analyse deterministisch und vollständig offline.
"""

from __future__ import annotations

import re
from typing import Any

from ..findings import Finding, Severity
from ._util import as_bool, as_list

# Werte, die eine nicht festgelegte ("ungepinnte") Version markieren.
_UNPINNED = {"", "*", "latest", "any", "x"}
_UNMAINTAINED_VERSION_SEV = Severity.MITTEL
_TWO_CHAR_OPS = ("<=", ">=", "==", "!=")


def _mk(title, category, severity, asset, evidence, *, location="", cwe="",
        owner="Entwicklung/DevOps") -> Finding:
    return Finding(
        title=title, category=category, severity=severity, asset=asset,
        location=location or asset, evidence=evidence, cwe=cwe, owner=owner,
        source="dependency_analyzer", status="offen",
    )


def _parse_version(value: Any) -> tuple[int, ...]:
    """Zerlegt eine Versionsangabe in eine vergleichbare Zahlenfolge."""
    parts: list[int] = []
    for token in re.split(r"[.\-+_]", str(value).strip()):
        digits = ""
        for ch in token:
            if ch.isdigit():
                digits += ch
            else:
                break
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def _cmp(a: Any, b: Any) -> int:
    """Vergleicht zwei Versionen: -1 (<), 0 (=), 1 (>)."""
    va, vb = _parse_version(a), _parse_version(b)
    length = max(len(va), len(vb))
    va += (0,) * (length - len(va))
    vb += (0,) * (length - len(vb))
    return (va > vb) - (va < vb)


def _split_op(part: str) -> tuple[str, str]:
    """Trennt einen Constraint in (Operator, Version). Default: '=='."""
    part = part.strip()
    for op in _TWO_CHAR_OPS:
        if part.startswith(op):
            return op, part[len(op):].strip()
    if part[:1] in ("<", ">"):
        return part[0], part[1:].strip()
    return "==", part


def _satisfies(version: Any, constraint: str) -> bool:
    """Prüft, ob eine Version die (kommagetrennten) Constraints erfüllt."""
    matched_any = False
    for raw in str(constraint).split(","):
        raw = raw.strip()
        if not raw:
            continue
        op, ver = _split_op(raw)
        if not ver:
            continue
        matched_any = True
        c = _cmp(version, ver)
        if op == "<" and not c < 0:
            return False
        if op == "<=" and not c <= 0:
            return False
        if op == ">" and not c > 0:
            return False
        if op == ">=" and not c >= 0:
            return False
        if op == "==" and c != 0:
            return False
        if op == "!=" and c == 0:
            return False
    return matched_any


def _advisory_matches(dep: dict[str, Any], adv: dict[str, Any]) -> bool:
    """True, wenn ein Advisory auf eine Abhängigkeit zutrifft."""
    if str(dep.get("name", "")).strip().lower() != str(adv.get("name", "")).strip().lower():
        return False
    adv_eco = str(adv.get("ecosystem", "")).strip().lower()
    dep_eco = str(dep.get("ecosystem", "")).strip().lower()
    if adv_eco and dep_eco and adv_eco != dep_eco:
        return False
    return _satisfies(dep.get("version", ""), str(adv.get("vulnerable", "")))


def _analyze_dependency(dep: dict[str, Any], advisories: list[dict[str, Any]],
                        project: str) -> list[Finding]:
    out: list[Finding] = []
    name = str(dep.get("name", "?"))
    eco = str(dep.get("ecosystem", "")).strip()
    version = str(dep.get("version", "")).strip()
    loc = f"{project}/{eco}/{name}" if eco else f"{project}/{name}"

    matches = [a for a in advisories if _advisory_matches(dep, a)]
    for adv in matches:
        sev = Severity.HOCH
        try:
            sev = Severity.parse(adv.get("severity", "hoch"))
        except ValueError:
            sev = Severity.HOCH
        cve = str(adv.get("cve", "")).strip() or "ohne CVE-ID"
        fixed = str(adv.get("fixed", "")).strip()
        adv_title = str(adv.get("title", "")).strip()
        detail = f" - {adv_title}" if adv_title else ""
        fix_hint = f"; behoben in {fixed}" if fixed else ""
        out.append(_mk(
            f"Verwundbare Abhängigkeit: {name} {version} ({cve})",
            "outdated_component", sev, loc,
            f"Version {version} erfüllt Advisory {cve} "
            f"(verwundbar: {adv.get('vulnerable')}{fix_hint}){detail}",
            location=loc, cwe="CWE-1395",
        ))

    if matches:
        return out

    if as_bool(dep.get("deprecated"), False):
        out.append(_mk(
            f"Nicht mehr gepflegte Abhängigkeit: {name}",
            "outdated_component", _UNMAINTAINED_VERSION_SEV, loc,
            f"deprecated=true (Version {version or 'unbekannt'}) - kein "
            "Sicherheits-Support mehr",
            location=loc, cwe="CWE-1104",
        ))
    if version.lower() in _UNPINNED:
        out.append(_mk(
            f"Ungepinnte Abhängigkeit: {name}",
            "outdated_component", Severity.NIEDRIG, loc,
            f"version={version or '(leer)'} - keine feste Version, "
            "reproduzierbare Builds und CVE-Zuordnung erschwert",
            location=loc, cwe="CWE-1104",
        ))
    return out


def analyze_dependencies(data: dict[str, Any]) -> list[Finding]:
    """Führt alle SCA-Prüfungen aus und liefert die Findings."""
    if not isinstance(data, dict):
        return []
    project = str(data.get("project", "Projekt"))
    advisories = [a for a in as_list(data.get("advisories")) if isinstance(a, dict)]
    findings: list[Finding] = []
    for dep in as_list(data.get("dependencies")):
        if isinstance(dep, dict):
            findings += _analyze_dependency(dep, advisories, project)
    return findings
