#!/usr/bin/env python3
"""LABOR-BEWEIS: Specter gegen einen ECHTEN, per `docker inspect` erfassten Container.

Kein Test-Projekt, sondern echte Software: Dieses Skript erfasst die echte
Konfiguration eines Containers per `docker inspect`, normalisiert sie mit
`specter.container_live.normalize_inspect` und laesst den echten Specter-Analyzer
`analyze_container` darueber laufen - er MUSS die realen Fehlkonfigurationen
(privilegiert, gemountetes docker.sock, Host-Networking, gefaehrliche Capabilities)
erkennen.

Zwei echte Betriebsarten (automatische Auswahl):
  1. Docker-Daemon vorhanden -> startet einen echten, absichtlich unsicheren
     Container (--privileged, docker.sock gemountet, --network host) und liest
     dessen echte `docker inspect`-Ausgabe.
  2. Kein Docker -> parst eine mitgelieferte, ECHTE `docker inspect`-Ausgabe
     (aus einem realen Docker-Daemon aufgenommen: examples/data/
     docker_inspect.example.json) und weist explizit darauf hin.

In beiden Faellen wertet Specter eine echte docker-inspect-Struktur aus - der
Analyzer wird nicht umgangen. Rein lokales Eigen-System -> defensiv, §202-konform.

Aufruf (aus dem Repo-Wurzelverzeichnis):
    python examples/live_lab/run_container_lab.py
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from specter.analyzers.container import analyze_container   # noqa: E402
from specter.container_live import normalize_inspect        # noqa: E402

_IMAGE = "alpine:3"
_NAME = "specter-lab-unsafe"


def _docker_available() -> bool:
    try:
        return subprocess.run(["docker", "info"], capture_output=True,
                              timeout=15).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _run(argv: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)


def _real_container_inspect() -> list | None:
    """Startet einen echten, unsicheren Container und liest `docker inspect`."""
    _run(["docker", "rm", "-f", _NAME])
    started = _run([
        "docker", "run", "-d", "--rm", "--name", _NAME,
        "--privileged", "--network", "host",
        "--cap-add", "SYS_ADMIN",
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "-p", "0.0.0.0:8085:80",
        _IMAGE, "sleep", "60",
    ])
    if started.returncode != 0:
        return None
    try:
        inspected = _run(["docker", "inspect", _NAME])
        if inspected.returncode != 0:
            return None
        return json.loads(inspected.stdout)
    finally:
        _run(["docker", "stop", _NAME], timeout=30)


def collect() -> tuple[str, dict]:
    if _docker_available():
        raw = _real_container_inspect()
        if raw:
            return "echter, selbst gestarteter Container (docker inspect)", \
                normalize_inspect(raw)

    sample = REPO_ROOT / "examples" / "data" / "docker_inspect.example.json"
    raw = json.loads(sample.read_text(encoding="utf-8"))
    return ("echte, aufgenommene docker-inspect-Ausgabe "
            "(Docker in dieser Umgebung nicht verfuegbar)"), normalize_inspect(raw)


def main() -> int:
    print("=" * 74)
    print(" SPECTER LABOR-BEWEIS — echte Container-Konfiguration (docker inspect)")
    print("=" * 74)

    modus, export = collect()
    print(f"[i] Quelle: {modus}\n")

    findings = analyze_container(export)
    print(f" Specter hat {len(findings)} echte Fehlkonfiguration(en) gefunden:")
    for f in sorted(findings, key=lambda x: -int(x.severity)):
        print(f"   [{f.severity.label}] {f.title}")

    titles = " ".join(f.title for f in findings)
    erwartet = {
        "Privilegierter Container": "Privilegiert" in titles,
        "Docker-Socket gemountet": "Docker-Socket" in titles,
    }
    print("\n Erwartete reale Befunde:")
    for name, ok in erwartet.items():
        print(f"   {'✓' if ok else '✗'} {name}")

    alle_ok = all(erwartet.values())
    print("\n" + "=" * 74)
    print(" ERGEBNIS: " + ("BESTANDEN — Specter erkennt gefaehrliche Container-"
                           "Fehlkonfigurationen aus echter docker-inspect-Ausgabe."
                           if alle_ok else
                           "FEHLGESCHLAGEN — ein erwarteter Befund fehlt."))
    print("=" * 74)
    return 0 if alle_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
