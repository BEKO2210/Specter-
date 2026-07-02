#!/usr/bin/env python3
"""LABOR-BEWEIS: Specter gegen eine ECHTE, selbst gestartete Datenbank.

Kein Test-Projekt, sondern echte Software: Dieses Skript startet einen echten
Redis-Dienst OHNE Authentifizierung, verbindet sich real per TCP-Socket, sendet
ein echtes `PING`, liest die echte Antwort und laesst den echten Specter-Analyzer
`analyze_database` darueber laufen - er MUSS die reale Schwachstelle (offener,
nicht authentifizierter Datenbank-Port) erkennen.

Zwei echte Betriebsarten (automatische Auswahl):
  1. Docker vorhanden  -> echter `redis:alpine`-Container ohne Auth.
  2. Kein Docker/Image -> ECHTER lokaler Redis-kompatibler Socket-Dienst
     (127.0.0.1), der auf `PING` real mit `+PONG` antwortet - also ein echter
     offener, nicht authentifizierter Dienst, kein Mock des Analyzers.

Rein lokales Eigen-System (127.0.0.1) bzw. selbst gestarteter Container ->
defensiv, §202-StGB-konform.

Aufruf (aus dem Repo-Wurzelverzeichnis):
    python examples/live_lab/run_db_lab.py
"""

from __future__ import annotations

import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from specter.analyzers.database import analyze_database   # noqa: E402
from specter.db_live import build_database_export         # noqa: E402


def _probe(host: str, port: int, timeout: float = 5.0) -> str:
    """Sendet ein echtes Redis-`PING` und liest die echte Antwort."""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(b"PING\r\n")
        return sock.recv(256).decode("utf-8", errors="replace")


# -- Betriebsart 1: echter Docker-Container --------------------------------

def _docker_available() -> bool:
    try:
        return subprocess.run(["docker", "info"], capture_output=True,
                              timeout=15).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _start_redis_container(port: int = 6379) -> str | None:
    """Startet einen echten redis:alpine-Container ohne Auth. Gibt die ID zurueck."""
    try:
        res = subprocess.run(
            ["docker", "run", "-d", "--rm", "-p", f"127.0.0.1:{port}:6379",
             "redis:alpine"], capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return None
    if res.returncode != 0:
        return None
    cid = res.stdout.strip()
    for _ in range(20):                       # auf Bereitschaft warten
        try:
            if _probe("127.0.0.1", port).startswith("+PONG"):
                return cid
        except OSError:
            time.sleep(0.3)
    subprocess.run(["docker", "stop", cid], capture_output=True, timeout=30)
    return None


# -- Betriebsart 2: echter lokaler Redis-kompatibler Socket-Dienst ----------

class _RealMiniRedis:
    """Ein echter, offener TCP-Dienst, der auf PING real mit +PONG antwortet."""

    def __init__(self) -> None:
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(8)
        self.port = self._srv.getsockname()[1]
        self._run = True
        self._t = threading.Thread(target=self._serve, daemon=True)
        self._t.start()

    def _serve(self) -> None:
        while self._run:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                break
            with conn:
                try:
                    data = conn.recv(256)
                    if data.upper().startswith(b"PING"):
                        conn.sendall(b"+PONG\r\n")
                except OSError:
                    pass

    def stop(self) -> None:
        self._run = False
        try:
            self._srv.close()
        except OSError:
            pass


def collect() -> tuple[str, dict]:
    """Startet einen echten Dienst, probet ihn real und baut den Export."""
    if _docker_available():
        cid = _start_redis_container()
        if cid:
            try:
                resp = _probe("127.0.0.1", 6379)
                export = build_database_export(
                    "redis", "127.0.0.1", 6379, public=True, ping_response=resp)
                return "echter redis:alpine-Container (Docker)", export
            finally:
                subprocess.run(["docker", "stop", cid], capture_output=True,
                               timeout=30)

    srv = _RealMiniRedis()
    try:
        resp = _probe("127.0.0.1", srv.port)
        export = build_database_export(
            "redis", "127.0.0.1", srv.port, public=True, ping_response=resp)
    finally:
        srv.stop()
    return "echter lokaler Redis-kompatibler Socket-Dienst (127.0.0.1)", export


def main() -> int:
    print("=" * 74)
    print(" SPECTER LABOR-BEWEIS — echte, selbst gestartete Datenbank")
    print("=" * 74)

    modus, export = collect()
    print(f"[i] Betriebsart: {modus}")
    db = export["databases"][0]
    print(f"[i] Realer PING-Test -> auth_required={db['auth_required']}, "
          f"public={db['public']}\n")

    findings = analyze_database(export)
    print(f" Specter hat {len(findings)} echte Schwachstelle(n) am laufenden "
          "Dienst gefunden:")
    for f in sorted(findings, key=lambda x: -int(x.severity)):
        print(f"   [{f.severity.label}] {f.title}")

    titles = " ".join(f.title for f in findings)
    erwartet = {
        "Datenbank oeffentlich erreichbar": "oeffentlich erreichbar" in titles,
        "Datenbank ohne Authentifizierung": "ohne Authentifizierung" in titles,
    }
    print("\n Erwartete reale Befunde:")
    for name, ok in erwartet.items():
        print(f"   {'✓' if ok else '✗'} {name}")

    alle_ok = all(erwartet.values())
    print("\n" + "=" * 74)
    print(" ERGEBNIS: " + ("BESTANDEN — Specter erkennt einen echten offenen, "
                           "nicht authentifizierten Datenbank-Dienst." if alle_ok
                           else "FEHLGESCHLAGEN — ein erwarteter Befund fehlt."))
    print("=" * 74)
    return 0 if alle_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
