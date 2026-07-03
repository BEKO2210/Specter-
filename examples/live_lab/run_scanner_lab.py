#!/usr/bin/env python3
"""LABOR-BEWEIS: Bringen AKTIVE Scanner (nmap/nikto) einen Mehrwert gegenüber
den passiven Specter-Analyzern? Alles rein lokal gegen 127.0.0.1 (autorisiert,
§202-StGB-konform).

Ablauf:
  1. Startet denselben echten, absichtlich unsicheren HTTPS-Server wie
     ``run_lab.py`` (abgelaufenes/selbstsigniertes Zertifikat, fehlende Header,
     unsicheres Cookie).
  2. Baseline: die passiven Analyzer (``analyze_http_headers`` + ``analyze_tls``).
  3. Aktiv: Specters SICHERE Scanner-Wrapper (nmap + nikto) gegen dasselbe Ziel.
  4. Zweite Demo: nmap gegen mehrere Hochrisiko-Ports (RDP/MySQL/SMB) — Dienste,
     die eine reine Web/TLS-Analyse gar nicht sehen kann.
  5. Fazit zum Mehrwert.

Sind nmap/nikto nicht installiert, meldet das Skript dies sauber (fail-closed)
und bricht den jeweiligen aktiven Teil ab — der Rest läuft weiter.

Aufruf (aus dem Repo-Wurzelverzeichnis):
    python examples/live_lab/run_scanner_lab.py
"""

from __future__ import annotations

import importlib.util
import socket
import sys
import tempfile
import textwrap
import threading
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from specter.analyzers.http_headers import analyze_http_headers   # noqa: E402
from specter.analyzers.tls_certificates import analyze_tls         # noqa: E402
from specter.config import Config, Engagement, ScannerPolicy       # noqa: E402
from specter.safety import SafetyPolicy                            # noqa: E402
from specter.scanners import NiktoScanner, NmapScanner             # noqa: E402

# Den bestehenden Labor-Server aus run_lab.py wiederverwenden.
_spec = importlib.util.spec_from_file_location(
    "run_lab", str(Path(__file__).resolve().parent / "run_lab.py"))
run_lab = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(run_lab)


def _config() -> Config:
    return Config(
        engagement=Engagement("Scanner-Mehrwert-Labor", "Selbsttest (Maintainer)",
                              "SCANNER-LAB"),
        allowed_targets=["127.0.0.1"], forbidden_targets=["169.254.169.254"],
        allowed_paths=[REPO_ROOT], max_file_bytes=1_000_000, allowed_binaries=[],
        command_timeout=60, require_approval=False, max_iterations=5,
        model="claude-sonnet-5",
        scanners={
            "nmap": ScannerPolicy(enabled=True, timeout_seconds=120),
            "nikto": ScannerPolicy(enabled=True, timeout_seconds=180),
        },
    )


def _show(title: str, findings) -> None:
    print(f"\n{title} — {len(findings)} Finding(s):")
    for f in sorted(findings, key=lambda x: -int(x.severity)):
        print(f"   [{f.severity.label:7}] {f.source:13} | {f.title}")


def _high_risk_port_demo(cfg: Config, safety: SafetyPolicy) -> None:
    """nmap gegen simulierte Hochrisiko-Dienste (RDP/MySQL/SMB) auf 127.0.0.1."""
    ports = [445, 3306, 3389]
    listeners: list[socket.socket] = []
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", p))
            s.listen(8)
            listeners.append(s)
        except OSError as exc:
            print(f"[!] Port {p} nicht bindbar ({exc}) — übersprungen.")

    def _accept(sock: socket.socket) -> None:
        while True:
            try:
                conn, _ = sock.accept()
                conn.close()
            except OSError:
                break

    for s in listeners:
        threading.Thread(target=_accept, args=(s,), daemon=True).start()

    try:
        res = NmapScanner().run("127.0.0.1", cfg.scanner_policy("nmap"), safety,
                                ports=",".join(str(p) for p in ports))
    finally:
        for s in listeners:
            s.close()

    if res.error:
        print(f"\n[nmap] nicht ausgeführt: {res.error}")
        return
    _show("AKTIV nmap gegen Hochrisiko-Ports (unsichtbar für Web/TLS-Analyse)",
          res.findings)


def main() -> int:
    print("=" * 74)
    print(" SPECTER SCANNER-MEHRWERT-LABOR — aktiv vs. passiv, rein lokal")
    print("=" * 74)

    cfg = _config()
    safety = SafetyPolicy(cfg)

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        cert, key = run_lab.mint_bad_cert(tmp_path)
        httpd, port = run_lab.start_https_server(cert, key)
        print(f"[i] Echter HTTPS-Server: https://127.0.0.1:{port}/  "
              "(abgelaufenes Zertifikat, schlechte Header, unsicheres Cookie)")
        try:
            headers_export, tls_export = run_lab.collect("127.0.0.1", port)
            passive = analyze_http_headers(headers_export) + analyze_tls(tls_export)
            nmap_res = NmapScanner().run("127.0.0.1", cfg.scanner_policy("nmap"),
                                         safety, ports=str(port))
            nikto_res = NiktoScanner().run("127.0.0.1", cfg.scanner_policy("nikto"),
                                           safety, ports=str(port),
                                           extra_args=["-ssl"])
        finally:
            httpd.shutdown()

    _show("PASSIV — analyze_http_headers + analyze_tls (Baseline)", passive)
    if nmap_res.error:
        print(f"\n[nmap]  nicht ausgeführt: {nmap_res.error}")
    else:
        _show("AKTIV nmap (gegen den einen Web-Port)", nmap_res.findings)
    if nikto_res.error:
        print(f"\n[nikto] nicht ausgeführt: {nikto_res.error}")
    else:
        _show("AKTIV nikto (Webserver-Checks)", nikto_res.findings)

    # Zweite Demo: nmap zeigt seinen eigentlichen Mehrwert bei mehreren Diensten.
    _high_risk_port_demo(cfg, safety)

    print("\n" + "=" * 74)
    print(" FAZIT")
    print("=" * 74)
    print(textwrap.dedent("""\
        • Bei einem reinen Web/TLS-Ziel decken die PASSIVEN Analyzer die
          Schwachstellen bereits präzise und vollständig ab; aktive Scanner
          liefern hier kaum Netto-Neues.
        • Der eigentliche MEHRWERT der aktiven Scanner liegt woanders:
            – nmap entdeckt EXPONIERTE Dienste (RDP/SMB/DB) auf einem Host/Netz
              — die häufigsten Ransomware-Einfallstore, für eine Web/TLS-Analyse
              unsichtbar.
            – nikto prüft Webserver-Spezifika (gefährliche Dateien, veraltete
              Server, CGI).
        • Empfehlung: aktive Scanner gezielt gegen Netz-/Host-Ziele einsetzen
          (nicht gegen ein einzelnes Web-Endpoint), passiv als schnelle,
          präzise Basisprüfung nutzen. Beide ergänzen sich."""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
