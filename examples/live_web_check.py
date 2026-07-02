#!/usr/bin/env python3
"""LIVE-Web/TLS-Check gegen einen echten Server (Labor oder eigene, freigegebene Domain).

Greift die HTTP-Antwort-Header (curl) und die TLS-Konfiguration (openssl s_client
+ x509) eines echten Endpunkts ab und wertet sie mit denselben Offline-Analyzern
aus, die auch im Kundenauftrag laufen (`analyze_http_headers`, `analyze_tls`).

Nur gegen **selbst betriebene** oder **schriftlich freigegebene eigene** Systeme
einsetzen (defensiv, §202 StGB).

Aufruf (aus dem Repo-Wurzelverzeichnis):
    python examples/live_web_check.py meine-domain.de
    python examples/live_web_check.py 127.0.0.1 --port 8443
"""

from __future__ import annotations

import datetime as _dt
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from specter.analyzers.http_headers import analyze_http_headers  # noqa: E402
from specter.analyzers.tls_certificates import analyze_tls        # noqa: E402
from specter.web_live import build_headers_export, build_tls_export  # noqa: E402


def _run(argv: list[str], stdin: str = "") -> str:
    try:
        return subprocess.run(argv, input=stdin, capture_output=True, text=True,
                              timeout=20).stdout
    except (subprocess.SubprocessError, OSError):
        return ""


def collect(host: str, port: int) -> tuple[dict, dict]:
    base = f"https://{host}:{port}/" if port != 443 else f"https://{host}/"
    raw_headers = _run(["curl", "-sSI", "--max-time", "15", "-k", base])
    headers_export = build_headers_export(base, raw_headers)

    connect = f"{host}:{port}"
    s_client = _run(["openssl", "s_client", "-connect", connect, "-servername",
                     host, "-brief"], stdin="Q\n") or \
        _run(["openssl", "s_client", "-connect", connect, "-servername", host],
             stdin="Q\n")
    # Zertifikat als PEM holen und mit x509 in Textform bringen.
    pem = _run(["openssl", "s_client", "-connect", connect, "-servername", host],
               stdin="Q\n")
    x509_text = ""
    if "BEGIN CERTIFICATE" in pem:
        start = pem.index("-----BEGIN CERTIFICATE-----")
        end = pem.index("-----END CERTIFICATE-----") + len("-----END CERTIFICATE-----")
        cert_pem = pem[start:end] + "\n"
        x509_text = _run(["openssl", "x509", "-noout", "-text", "-enddate",
                          "-subject", "-issuer"], stdin=cert_pem)
    today = _dt.date.today().strftime("%Y-%m-%d")
    tls_export = build_tls_export(connect, s_client, x509_text, today)
    return headers_export, tls_export


def main() -> int:
    argv = [a for a in sys.argv[1:] if a != "--port"]
    if not argv:
        print("Aufruf: python examples/live_web_check.py <host> [--port <n>]")
        return 2
    host = argv[0]
    port = 443
    if "--port" in sys.argv:
        try:
            port = int(sys.argv[sys.argv.index("--port") + 1])
        except (ValueError, IndexError):
            port = 443

    headers_export, tls_export = collect(host, port)
    findings = analyze_http_headers(headers_export) + analyze_tls(tls_export)

    print("=" * 74)
    print(f" LIVE-Web/TLS-Check: {host}:{port}")
    print("=" * 74)
    if findings:
        print(f" {len(findings)} Befund(e):")
        for f in findings:
            print(f"   [{f.severity.label}] {f.title}")
    else:
        print(" Keine Befunde (oder Server nicht erreichbar).")
    print("=" * 74)
    print(" Hinweis: nur gegen selbst betriebene/freigegebene Systeme einsetzen.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
