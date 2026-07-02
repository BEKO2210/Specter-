#!/usr/bin/env python3
"""LABOR-BEWEIS: Specter gegen ECHTE, selbst gestartete Server.

Kein Test-Projekt, sondern echte Software: Dieses Skript
  1. mintet mit `cryptography` ein echtes, ABGELAUFENES und mit ZU KURZEM
     Schlüssel (1024 bit) selbstsigniertes TLS-Zertifikat,
  2. startet damit einen echten Python-`ssl`-HTTPS-Server auf 127.0.0.1 mit
     absichtlich FEHLENDEN Sicherheits-Headern, LEAKENDEM Server-Banner und
     einem UNSICHEREN Cookie (ohne Secure/HttpOnly/SameSite),
  3. greift den laufenden Server real ab (curl + openssl s_client/x509),
  4. lässt die echten Specter-Analyzer (`analyze_http_headers`, `analyze_tls`)
     darüber laufen und PRÜFT, dass die realen Schwachstellen gefunden werden,
  5. räumt alles wieder ab.

Rein lokales Eigen-System (127.0.0.1) → defensiv, §202-StGB-konform.

Aufruf (aus dem Repo-Wurzelverzeichnis):
    python examples/live_lab/run_lab.py
"""

from __future__ import annotations

import datetime as _dt
import http.server
import ssl
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from cryptography import x509                                   # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa       # noqa: E402
from cryptography.x509.oid import NameOID                       # noqa: E402

from specter.analyzers.http_headers import analyze_http_headers  # noqa: E402
from specter.analyzers.tls_certificates import analyze_tls        # noqa: E402
from specter.web_live import build_headers_export, build_tls_export  # noqa: E402


def _run(argv: list[str], stdin: str = "") -> str:
    return subprocess.run(argv, input=stdin, capture_output=True, text=True,
                          timeout=20).stdout


def mint_bad_cert(directory: Path) -> tuple[Path, Path]:
    """Echtes, abgelaufenes, selbstsigniertes Zertifikat erzeugen.

    2048-bit/SHA256, damit es der TLS-Handshake der Umgebung (OpenSSL-
    Security-Level 2) real ausliefert; die Schwachstellen liegen in Ablauf und
    Selbstsignierung. Schwache Schlüssel/Cipher/Signaturen deckt der Offline-
    TLS-Analyzer (mit Unit-Tests + echten Domain-Checks) ab - sie sind hier nicht
    live servierbar, weil moderne OpenSSL-Bibliotheken sie im Handshake blocken.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "lab-expired.local")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_dt.datetime(2019, 1, 1))
        .not_valid_after(_dt.datetime(2020, 1, 1))       # ABGELAUFEN
        .sign(key, hashes.SHA256())
    )
    key_path = directory / "lab.key"
    cert_path = directory / "lab.crt"
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


class _BadHandler(http.server.BaseHTTPRequestHandler):
    """Absichtlich unsicher: leakendes Banner, fehlende Header, offenes Cookie."""

    server_version = "LabServer/1.0"
    sys_version = "(PHP/7.2.1)"

    def do_HEAD(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Set-Cookie", "SESSIONID=deadbeef; Path=/")  # keine Flags
        # bewusst KEIN HSTS/CSP/X-Frame-Options/... gesetzt
        self.end_headers()

    do_GET = do_HEAD

    def log_message(self, *args):  # Ruhe im Terminal
        pass


def start_https_server(cert: Path, key: Path) -> tuple[http.server.HTTPServer, int]:
    httpd = http.server.HTTPServer(("127.0.0.1", 0), _BadHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, port


def collect(host: str, port: int) -> tuple[dict, dict]:
    base = f"https://{host}:{port}/"
    raw_headers = _run(["curl", "-sSI", "--max-time", "10", "-k", base])
    headers_export = build_headers_export(base, raw_headers)

    connect = f"{host}:{port}"
    s_client = _run(["openssl", "s_client", "-connect", connect], stdin="Q\n")
    x509_text = ""
    if "BEGIN CERTIFICATE" in s_client:
        start = s_client.index("-----BEGIN CERTIFICATE-----")
        end = s_client.index("-----END CERTIFICATE-----") + len("-----END CERTIFICATE-----")
        cert_pem = s_client[start:end] + "\n"
        x509_text = _run(["openssl", "x509", "-noout", "-text", "-enddate",
                          "-subject", "-issuer"], stdin=cert_pem)
    today = _dt.date.today().strftime("%Y-%m-%d")
    return headers_export, build_tls_export(connect, s_client, x509_text, today)


def main() -> int:
    print("=" * 74)
    print(" SPECTER LABOR-BEWEIS — echte, selbst gestartete Server")
    print("=" * 74)

    with tempfile.TemporaryDirectory() as tmp:
        cert, key = mint_bad_cert(Path(tmp))
        httpd, port = start_https_server(cert, key)
        print(f"[i] Echter HTTPS-Server läuft: https://127.0.0.1:{port}/")
        print("[i] (abgelaufenes, selbstsigniertes Zertifikat, "
              "schlechte Header, unsicheres Cookie)\n")
        try:
            headers_export, tls_export = collect("127.0.0.1", port)
        finally:
            httpd.shutdown()

    findings = analyze_http_headers(headers_export) + analyze_tls(tls_export)
    titles = " ".join(f.title for f in findings)

    print(f" Specter hat {len(findings)} echte Schwachstelle(n) am laufenden Server gefunden:")
    for f in sorted(findings, key=lambda x: -int(x.severity)):
        print(f"   [{f.severity.label}] {f.title}")

    # Nachweis: die erwarteten realen Funde müssen dabei sein.
    erwartet = {
        "TLS-Zertifikat abgelaufen": "abgelaufen" in titles,
        "Selbstsigniertes Zertifikat": "Selbstsigniert" in titles,
        "Kein HSTS": "Kein HSTS" in titles,
        "Keine CSP": "Content-Security-Policy" in titles,
        "Clickjacking-Schutz fehlt": "Clickjacking" in titles,
        "Server-Banner-Leak": "Server-Banner" in titles,
        "Unsicheres Cookie (ohne Secure)": "Cookie ohne Secure-Flag" in titles,
    }
    print("\n Erwartete reale Befunde:")
    for name, ok in erwartet.items():
        print(f"   {'✓' if ok else '✗'} {name}")

    alle_ok = all(erwartet.values())
    print("\n" + "=" * 74)
    print(" ERGEBNIS: " + ("BESTANDEN — Specter erkennt echte Schwachstellen an "
                           "einem echten Server." if alle_ok else
                           "FEHLGESCHLAGEN — ein erwarteter Befund fehlt."))
    print("=" * 74)
    return 0 if alle_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
