#!/usr/bin/env python3
"""End-to-End-Demo OHNE API-Key: beweist, dass die Specter-Pipeline real laeuft.

Startet einen lokalen Test-Webserver (127.0.0.1) und fuehrt die echten
Werkzeuge in der Esprit-Reihenfolge aus:
  Recon -> Scan (White-Box) -> aktiver Check (curl) -> Findings ->
  Angriffspfad-Korrelation -> Bericht.

So aufrufen (aus dem Repo-Wurzelverzeichnis):
    python examples/run_demo.py

Fuer den VOLL AUTONOMEN Lauf mit KI stattdessen:
    export ANTHROPIC_API_KEY=sk-ant-...
    python main.py --scope examples/demo_scope.yaml \\
        --objective "Pruefe die App in examples/vulnerable_app und 127.0.0.1."
"""

from __future__ import annotations

import http.server
import socketserver
import threading
from pathlib import Path

# Repo-Wurzel in den Importpfad aufnehmen.
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from specter.audit import AuditLog                       # noqa: E402
from specter.config import Config                        # noqa: E402
from specter.safety import SafetyPolicy                  # noqa: E402
from specter.state import EngagementState                # noqa: E402
from specter.tools.base import build_registry            # noqa: E402

VULN_LOGIN_PAGE = b"""<!doctype html>
<html><head><title>Login</title></head>
<body>
  <h1>Mitarbeiter-Portal</h1>
  <!-- DEMO-Schwachstelle: Kommentar mit Zugangsdaten -->
  <!-- default admin / admin123 -->
  <form method="POST" action="/login">
    <input name="user"><input name="pass" type="password">
    <button>Anmelden</button>
  </form>
</body></html>
"""


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        # DEMO-Schwachstelle: Server-Banner verraet Version.
        self.send_header("Server", "DemoServer/0.1 (Test)")
        self.end_headers()
        self.wfile.write(VULN_LOGIN_PAGE)

    def log_message(self, *_a):  # Ruhe im Terminal
        pass


def _start_server() -> tuple[socketserver.TCPServer, int]:
    httpd = socketserver.TCPServer(("127.0.0.1", 0), _Handler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, port


def main() -> int:
    print("=" * 70)
    print(" Specter - End-to-End-Demo (localhost, ohne API-Key)")
    print("=" * 70)

    httpd, port = _start_server()
    base = f"http://127.0.0.1:{port}/"
    print(f"[i] Lokaler Test-Webserver laeuft: {base}")

    config = Config.load(REPO_ROOT / "examples" / "demo_scope.yaml")
    audit = AuditLog(REPO_ROOT / "audit")
    state = EngagementState()
    policy = SafetyPolicy(config)
    tools = build_registry(config, policy, audit, state)

    app_dir = str(REPO_ROOT / "examples" / "vulnerable_app")

    print("\n--- Phase 1: RECON (Asset-Graph) ---")
    print(tools["register_asset"].run(
        {"type": "code", "name": "examples/vulnerable_app", "note": "Ziel-Codebasis"}
    ).content)
    print(tools["register_asset"].run(
        {"type": "host", "name": "127.0.0.1", "note": "Test-Webserver",
         "relation": "betreibt", "related_to": "code:examples/vulnerable_app"}
    ).content)
    print(tools["register_asset"].run(
        {"type": "endpoint", "name": base}
    ).content)

    print("\n--- Phase 2: SCAN (White-Box, erfasst Findings automatisch) ---")
    print(tools["scan_code"].run({"path": app_dir}).content)

    print("\n--- Phase 3: AKTIVER CHECK (echtes curl gegen den Testserver) ---")
    curl = tools["run_command"].run(
        {"command": f"curl -s -i {base}", "rationale": "HTTP-Antwort/Header pruefen"}
    )
    print(curl.content[:400] + (" ..." if len(curl.content) > 400 else ""))
    # Aus der Antwort ein Finding ableiten (Zugangsdaten im HTML-Kommentar).
    if "admin123" in curl.content:
        print(tools["record_finding"].run({
            "title": "Zugangsdaten im HTML-Kommentar sichtbar",
            "category": "secret_exposure", "severity": "hoch",
            "asset": base, "location": f"{base} (HTML-Kommentar)",
            "evidence": "<!-- default admin / admin123 -->", "cwe": "CWE-615",
            "owner": "Web-Team",
        }).content)

    print("\n--- Phase 3b: exponierten Dienst als Finding erfassen ---")
    print(tools["record_finding"].run({
        "title": "HTTP-Dienst ohne Authentifizierung exponiert",
        "category": "exposed_service", "severity": "hoch",
        "asset": "127.0.0.1", "location": f"127.0.0.1:{port}",
        "evidence": "GET / -> 200, Server: DemoServer/0.1", "owner": "Infrastruktur",
    }).content)

    print("\n--- Phase 3c: WINDOWS-/CLOUD-OFFLINE-ANALYSE (AD, Exchange, Entra-ID/M365, AWS, Azure) ---")
    data_dir = REPO_ROOT / "examples" / "data"
    print(tools["analyze_ad"].run(
        {"path": str(data_dir / "ad_export.example.json")}).content)
    print(tools["analyze_exchange"].run(
        {"path": str(data_dir / "exchange.example.json")}).content)
    print(tools["analyze_entra"].run(
        {"path": str(data_dir / "entra_export.example.json")}).content)
    print(tools["analyze_aws"].run(
        {"path": str(data_dir / "aws_export.example.json")}).content)
    print(tools["analyze_azure"].run(
        {"path": str(data_dir / "azure_export.example.json")}).content)
    print(tools["analyze_email_security"].run(
        {"path": str(data_dir / "email_security.example.json")}).content)
    print(tools["analyze_dns"].run(
        {"path": str(data_dir / "dns.example.json")}).content)
    print(tools["analyze_database"].run(
        {"path": str(data_dir / "database.example.json")}).content)
    print(tools["analyze_dependencies"].run(
        {"path": str(data_dir / "dependencies.example.json")}).content)
    print(tools["analyze_firewall"].run(
        {"path": str(data_dir / "firewall.example.json")}).content)
    print(tools["analyze_tls"].run(
        {"path": str(data_dir / "tls.example.json")}).content)
    print(tools["analyze_backup"].run(
        {"path": str(data_dir / "backup.example.json")}).content)
    print(tools["analyze_http_headers"].run(
        {"path": str(data_dir / "http_headers.example.json")}).content)

    print("\n--- Phase 4: ANGRIFFSPFAD-KORRELATION ---")
    print(tools["correlate_paths"].run({}).content)

    print("\n--- Phase 5: BERICHT + FIX-VORSCHLAEGE ---")
    print(tools["generate_report"].run({"include_pr_drafts": False}).content)

    counts = state.findings.counts()
    print("\n" + "=" * 70)
    print(f" Ergebnis: {len(state.assets)} Assets · {len(state.findings)} Findings "
          f"(Kritisch {counts['Kritisch']}, Hoch {counts['Hoch']}, "
          f"Mittel {counts['Mittel']}) · {len(state.attack_paths)} Angriffspfade")
    print("=" * 70)

    httpd.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
