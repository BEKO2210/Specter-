"""Integrationstest: echtes run_command (curl) gegen einen lokalen Testserver.

Beweist, dass die aktive Prüfung mit realem Subprozess und echtem Netzzugriff
(auf 127.0.0.1) funktioniert - nicht nur gemockt.
"""

from __future__ import annotations

import http.server
import shutil
import socketserver
import threading

import pytest

from specter.audit import AuditLog
from specter.safety import SafetyPolicy
from specter.tools.run_command import RunCommandTool

PAGE = b"<html><body><h1>Testserver</h1><!-- admin/admin123 --></body></html>"


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(PAGE)

    def log_message(self, *_a):
        pass


@pytest.fixture
def server():
    httpd = socketserver.TCPServer(("127.0.0.1", 0), _Handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield port
    httpd.shutdown()


@pytest.mark.skipif(shutil.which("curl") is None, reason="curl nicht installiert")
def test_run_command_curl_against_local_server(server, config, tmp_path):
    audit = AuditLog(tmp_path / "audit")
    tool = RunCommandTool(config, SafetyPolicy(config), audit)
    r = tool.run({"command": f"curl -s http://127.0.0.1:{server}/",
                  "rationale": "Testserver abrufen"})
    assert not r.is_error
    assert "Exit-Code: 0" in r.content
    assert "Testserver" in r.content
    assert "admin123" in r.content       # Inhalt real vom Server geladen


@pytest.mark.skipif(shutil.which("curl") is None, reason="curl nicht installiert")
def test_run_command_curl_out_of_scope_denied(server, config, tmp_path):
    # Selbes curl, aber gegen ein nicht freigegebenes Ziel -> verweigert.
    audit = AuditLog(tmp_path / "audit")
    tool = RunCommandTool(config, SafetyPolicy(config), audit)
    r = tool.run({"command": "curl -s http://8.8.8.8/"})
    assert r.is_error and "VERWEIGERT" in r.content
