"""Tool: HTTP-Security-Header-/Cookie-Export offline analysieren."""

from __future__ import annotations

from ..analyzers import analyze_http_headers
from .base import FileAnalysisTool


class AnalyzeHttpHeadersTool(FileAnalysisTool):
    name = "analyze_http_headers"
    label = "HTTP-Header-Analyse"
    description = (
        "Analysiert einen bereitgestellten Export der HTTP-Antwort-Header (und "
        "optional Cookies) rein defensiv und erfasst Web-Sicherheits-lücken als "
        "Findings: fehlendes/kurzes HSTS, fehlende CSP, fehlendes "
        "X-Frame-Options, X-Content-Type-Options, Referrer-/Permissions-Policy, "
        "verraterische Server-/X-Powered-By-Banner sowie Cookies ohne "
        "Secure/HttpOnly/SameSite. Keine Live-Abfrage - nur die lokale Datei im "
        "Scope."
    )
    analyzer = staticmethod(analyze_http_headers)
