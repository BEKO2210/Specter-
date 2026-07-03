"""Tool: TLS-/Zertifikats-Export offline analysieren."""

from __future__ import annotations

from ..analyzers import analyze_tls
from .base import FileAnalysisTool


class AnalyzeTlsTool(FileAnalysisTool):
    name = "analyze_tls"
    label = "TLS-/Zertifikatsanalyse"
    description = (
        "Analysiert einen bereitgestellten TLS-/Zertifikats-Export (JSON) rein "
        "defensiv und erfasst Transport-/Krypto-Risiken als Findings: abgelaufene "
        "oder bald ablaufende Zertifikate, schwache Signatur (SHA-1/MD5), zu "
        "kurze Schlüssel, selbstsignierte Zertifikate, veraltete Protokolle "
        "(SSLv3/TLS 1.0/1.1) und schwache Cipher-Suites. Kein Live-Handshake, "
        "keine Ausnutzung - nur die lokale Datei im Scope."
    )
    analyzer = staticmethod(analyze_tls)
