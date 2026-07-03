"""Tool: E-Mail-Security-Export (SPF/DKIM/DMARC) offline analysieren."""

from __future__ import annotations

from ..analyzers import analyze_email_security
from .base import FileAnalysisTool


class AnalyzeEmailSecurityTool(FileAnalysisTool):
    name = "analyze_email_security"
    label = "E-Mail-Security-Analyse"
    description = (
        "Analysiert einen bereitgestellten DNS-Export (JSON) zur "
        "E-Mail-Sicherheit einer Domain rein defensiv und erfasst "
        "Spoofing-/Phishing-Risiken als Findings: fehlendes oder weiches SPF "
        "(+all/?all), fehlendes DKIM oder zu schwacher DKIM-Schlüssel, fehlendes "
        "DMARC oder nur p=none, fehlende rua-Reportadresse. Keine "
        "Live-DNS-Abfrage, kein Mailversand - nur die lokale Datei im Scope."
    )
    analyzer = staticmethod(analyze_email_security)
