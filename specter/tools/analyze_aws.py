"""Tool: AWS-Export offline analysieren."""

from __future__ import annotations

from ..analyzers import analyze_aws
from .base import FileAnalysisTool


class AnalyzeAwsTool(FileAnalysisTool):
    name = "analyze_aws"
    label = "AWS-Analyse"
    description = (
        "Analysiert einen bereitgestellten AWS-Export (JSON) rein defensiv und "
        "erfasst typische Cloud-Risiken als Findings: Root ohne MFA oder mit "
        "Access-Keys, schwache IAM-Passwort-Policy, überprivilegierte "
        "IAM-User/Rollen, alte/ungenutzte Access-Keys, "
        "öffentliche/unverschlüsselte S3-Buckets, Security-Groups mit 0.0.0.0/0 "
        "auf sensiblen Ports. Keine Live-Verbindung zum Konto - nur die lokale "
        "Datei im Scope."
    )
    analyzer = staticmethod(analyze_aws)
