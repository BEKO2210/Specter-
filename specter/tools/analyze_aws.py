"""Tool: AWS-Export offline analysieren."""

from __future__ import annotations

from typing import Any

from ..analyzers import analyze_aws
from ..aws_raw import coerce_aws_export
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
        "auf sensiblen Ports. Akzeptiert sowohl ein Bündel echter "
        "AWS-CLI-Antworten (get-account-summary, describe-security-groups, "
        "get-bucket-policy-status ...) als auch den normalisierten Export. "
        "Keine Live-Verbindung zum Konto - nur die lokale Datei im Scope."
    )
    analyzer = staticmethod(analyze_aws)

    def _coerce(self, data: Any) -> Any:
        return coerce_aws_export(data)
