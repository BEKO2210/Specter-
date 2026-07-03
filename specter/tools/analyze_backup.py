"""Tool: Backup-/Ransomware-Resilienz-Export offline analysieren."""

from __future__ import annotations

from ..analyzers import analyze_backup
from .base import FileAnalysisTool


class AnalyzeBackupTool(FileAnalysisTool):
    name = "analyze_backup"
    label = "Backup-/Resilienzanalyse"
    description = (
        "Analysiert einen bereitgestellten Backup-/Resilienz-Export (JSON) rein "
        "defensiv und erfasst Ransomware-Resilienzlücken als Findings: zu wenige "
        "Kopien (3-2-1), fehlendes offline-/Immutable-Backup, keine "
        "Offsite-Kopie, ungetestete Wiederherstellung, Backup-Konsole ohne MFA, "
        "unverschlüsselte Backups, zu kurze Aufbewahrung und fehlendes "
        "Wiederanlaufkonzept. Kein Live-Abgleich mit dem Backup-System, keine "
        "Ausnutzung - nur die lokale Datei im Scope."
    )
    analyzer = staticmethod(analyze_backup)
