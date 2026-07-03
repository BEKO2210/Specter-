"""Defensive Backup-/Ransomware-Resilienzanalyse aus bereitgestellten Angaben.

Wertet einen lokalen JSON-Export der Datensicherungs-Posture aus (Anzahl Kopien,
Offsite, Offline/Immutable, Verschlüsselung, Restore-Test, MFA auf der
Backup-Konsole, Aufbewahrung) und leitet typische Resilienz-Lücken ab - ohne
jede Live-Verbindung zum Backup-System, ohne Ausnutzung.

Für Cyber-Versicherer ist das DER zentrale Prüfpunkt: Ob ein Unternehmen einen
Ransomware-Vorfall überlebt, hängt an unveränderbaren (immutable/offline)
Backups und regelmäßig getesteten Wiederherstellungen. Grundlage ist die
3-2-1-Regel (3 Kopien, 2 Medien, 1 Kopie offsite).

Erwartete Struktur (alle Felder optional):

    {
      "organization": "Muster GmbH",
      "backups": [
        {"name": "fileserver", "copies": 1, "offsite": false,
         "offline_or_immutable": false, "encrypted": false,
         "restore_tested": false, "last_restore_test_days": 400,
         "mfa_on_console": false, "retention_days": 7}
      ],
      "policy": {"documented": false}
    }
"""

from __future__ import annotations

from typing import Any

from ..findings import Finding, Severity
from ._util import as_bool, as_int, as_list

MIN_COPIES = 3            # 3-2-1-Regel: mindestens 3 Kopien
MIN_RETENTION_DAYS = 30   # unter der typischen Angreifer-Verweildauer riskant
MAX_RESTORE_TEST_AGE = 365  # Restore mindestens jährlich testen


def _mk(title, category, severity, asset, evidence, *, location="", cwe="",
        owner="IT-/Backup-Team") -> Finding:
    return Finding(
        title=title, category=category, severity=severity, asset=asset,
        location=location or asset, evidence=evidence, cwe=cwe, owner=owner,
        source="backup_analyzer", status="offen",
    )


def _analyze_backup(b: dict[str, Any], org: str) -> list[Finding]:
    out: list[Finding] = []
    name = str(b.get("name", "Backup"))
    loc = f"{org}/backup/{name}"

    copies = as_int(b.get("copies"))
    if copies is not None and copies < 2:
        out.append(_mk(
            f"Höchstens eine Backup-Kopie (Single Point of Failure): {name}",
            "backup_resilience", Severity.HOCH, loc,
            f"copies={copies} - 3-2-1-Regel verlangt mindestens {MIN_COPIES} Kopien",
            location=loc, cwe="CWE-693",
        ))
    elif copies is not None and copies < MIN_COPIES:
        out.append(_mk(
            f"Zu wenige Backup-Kopien für die 3-2-1-Regel: {name}",
            "backup_resilience", Severity.MITTEL, loc,
            f"copies={copies} - empfohlen sind mindestens {MIN_COPIES}",
            location=loc, cwe="CWE-693",
        ))

    if as_bool(b.get("offline_or_immutable")) is False:
        out.append(_mk(
            f"Kein offline-/unveränderbares (Immutable) Backup: {name}",
            "backup_resilience", Severity.HOCH, loc,
            "offline_or_immutable=false - Ransomware kann erreichbare Backups "
            "mitverschlüsseln/löschen", location=loc, cwe="CWE-693",
        ))

    if as_bool(b.get("offsite")) is False:
        out.append(_mk(
            f"Keine Offsite-Kopie des Backups: {name}", "backup_resilience",
            Severity.HOCH, loc, "offsite=false - kein Schutz gegen Standort-"
            "Totalverlust (Brand/Ransomware im LAN)", location=loc, cwe="CWE-693",
        ))

    if as_bool(b.get("restore_tested")) is False:
        out.append(_mk(
            f"Wiederherstellung nie getestet: {name}", "backup_resilience",
            Severity.HOCH, loc, "restore_tested=false - ungetestete Backups "
            "sind im Ernstfall oft nicht wiederherstellbar", location=loc, cwe="CWE-754",
        ))
    else:
        age = as_int(b.get("last_restore_test_days"))
        if age is not None and age > MAX_RESTORE_TEST_AGE:
            out.append(_mk(
                f"Restore-Test überfällig ({age} Tage): {name}",
                "backup_resilience", Severity.HOCH, loc,
                f"last_restore_test_days={age} - mindestens jährlich testen",
                location=loc, cwe="CWE-754",
            ))

    if as_bool(b.get("mfa_on_console")) is False:
        out.append(_mk(
            f"Backup-Konsole ohne MFA: {name}", "backup_resilience",
            Severity.MITTEL, loc, "mfa_on_console=false - Angreifer können "
            "Backups aus der Konsole löschen", location=loc, cwe="CWE-308",
        ))

    if as_bool(b.get("encrypted")) is False:
        out.append(_mk(
            f"Backup nicht verschlüsselt: {name}", "backup_resilience",
            Severity.MITTEL, loc, "encrypted=false - Datenabfluss aus Backups "
            "(DSGVO-relevant)", location=loc, cwe="CWE-311",
        ))

    retention = as_int(b.get("retention_days"))
    if retention is not None and retention < MIN_RETENTION_DAYS:
        out.append(_mk(
            f"Zu kurze Backup-Aufbewahrung ({retention} Tage): {name}",
            "backup_resilience", Severity.MITTEL, loc,
            f"retention_days={retention} - unter {MIN_RETENTION_DAYS} Tagen kann "
            "eine spät entdeckte Kompromittierung alle Kopien betreffen",
            location=loc, cwe="CWE-693",
        ))
    return out


def analyze_backup(data: dict[str, Any]) -> list[Finding]:
    """Führt alle Backup-/Resilienzprüfungen aus und liefert die Findings."""
    if not isinstance(data, dict):
        return []
    org = str(data.get("organization", "Organisation"))
    findings: list[Finding] = []
    for b in as_list(data.get("backups")):
        if isinstance(b, dict):
            findings += _analyze_backup(b, org)
    policy = data.get("policy")
    if isinstance(policy, dict) and as_bool(policy.get("documented")) is False:
        findings.append(_mk(
            "Kein dokumentiertes Backup-/Wiederanlaufkonzept",
            "backup_resilience", Severity.NIEDRIG, f"{org}/policy",
            "policy.documented=false - ohne dokumentiertes Konzept fehlt im "
            "Ernstfall die Handlungssicherheit", location=f"{org}/policy", cwe="CWE-1053",
        ))
    return findings
