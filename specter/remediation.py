"""Remediation-Vorschlaege und Draft-PR-Inhalte ("Fix & Draft PR").

Entspricht der letzten Esprit/Trident-Stufe: zu jedem Finding wird eine
konkrete Gegenmassnahme und ein fertiger Pull-Request-Text (Titel + Body auf
Deutsch) erzeugt, den der/die Verantwortliche direkt umsetzen kann.
"""

from __future__ import annotations

from .findings import Finding

# Standard-Gegenmassnahmen je Kategorie (falls das Finding keine mitbringt).
DEFAULT_REMEDIATION: dict[str, str] = {
    "secret_exposure": (
        "Secret sofort rotieren und aus dem Code entfernen. Geheimnisse ueber "
        "Umgebungsvariablen oder einen Secret-Manager (z. B. HashiCorp Vault, "
        "AWS Secrets Manager) laden. Git-Historie bereinigen (git filter-repo)."
    ),
    "injection": (
        "Parametrisierte Abfragen / Prepared Statements verwenden, Eingaben "
        "streng validieren und niemals ungeprueft in Befehle/Queries einsetzen. "
        "shell=True vermeiden; Argumentlisten statt Shell-Strings nutzen."
    ),
    "auth_weakness": (
        "Starke Passwort-/MFA-Richtlinien, sichere Session-Verwaltung und "
        "serverseitige Rechtepruefung durchsetzen. Standard-Zugangsdaten entfernen."
    ),
    "access_control": (
        "Zugriffskontrolle serverseitig pro Objekt/Ressource pruefen "
        "(Deny-by-default). Direkte Objektreferenzen (IDs) nicht ohne "
        "Berechtigungspruefung akzeptieren."
    ),
    "crypto_weakness": (
        "Schwache Algorithmen (MD5/SHA1) durch SHA-256+ bzw. fuer Passwoerter "
        "durch bcrypt/scrypt/Argon2 ersetzen. Keine Eigenbau-Kryptographie."
    ),
    "misconfiguration": (
        "Sichere Standardkonfiguration erzwingen: Debug-Modus in Produktion aus, "
        "unnoetige Dienste deaktivieren, Sicherheits-Header setzen."
    ),
    "cloud_storage": (
        "Oeffentlichen Zugriff auf Speicher/Buckets sperren, Least-Privilege-"
        "Policies setzen und Verschluesselung im Ruhezustand aktivieren."
    ),
    "transport_security": (
        "TLS-Zertifikatspruefung aktivieren (verify=True), aktuelle TLS-Version "
        "erzwingen und HSTS setzen."
    ),
    "deserialization": (
        "Keine ungepruefte Deserialisierung nicht-vertrauenswuerdiger Daten. "
        "Sichere Formate (JSON mit Schema) und yaml.safe_load verwenden."
    ),
    "exposed_service": (
        "Dienst hinter Firewall/VPN legen, auf benoetigte Quell-IPs beschraenken "
        "und nicht benoetigte Ports schliessen."
    ),
    "sensitive_data": (
        "Sensible Daten verschluesseln, Zugriff protokollieren und nach "
        "Least-Privilege einschraenken (DSGVO-Konformitaet pruefen)."
    ),
    "remote_access": (
        "Fernzugang (RDP/VPN) nie direkt ins Internet. MFA erzwingen, hinter "
        "VPN/Zero-Trust-Gateway legen, auf benoetigte Quell-IPs beschraenken, "
        "Accounts nach Fehlversuchen sperren und Zugriffe protokollieren."
    ),
    "default_credentials": (
        "Alle Standard-/Default-Zugangsdaten aendern, ungenutzte Konten "
        "deaktivieren, starke Passwort-Richtlinie und MFA durchsetzen."
    ),
    "outdated_component": (
        "Komponente auf eine unterstuetzte, gepatchte Version aktualisieren. "
        "Patch-Management und ein Software-Inventar (SBOM) etablieren; "
        "veraltete, nicht mehr benoetigte Dienste abschalten."
    ),
    "personal_data": (
        "Personenbezogene Daten nach DSGVO schuetzen: Datenminimierung, "
        "Verschluesselung, Pseudonymisierung, Zugriff nach Least-Privilege, "
        "Loeschkonzept und Verarbeitungsverzeichnis. Besondere Kategorien "
        "(Art. 9 DSGVO) gesondert schuetzen."
    ),
    "other": "Schwachstelle nach Stand der Technik beheben und erneut pruefen.",
}


def remediation_for(finding: Finding) -> str:
    if finding.remediation.strip():
        return finding.remediation.strip()
    return DEFAULT_REMEDIATION.get(finding.category, DEFAULT_REMEDIATION["other"])


def draft_pr(finding: Finding) -> dict[str, str]:
    """Erzeugt Titel und Body fuer einen Remediation-Pull-Request (Deutsch)."""
    fix = remediation_for(finding)
    cwe = f" ({finding.cwe})" if finding.cwe else ""
    title = f"fix(security): {finding.title} [{finding.severity.label}]"
    body = f"""## Sicherheits-Fix: {finding.title}

**Finding-ID:** {finding.id}
**Schweregrad:** {finding.severity.label}{cwe}
**Kategorie:** {finding.category_label}
**Betroffenes Asset:** {finding.asset}
**Fundstelle:** {finding.location or "n/a"}

### Beleg (Evidenz)
```
{finding.evidence or "(keine Evidenz erfasst)"}
```

### Empfohlene Gegenmassnahme
{fix}

### Verantwortlich
{finding.owner or "noch zuzuweisen"}

---
_Automatisch erzeugt von Specter (autorisierte Sicherheitspruefung). Bitte den
Fix pruefen, testen und die Fundstelle nach dem Merge erneut verifizieren._
"""
    return {"title": title, "body": body}
