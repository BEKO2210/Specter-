"""Remediation-Vorschläge und Draft-PR-Inhalte ("Fix & Draft PR").

Entspricht der letzten Esprit/Trident-Stufe: zu jedem Finding wird eine
konkrete Gegenmaßnahme und ein fertiger Pull-Request-Text (Titel + Body auf
Deutsch) erzeugt, den der/die Verantwortliche direkt umsetzen kann.
"""

from __future__ import annotations

from .findings import Finding

# Standard-Gegenmaßnahmen je Kategorie (falls das Finding keine mitbringt).
DEFAULT_REMEDIATION: dict[str, str] = {
    "secret_exposure": (
        "Secret sofort rotieren und aus dem Code entfernen. Geheimnisse über "
        "Umgebungsvariablen oder einen Secret-Manager (z. B. HashiCorp Vault, "
        "AWS Secrets Manager) laden. Git-Historie bereinigen (git filter-repo)."
    ),
    "injection": (
        "Parametrisierte Abfragen / Prepared Statements verwenden, Eingaben "
        "streng validieren und niemals ungeprüft in Befehle/Queries einsetzen. "
        "shell=True vermeiden; Argumentlisten statt Shell-Strings nutzen."
    ),
    "auth_weakness": (
        "Starke Passwort-/MFA-Richtlinien, sichere Session-Verwaltung und "
        "serverseitige Rechteprüfung durchsetzen. Standard-Zugangsdaten entfernen."
    ),
    "access_control": (
        "Zugriffskontrolle serverseitig pro Objekt/Ressource prüfen "
        "(Deny-by-default). Direkte Objektreferenzen (IDs) nicht ohne "
        "Berechtigungsprüfung akzeptieren."
    ),
    "crypto_weakness": (
        "Schwache Algorithmen (MD5/SHA1) durch SHA-256+ bzw. für Passwörter "
        "durch bcrypt/scrypt/Argon2 ersetzen. Keine Eigenbau-Kryptographie."
    ),
    "misconfiguration": (
        "Sichere Standardkonfiguration erzwingen: Debug-Modus in Produktion aus, "
        "unnötige Dienste deaktivieren, Sicherheits-Header setzen."
    ),
    "cloud_storage": (
        "Öffentlichen Zugriff auf Speicher/Buckets sperren, Least-Privilege-"
        "Policies setzen und Verschlüsselung im Ruhezustand aktivieren."
    ),
    "transport_security": (
        "TLS-Zertifikatsprüfung aktivieren (verify=True), aktuelle TLS-Version "
        "erzwingen und HSTS setzen."
    ),
    "deserialization": (
        "Keine ungeprüfte Deserialisierung nicht-vertrauenswürdiger Daten. "
        "Sichere Formate (JSON mit Schema) und yaml.safe_load verwenden."
    ),
    "exposed_service": (
        "Dienst hinter Firewall/VPN legen, auf benötigte Quell-IPs beschränken "
        "und nicht benötigte Ports schließen."
    ),
    "sensitive_data": (
        "Sensible Daten verschlüsseln, Zugriff protokollieren und nach "
        "Least-Privilege einschränken (DSGVO-Konformität prüfen)."
    ),
    "remote_access": (
        "Fernzugang (RDP/VPN) nie direkt ins Internet. MFA erzwingen, hinter "
        "VPN/Zero-Trust-Gateway legen, auf benötigte Quell-IPs beschränken, "
        "Accounts nach Fehlversuchen sperren und Zugriffe protokollieren."
    ),
    "default_credentials": (
        "Alle Standard-/Default-Zugangsdaten ändern, ungenutzte Konten "
        "deaktivieren, starke Passwort-Richtlinie und MFA durchsetzen."
    ),
    "outdated_component": (
        "Komponente auf eine unterstützte, gepatchte Version aktualisieren. "
        "Patch-Management und ein Software-Inventar (SBOM) etablieren; "
        "veraltete, nicht mehr benötigte Dienste abschalten."
    ),
    "personal_data": (
        "Personenbezogene Daten nach DSGVO schützen: Datenminimierung, "
        "Verschlüsselung, Pseudonymisierung, Zugriff nach Least-Privilege, "
        "Löschkonzept und Verarbeitungsverzeichnis. Besondere Kategorien "
        "(Art. 9 DSGVO) gesondert schützen."
    ),
    "email_security": (
        "E-Mail-Spoofing verhindern: SPF mit -all (bzw. mindestens ~all) setzen, "
        "DKIM mit >= 2048-Bit-Schlüssel signieren und DMARC schrittweise auf "
        "p=quarantine, dann p=reject anheben. rua-Reportadresse konfigurieren und "
        "die Berichte regelmäßig auswerten (Schutz vor CEO-Fraud/BEC)."
    ),
    "backup_resilience": (
        "3-2-1-Regel umsetzen: mindestens 3 Kopien, 2 verschiedene Medien, 1 Kopie "
        "offsite - und mindestens eine offline bzw. unveränderbar (WORM/Immutable) "
        "gegen Ransomware. Restores regelmäßig testen (mind. jährlich, besser "
        "quartalsweise), die Backup-Konsole mit MFA schützen, Aufbewahrung an die "
        "Angreifer-Verweildauer anpassen (>= 30 Tage) und Backups verschlüsseln. "
        "Wiederanlauf-/Notfallkonzept dokumentieren und üben."
    ),
    "web_security": (
        "Sicherheits-Header setzen: HSTS (max-age >= 1 Jahr, includeSubDomains), "
        "Content-Security-Policy, X-Frame-Options bzw. CSP frame-ancestors, "
        "X-Content-Type-Options: nosniff, Referrer-Policy und Permissions-Policy. "
        "Cookies mit Secure, HttpOnly und SameSite ausliefern; Server-/X-Powered-By-"
        "Banner reduzieren, damit keine Softwareversionen preisgegeben werden."
    ),
    "dns_security": (
        "DNS absichern: DNSSEC aktivieren und die Zone signieren (Schutz vor "
        "Cache-Poisoning/Spoofing), CAA-Records setzen, damit nur autorisierte "
        "Zertifizierungsstellen ausstellen dürfen, Zonentransfer (AXFR) auf "
        "berechtigte Secondaries beschränken, Wildcard-Einträge vermeiden bzw. "
        "eng fassen und ungenutzte CNAME-Verweise (dangling) entfernen, um "
        "Subdomain-Takeover zu verhindern."
    ),
    "container_security": (
        "Container härten: nicht privilegiert und als unprivilegierter Benutzer "
        "laufen (USER != root), das Docker-Socket niemals in Container mounten, "
        "Host-Networking vermeiden, nur die minimal nötigen Capabilities vergeben "
        "(--cap-drop=ALL, gezielt einzelne --cap-add), Images mit festem Tag/Digest "
        "pinnen (kein :latest) und regelmäßig aktualisieren, Ports nur auf "
        "benötigte Quell-IPs/127.0.0.1 veröffentlichen und den Docker-Daemon nicht "
        "ungeschützt exponieren."
    ),
    "other": "Schwachstelle nach Stand der Technik beheben und erneut prüfen.",
}


def remediation_for(finding: Finding) -> str:
    if finding.remediation.strip():
        return finding.remediation.strip()
    return DEFAULT_REMEDIATION.get(finding.category, DEFAULT_REMEDIATION["other"])


def draft_pr(finding: Finding) -> dict[str, str]:
    """Erzeugt Titel und Body für einen Remediation-Pull-Request (Deutsch)."""
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

### Empfohlene Gegenmaßnahme
{fix}

### Verantwortlich
{finding.owner or "noch zuzuweisen"}

---
_Automatisch erzeugt von Specter (autorisierte Sicherheitsprüfung). Bitte den
Fix prüfen, testen und die Fundstelle nach dem Merge erneut verifizieren._
"""
    return {"title": title, "body": body}
