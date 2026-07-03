"""Defensive Azure-Analyse aus bereitgestellten Exporten.

Wertet einen lokalen JSON-Export einer Azure-Subscription aus (Storage, NSG,
VMs, Key Vault, SQL, RBAC) und leitet typische Cloud-Risiken ab - ohne jede
Live-Verbindung zur Subscription, ohne Credential-Nutzung, ohne Ausnutzung.

Hinweis: Identitäts-/M365-Themen (MFA, Conditional Access, Legacy-Auth) deckt
`analyze_entra` ab; dieser Analyzer betrachtet die Azure-Infrastruktur.

Erwartete Struktur (alle Felder optional):

    {
      "subscription_id": "0000-...",
      "storage_accounts": [
        {"name": "sa1", "public_blob_access": true, "https_only": false,
         "encryption": false, "min_tls": "TLS1.0"}
      ],
      "network_security_groups": [
        {"name": "nsg-db", "open_to_internet_ports": [3389, 1433]}
      ],
      "virtual_machines": [
        {"name": "vm1", "public_ip": true, "disk_encryption": false,
         "os": "Windows Server 2012"}
      ],
      "key_vaults": [
        {"name": "kv1", "public_network_access": true, "purge_protection": false}
      ],
      "sql_servers": [
        {"name": "sql1", "public_access": true, "tde_enabled": false}
      ],
      "role_assignments": [
        {"principal": "user@x", "role": "Owner", "scope": "subscription"}
      ]
    }
"""

from __future__ import annotations

from typing import Any

from ..findings import Finding, Severity
from ._util import as_list

SENSITIVE_PORTS = {22, 3389, 1433, 3306, 5432, 27017, 6379, 5985, 5986}
WEAK_TLS = {"tls1.0", "tlsv1.0", "tls1.1", "tlsv1.1", "ssl3", "sslv3"}
OUTDATED_OS = ("2003", "2008", "2012")
MAX_OWNERS = 3


def _mk(title, category, severity, asset, evidence, *, location="", cwe="",
        owner="Cloud-/Azure-Team") -> Finding:
    return Finding(
        title=title, category=category, severity=severity, asset=asset,
        location=location or asset, evidence=evidence, cwe=cwe, owner=owner,
        source="azure_analyzer", status="offen",
    )


def _analyze_storage(sa: dict[str, Any], sub: str) -> list[Finding]:
    out: list[Finding] = []
    name = str(sa.get("name", "storage"))
    loc = f"{sub}/storage/{name}"
    if sa.get("public_blob_access"):
        out.append(_mk(
            f"Öffentlicher Blob-Zugriff auf Storage-Account: {name}",
            "cloud_storage", Severity.HOCH, loc,
            "public_blob_access=true - Daten ohne Zugangskontrolle erreichbar",
            cwe="CWE-284",
        ))
    if sa.get("https_only") is False:
        out.append(_mk(
            f"Storage-Account erlaubt unverschlüsselten Zugriff (kein HTTPS-only): {name}",
            "transport_security", Severity.MITTEL, loc, "https_only=false", cwe="CWE-319",
        ))
    if str(sa.get("min_tls", "")).strip().lower() in WEAK_TLS:
        out.append(_mk(
            f"Storage-Account mit schwacher TLS-Mindestversion: {name}",
            "transport_security", Severity.MITTEL, loc,
            f"min_tls={sa.get('min_tls')}", cwe="CWE-327",
        ))
    if sa.get("encryption") is False:
        out.append(_mk(
            f"Storage-Account ohne Verschlüsselung im Ruhezustand: {name}",
            "misconfiguration", Severity.NIEDRIG, loc, "encryption=false", cwe="CWE-311",
        ))
    return out


def _analyze_nsg(nsg: dict[str, Any], sub: str) -> list[Finding]:
    out: list[Finding] = []
    name = str(nsg.get("name", "nsg"))
    raw_ports = nsg.get("open_to_internet_ports")
    for port in (raw_ports if isinstance(raw_ports, list) else []):
        try:
            pnum = int(port)
        except (TypeError, ValueError):
            continue
        sev = Severity.HOCH if pnum in SENSITIVE_PORTS else Severity.MITTEL
        out.append(_mk(
            f"NSG offen ins Internet (0.0.0.0/0) auf Port {pnum}: {name}",
            "exposed_service", sev, f"{sub}/nsg/{name}",
            f"open_to_internet_ports enthält {pnum}", location=f"{sub}/nsg/{name}",
            cwe="CWE-284",
        ))
    return out


def _analyze_vm(vm: dict[str, Any], sub: str) -> list[Finding]:
    out: list[Finding] = []
    name = str(vm.get("name", "vm"))
    loc = f"{sub}/vm/{name}"
    os_name = str(vm.get("os", ""))
    if vm.get("public_ip"):
        out.append(_mk(
            f"VM direkt aus dem Internet erreichbar (Public IP): {name}",
            "exposed_service", Severity.MITTEL, loc, "public_ip=true", cwe="CWE-284",
        ))
    if any(o in os_name for o in OUTDATED_OS):
        out.append(_mk(
            f"VM mit veraltetem Betriebssystem: {name}", "outdated_component",
            Severity.HOCH, loc, f"os={os_name}", cwe="CWE-1104",
        ))
    if vm.get("disk_encryption") is False:
        out.append(_mk(
            f"VM ohne Datenträgerverschlüsselung: {name}", "misconfiguration",
            Severity.NIEDRIG, loc, "disk_encryption=false", cwe="CWE-311",
        ))
    return out


def _analyze_key_vault(kv: dict[str, Any], sub: str) -> list[Finding]:
    out: list[Finding] = []
    name = str(kv.get("name", "kv"))
    loc = f"{sub}/keyvault/{name}"
    if kv.get("public_network_access"):
        out.append(_mk(
            f"Key Vault öffentlich erreichbar: {name}", "misconfiguration",
            Severity.HOCH, loc, "public_network_access=true - sollte privat sein",
            cwe="CWE-284",
        ))
    if kv.get("purge_protection") is False:
        out.append(_mk(
            f"Key Vault ohne Purge-Protection: {name}", "misconfiguration",
            Severity.NIEDRIG, loc, "purge_protection=false",
        ))
    return out


def _analyze_sql(sql: dict[str, Any], sub: str) -> list[Finding]:
    out: list[Finding] = []
    name = str(sql.get("name", "sql"))
    loc = f"{sub}/sql/{name}"
    if sql.get("public_access"):
        out.append(_mk(
            f"Azure-SQL-Server öffentlich erreichbar: {name}", "exposed_service",
            Severity.HOCH, loc, "public_access=true", cwe="CWE-284",
        ))
    if sql.get("tde_enabled") is False:
        out.append(_mk(
            f"Azure-SQL ohne Transparent Data Encryption (TDE): {name}",
            "crypto_weakness", Severity.MITTEL, loc, "tde_enabled=false", cwe="CWE-311",
        ))
    return out


def _analyze_rbac(assignments: Any, sub: str) -> list[Finding]:
    if not isinstance(assignments, list):
        assignments = []
    owners = [
        a for a in assignments
        if isinstance(a, dict)
        and str(a.get("role", "")).strip().lower() == "owner"
        and str(a.get("scope", "")).strip().lower() == "subscription"
    ]
    if len(owners) > MAX_OWNERS:
        return [_mk(
            f"Zu viele Subscription-Owner ({len(owners)})", "access_control",
            Severity.HOCH, sub,
            f"{len(owners)} Owner auf Subscription-Ebene (Empfehlung <= {MAX_OWNERS})",
            location=f"{sub}/rbac", cwe="CWE-269",
        )]
    return []


def analyze_azure(data: dict[str, Any]) -> list[Finding]:
    """Führt alle Azure-Prüfungen aus und liefert die Findings."""
    if not isinstance(data, dict):
        return []
    sub = str(data.get("subscription_id", "Azure-Subscription"))
    findings: list[Finding] = []
    for sa in as_list(data.get("storage_accounts")):
        if isinstance(sa, dict):
            findings += _analyze_storage(sa, sub)
    for nsg in as_list(data.get("network_security_groups")):
        if isinstance(nsg, dict):
            findings += _analyze_nsg(nsg, sub)
    for vm in as_list(data.get("virtual_machines")):
        if isinstance(vm, dict):
            findings += _analyze_vm(vm, sub)
    for kv in as_list(data.get("key_vaults")):
        if isinstance(kv, dict):
            findings += _analyze_key_vault(kv, sub)
    for sql in as_list(data.get("sql_servers")):
        if isinstance(sql, dict):
            findings += _analyze_sql(sql, sub)
    findings += _analyze_rbac(data.get("role_assignments"), sub)
    return findings
