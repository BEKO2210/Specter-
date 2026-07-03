"""Defensive Firewall-/VPN-Konfigurationsanalyse aus bereitgestelltem Export.

Wertet einen lokalen JSON-Export einer Firewall-/VPN-Konfiguration aus
(Regelwerk, VPN-Tunnel, Management-Ebene) und leitet typische Perimeter-Risiken
ab - ohne jede Live-Verbindung zum Gerät, ohne Credential-Nutzung, ohne
Ausnutzung.

Im Mittelstand ein Haupteinfallstor: offene RDP-/SSH-Ports ins Internet,
"Any-Any"-Freigaben, VPN ohne MFA oder mit veralteter Kryptographie/IKEv1 und
öffentlich erreichbare Management-Interfaces.

Erwartete Struktur (alle Felder optional):

    {
      "device": "fw-hq",
      "rules": [
        {"name": "permit-all", "action": "allow", "source": "any",
         "destination": "any", "service": "any"},
        {"name": "rdp-in", "action": "allow", "source": "0.0.0.0/0",
         "destination": "10.0.0.5", "service": "RDP", "port": 3389}
      ],
      "vpn": [
        {"name": "site-a", "encryption": "3des", "ike_version": 1,
         "mfa": false, "eol": true}
      ],
      "management": {"public": true, "exposed_interfaces": ["https", "ssh"]}
    }
"""

from __future__ import annotations

from typing import Any

from ..findings import Finding, Severity
from ._util import as_list

# Werte, die "beliebig / aus dem Internet" bedeuten.
_ANY = {"any", "*", "all", "0.0.0.0/0", "0.0.0.0", "::/0", ""}
# Fernzugangs-Ports (für den Mittelstand besonders kritisch).
_REMOTE_PORTS = {22: "SSH", 3389: "RDP"}
# Weitere sensible Dienste, die nicht offen ins Internet gehören.
_SENSITIVE_PORTS = {
    23: "Telnet", 445: "SMB", 1433: "MSSQL", 3306: "MySQL",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 27017: "MongoDB",
}
# Servicename -> Port (für Regeln ohne numerisches Port-Feld).
_SERVICE_PORTS = {
    "ssh": 22, "rdp": 3389, "telnet": 23, "smb": 445, "cifs": 445,
    "mssql": 1433, "mysql": 3306, "postgres": 5432, "postgresql": 5432,
    "vnc": 5900, "redis": 6379, "mongodb": 27017,
}
# Als schwach geltende VPN-/IPsec-Kryptographie.
_WEAK_CRYPTO = {"des", "3des", "rc4", "null", "md5", "sha1"}


def _mk(title, category, severity, asset, evidence, *, location="", cwe="",
        owner="Netzwerk-/Firewall-Team") -> Finding:
    return Finding(
        title=title, category=category, severity=severity, asset=asset,
        location=location or asset, evidence=evidence, cwe=cwe, owner=owner,
        source="firewall_analyzer", status="offen",
    )


def _is_any(value: Any) -> bool:
    return str(value or "").strip().lower() in _ANY


def _rule_port(rule: dict[str, Any]) -> int:
    """Ermittelt den Zielport aus 'port' (numerisch) oder 'service' (Name)."""
    try:
        pnum = int(rule.get("port"))
    except (TypeError, ValueError):
        pnum = 0
    if pnum:
        return pnum
    return _SERVICE_PORTS.get(str(rule.get("service", "")).strip().lower(), 0)


def _analyze_rule(rule: dict[str, Any], device: str) -> list[Finding]:
    if str(rule.get("action", "allow")).strip().lower() not in ("allow", "permit", "accept"):
        return []
    name = str(rule.get("name", "Regel"))
    loc = f"{device}/rule/{name}"
    src, dst, svc = rule.get("source"), rule.get("destination"), rule.get("service")
    if not _is_any(src):
        return []
    if _is_any(dst) and _is_any(svc):
        return [_mk(
            f"Any-Any-Freigabe in der Firewall: {name}",
            "misconfiguration", Severity.HOCH, loc,
            "action=allow, source=any, destination=any, service=any - "
            "hebt die Segmentierung praktisch auf", location=loc, cwe="CWE-284",
        )]
    port = _rule_port(rule)
    if port in _REMOTE_PORTS:
        return [_mk(
            f"{_REMOTE_PORTS[port]} aus dem Internet erreichbar: {name}",
            "remote_access", Severity.HOCH, loc,
            f"source={src} -> Port {port} ({_REMOTE_PORTS[port]}) offen - "
            "Fernzugang gehört hinter VPN/MFA", location=loc, cwe="CWE-284",
        )]
    if port in _SENSITIVE_PORTS:
        return [_mk(
            f"Sensibler Dienst offen ins Internet ({_SENSITIVE_PORTS[port]}): {name}",
            "exposed_service", Severity.HOCH, loc,
            f"source={src} -> Port {port} ({_SENSITIVE_PORTS[port]})",
            location=loc, cwe="CWE-284",
        )]
    if _is_any(svc):
        return [_mk(
            f"Alle Ports aus dem Internet freigegeben: {name}",
            "exposed_service", Severity.HOCH, loc,
            f"source={src}, service=any -> {dst} auf allen Ports erreichbar",
            location=loc, cwe="CWE-284",
        )]
    return []


def _analyze_vpn(vpn: dict[str, Any], device: str) -> list[Finding]:
    out: list[Finding] = []
    name = str(vpn.get("name", "vpn"))
    loc = f"{device}/vpn/{name}"
    if str(vpn.get("encryption", "")).strip().lower() in _WEAK_CRYPTO:
        out.append(_mk(
            f"VPN mit schwacher Kryptographie: {name}", "crypto_weakness",
            Severity.HOCH, loc, f"encryption={vpn.get('encryption')} - "
            "veraltet, durch AES-256/SHA-256+ ersetzen", location=loc, cwe="CWE-327",
        ))
    if str(vpn.get("ike_version", "")).strip() == "1":
        out.append(_mk(
            f"VPN nutzt veraltetes IKEv1: {name}", "misconfiguration",
            Severity.MITTEL, loc, "ike_version=1 - auf IKEv2 umstellen",
            location=loc, cwe="CWE-327",
        ))
    if vpn.get("mfa") is False:
        out.append(_mk(
            f"VPN-Zugang ohne MFA: {name}", "remote_access", Severity.HOCH, loc,
            "mfa=false - Fernzugang ohne zweiten Faktor", location=loc, cwe="CWE-308",
        ))
    if vpn.get("eol") or vpn.get("outdated"):
        out.append(_mk(
            f"Veraltetes/abgekündigtes VPN-Gateway: {name}", "outdated_component",
            Severity.HOCH, loc, "eol/outdated=true - kein Sicherheits-Support mehr",
            location=loc, cwe="CWE-1104",
        ))
    return out


def _analyze_management(mgmt: dict[str, Any], device: str) -> list[Finding]:
    if not mgmt.get("public"):
        return []
    loc = f"{device}/management"
    out: list[Finding] = []
    exposed = [str(i).strip().lower() for i in as_list(mgmt.get("exposed_interfaces"))]
    out.append(_mk(
        "Management-Interface aus dem Internet erreichbar",
        "exposed_service", Severity.HOCH, loc,
        f"public=true, exposed={exposed or 'unbekannt'} - Verwaltungsebene "
        "gehört nur ins interne/Out-of-Band-Netz", location=loc, cwe="CWE-284",
    ))
    if "ssh" in exposed:
        out.append(_mk(
            "SSH-Fernzugang der Firewall öffentlich erreichbar",
            "remote_access", Severity.HOCH, loc,
            "ssh in exposed_interfaces bei public=true", location=loc, cwe="CWE-284",
        ))
    return out


def analyze_firewall(data: dict[str, Any]) -> list[Finding]:
    """Führt alle Firewall-/VPN-Prüfungen aus und liefert die Findings."""
    if not isinstance(data, dict):
        return []
    device = str(data.get("device", "Firewall"))
    findings: list[Finding] = []
    for rule in as_list(data.get("rules")):
        if isinstance(rule, dict):
            findings += _analyze_rule(rule, device)
    for vpn in as_list(data.get("vpn")):
        if isinstance(vpn, dict):
            findings += _analyze_vpn(vpn, device)
    mgmt = data.get("management")
    if isinstance(mgmt, dict):
        findings += _analyze_management(mgmt, device)
    return findings
