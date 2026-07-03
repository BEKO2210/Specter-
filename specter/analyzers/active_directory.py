"""Defensive Active-Directory-Analyse aus bereitgestellten Exporten.

Wertet einen lokalen JSON-Export aus (eigene, dokumentierte Struktur oder ein
BloodHound-`users`-Export) und leitet typische AD-Risiken KMU-tauglich ab -
ohne jede Live-Interaktion mit dem Verzeichnis.

Erwartete (eigene) Struktur (alle Felder optional):

    {
      "domain": "corp.example.de",
      "password_policy": {
        "min_length": 8, "complexity": false, "max_age_days": 0,
        "lockout_threshold": 0, "history_length": 3
      },
      "krbtgt_password_age_days": 1200,
      "privileged_groups": {"Domain Admins": ["a", "b", ...]},
      "users": [
        {"name": "svc_sql", "enabled": true, "privileged": true,
         "password_never_expires": true, "last_logon_days": 400,
         "service_principal_names": ["MSSQL/db01"], "kerberos_preauth": false,
         "admin_count": 1, "groups": ["Domain Admins"]}
      ]
    }
"""

from __future__ import annotations

from typing import Any

from ..findings import Finding, Severity
from ._util import as_bool, as_int, as_str_list

# Schwellenwerte (an BSI-Empfehlungen / gängiger Praxis orientiert).
MIN_PASSWORD_LENGTH = 12
STALE_LOGON_DAYS = 90
KRBTGT_MAX_AGE_DAYS = 180
MAX_DOMAIN_ADMINS = 8
HIGH_PRIV_GROUPS = {
    "domain admins", "enterprise admins", "schema admins",
    "administrators", "domänen-admins", "organisations-admins",
}


def _mk(title, category, severity, asset, evidence, *, location="", cwe="",
        owner="AD-Team") -> Finding:
    return Finding(
        title=title, category=category, severity=severity, asset=asset,
        location=location or asset, evidence=evidence, cwe=cwe, owner=owner,
        source="ad_analyzer", status="offen",
    )


def _analyze_password_policy(pol: dict[str, Any], domain: str) -> list[Finding]:
    out: list[Finding] = []
    if not isinstance(pol, dict) or not pol:
        return out
    min_len = as_int(pol.get("min_length"))
    if min_len is not None and min_len < MIN_PASSWORD_LENGTH:
        out.append(_mk(
            f"Passwort-Mindestlänge zu gering ({min_len} < {MIN_PASSWORD_LENGTH})",
            "auth_weakness", Severity.HOCH, domain,
            f"password_policy.min_length = {min_len}", cwe="CWE-521",
        ))
    if as_bool(pol.get("complexity")) is False:
        out.append(_mk(
            "Passwort-Komplexität nicht erzwungen", "auth_weakness",
            Severity.HOCH, domain, "password_policy.complexity = false", cwe="CWE-521",
        ))
    if as_int(pol.get("lockout_threshold")) == 0:
        out.append(_mk(
            "Keine Account-Lockout-Policy (Brute-Force ungebremst)",
            "auth_weakness", Severity.HOCH, domain,
            "password_policy.lockout_threshold = 0", cwe="CWE-307",
        ))
    if as_int(pol.get("max_age_days")) == 0:
        out.append(_mk(
            "Passwörter laufen nie ab", "auth_weakness", Severity.MITTEL,
            domain, "password_policy.max_age_days = 0", cwe="CWE-262",
        ))
    hist = as_int(pol.get("history_length"))
    if hist is not None and hist < 5:
        out.append(_mk(
            f"Passwort-Historie zu kurz ({hist})", "auth_weakness",
            Severity.NIEDRIG, domain, f"password_policy.history_length = {hist}",
        ))
    return out


def _analyze_krbtgt(raw_age: Any, domain: str) -> list[Finding]:
    age = as_int(raw_age)
    if age is not None and age > KRBTGT_MAX_AGE_DAYS:
        return [_mk(
            f"krbtgt-Passwort veraltet ({age} Tage) - Golden-Ticket-Risiko",
            "auth_weakness", Severity.HOCH, domain,
            f"krbtgt_password_age_days = {age} (> {KRBTGT_MAX_AGE_DAYS})",
            cwe="CWE-324",
        )]
    return []


def _analyze_privileged_groups(groups: dict[str, Any], domain: str) -> list[Finding]:
    out: list[Finding] = []
    if not isinstance(groups, dict):
        return out
    for name, members in groups.items():
        if not isinstance(members, list):
            continue
        if name.strip().lower() in HIGH_PRIV_GROUPS and len(members) > MAX_DOMAIN_ADMINS:
            out.append(_mk(
                f"Zu viele privilegierte Konten in '{name}' ({len(members)})",
                "access_control", Severity.HOCH, domain,
                f"{name}: {len(members)} Mitglieder (Richtwert <= {MAX_DOMAIN_ADMINS})",
                location=f"{domain}/{name}", cwe="CWE-269",
            ))
    return out


def _analyze_user(user: dict[str, Any], domain: str) -> list[Finding]:
    out: list[Finding] = []
    name = str(user.get("name", "unbekannt"))
    enabled = as_bool(user.get("enabled"), True)
    groups = as_str_list(user.get("groups"))
    priv = as_bool(user.get("privileged"), False) or any(
        g.strip().lower() in HIGH_PRIV_GROUPS for g in groups
    )
    loc = f"{domain}/{name}"

    if enabled and priv and as_bool(user.get("password_never_expires"), False):
        out.append(_mk(
            f"Privilegiertes Konto mit nie ablaufendem Passwort: {name}",
            "auth_weakness", Severity.HOCH, name,
            "privileged=true, password_never_expires=true", location=loc,
            cwe="CWE-262",
        ))

    last = as_int(user.get("last_logon_days"))
    if enabled and last is not None and last > STALE_LOGON_DAYS:
        sev = Severity.HOCH if priv else Severity.MITTEL
        out.append(_mk(
            f"Aktives, aber ungenutztes Konto (seit {last} Tagen): {name}",
            "access_control", sev, name,
            f"enabled=true, last_logon_days={last}", location=loc, cwe="CWE-1108",
        ))

    if not enabled and priv:
        out.append(_mk(
            f"Deaktiviertes Konto weiterhin in privilegierter Gruppe: {name}",
            "access_control", Severity.MITTEL, name,
            "enabled=false, aber Mitglied einer privilegierten Gruppe", location=loc,
            cwe="CWE-269",
        ))

    spns = as_str_list(user.get("service_principal_names"))
    if enabled and spns:
        out.append(_mk(
            f"Service-Konto mit SPN (Kerberoasting-Exposition): {name}",
            "auth_weakness", Severity.MITTEL, name,
            f"service_principal_names={spns[:3]}", location=loc, cwe="CWE-522",
        ))

    if enabled and as_bool(user.get("kerberos_preauth")) is False:
        out.append(_mk(
            f"Kerberos-Pre-Auth deaktiviert (AS-REP-Roasting): {name}",
            "auth_weakness", Severity.HOCH, name,
            "kerberos_preauth=false", location=loc, cwe="CWE-522",
        ))

    in_priv_group = any(g.strip().lower() in HIGH_PRIV_GROUPS for g in groups)
    if as_int(user.get("admin_count")) == 1 and not in_priv_group:
        out.append(_mk(
            f"adminCount=1 ohne aktuelle Privilegien (AdminSDHolder-Rest): {name}",
            "access_control", Severity.NIEDRIG, name,
            "admin_count=1, aber nicht in privilegierter Gruppe", location=loc,
        ))
    return out


def normalize_bloodhound_users(data: Any) -> list[dict[str, Any]]:
    """Mappt einen BloodHound-`users`-Export auf die eigene User-Struktur.

    Nur statische Felder (keine zeitabhängige Stale-Erkennung).
    """
    if not isinstance(data, dict):
        return []
    entries = data.get("data")
    if not isinstance(entries, list):
        return []
    users: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        props = entry.get("Properties")
        if not isinstance(props, dict):
            props = {}
        if "name" not in props and "samaccountname" not in props:
            continue
        users.append({
            "name": props.get("name") or props.get("samaccountname"),
            "enabled": props.get("enabled", True),
            "privileged": bool(props.get("admincount", False)),
            "admin_count": 1 if props.get("admincount") else 0,
            "password_never_expires": bool(props.get("pwdneverexpires", False)),
            "kerberos_preauth": not bool(props.get("dontreqpreauth", False)),
            "service_principal_names": props.get("serviceprincipalnames") or [],
            "groups": [],
        })
    return users


def analyze_ad(data: dict[str, Any]) -> list[Finding]:
    """Führt alle AD-Prüfungen aus und liefert die Findings."""
    if not isinstance(data, dict):
        return []
    domain = str(data.get("domain", "AD-Domäne"))

    users = data.get("users")
    if not isinstance(users, list):
        # Evtl. ein BloodHound-Export?
        users = normalize_bloodhound_users(data)

    findings: list[Finding] = []
    findings += _analyze_password_policy(data.get("password_policy") or {}, domain)
    findings += _analyze_krbtgt(data.get("krbtgt_password_age_days"), domain)
    findings += _analyze_privileged_groups(data.get("privileged_groups") or {}, domain)
    for user in users:
        if isinstance(user, dict):
            findings += _analyze_user(user, domain)
    return findings
