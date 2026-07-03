"""Defensive Entra-ID-/Microsoft-365-Analyse aus bereitgestellten Exporten.

Wertet einen lokalen JSON-Export einer Entra-ID-(Azure-AD-)/M365-Umgebung aus
und leitet typische KMU-Risiken ab - ohne jede Live-Verbindung zum Tenant.
Fast jeder deutsche Mittelständler nutzt M365; diese Prüfungen decken die
häufigsten Fehlkonfigurationen ab.

Erwartete Struktur (alle Felder optional):

    {
      "tenant": "contoso.onmicrosoft.com",
      "security_defaults_enabled": false,
      "legacy_auth_allowed": true,
      "conditional_access_policies": [
        {"name": "MFA", "state": "enabled",
         "requires_mfa": true, "blocks_legacy_auth": false}
      ],
      "roles": {"Global Administrator": ["a@x", "b@x", ...]},
      "users": [
        {"upn": "admin@x", "enabled": true, "privileged": true,
         "mfa_registered": false, "guest": false, "last_sign_in_days": 5}
      ],
      "app_registrations": [
        {"name": "Legacy App", "admin_consent": true,
         "high_privilege_permissions": ["Directory.ReadWrite.All"]}
      ],
      "sharing": {"anonymous_links_enabled": true}
    }
"""

from __future__ import annotations

from typing import Any

from ..findings import Finding, Severity

MAX_GLOBAL_ADMINS = 5
STALE_GUEST_DAYS = 90
HIGH_PRIV_ROLES = {
    "global administrator", "privileged role administrator",
    "privileged authentication administrator", "application administrator",
    "globaler administrator",
}


def _mk(title, category, severity, asset, evidence, *, location="", cwe="",
        owner="M365-/Identity-Team") -> Finding:
    return Finding(
        title=title, category=category, severity=severity, asset=asset,
        location=location or asset, evidence=evidence, cwe=cwe, owner=owner,
        source="entra_analyzer", status="offen",
    )


def _analyze_baseline(data: dict[str, Any], tenant: str) -> list[Finding]:
    out: list[Finding] = []
    sec_defaults = bool(data.get("security_defaults_enabled", False))
    policies = data.get("conditional_access_policies")
    policies = policies if isinstance(policies, list) else []
    enabled = [p for p in policies
               if isinstance(p, dict) and str(p.get("state", "")).lower() == "enabled"]
    requires_mfa = any((p or {}).get("requires_mfa") for p in enabled)
    blocks_legacy = any((p or {}).get("blocks_legacy_auth") for p in enabled)
    legacy_allowed = bool(data.get("legacy_auth_allowed", False))

    if not sec_defaults and not enabled:
        out.append(_mk(
            "Weder Security Defaults noch Conditional Access aktiv",
            "misconfiguration", Severity.HOCH, tenant,
            "security_defaults_enabled=false und keine aktive CA-Richtlinie",
            cwe="CWE-1188",
        ))
    if not sec_defaults and not requires_mfa:
        out.append(_mk(
            "Keine MFA-Erzwingung (Security Defaults/CA)", "auth_weakness",
            Severity.HOCH, tenant,
            "Keine aktive Richtlinie erzwingt MFA", cwe="CWE-308",
        ))
    if legacy_allowed and not blocks_legacy:
        out.append(_mk(
            "Legacy-Authentifizierung nicht blockiert (Password-Spraying)",
            "auth_weakness", Severity.HOCH, tenant,
            "legacy_auth_allowed=true, keine CA blockiert Legacy-Auth", cwe="CWE-287",
        ))
    return out


def _analyze_roles(roles: dict[str, Any], tenant: str) -> list[Finding]:
    out: list[Finding] = []
    if not isinstance(roles, dict):
        return out
    for name, members in roles.items():
        if not isinstance(members, list):
            continue
        if name.strip().lower() in HIGH_PRIV_ROLES and len(members) > MAX_GLOBAL_ADMINS:
            out.append(_mk(
                f"Zu viele Konten in '{name}' ({len(members)})", "access_control",
                Severity.HOCH, tenant,
                f"{name}: {len(members)} Mitglieder (Empfehlung <= {MAX_GLOBAL_ADMINS})",
                location=f"{tenant}/{name}", cwe="CWE-269",
            ))
    return out


def _analyze_user(user: dict[str, Any], tenant: str) -> list[Finding]:
    out: list[Finding] = []
    upn = str(user.get("upn", "unbekannt"))
    enabled = bool(user.get("enabled", True))
    priv = bool(user.get("privileged", False))
    loc = f"{tenant}/{upn}"

    if enabled and user.get("mfa_registered") is False:
        if priv:
            out.append(_mk(
                f"Privilegiertes Konto ohne MFA: {upn}", "auth_weakness",
                Severity.KRITISCH, upn, "privileged=true, mfa_registered=false",
                location=loc, cwe="CWE-308",
            ))
        else:
            out.append(_mk(
                f"Konto ohne MFA: {upn}", "auth_weakness", Severity.MITTEL, upn,
                "mfa_registered=false", location=loc, cwe="CWE-308",
            ))

    last = user.get("last_sign_in_days")
    if enabled and user.get("guest") and isinstance(last, int) and last > STALE_GUEST_DAYS:
        out.append(_mk(
            f"Inaktives Gastkonto (seit {last} Tagen): {upn}", "access_control",
            Severity.MITTEL, upn, f"guest=true, last_sign_in_days={last}",
            location=loc, cwe="CWE-1108",
        ))
    return out


def _analyze_apps(apps: Any, tenant: str) -> list[Finding]:
    out: list[Finding] = []
    for app in (apps or []):
        if not isinstance(app, dict):
            continue
        name = str(app.get("name", "App"))
        perms = app.get("high_privilege_permissions") or []
        if app.get("admin_consent") and perms:
            out.append(_mk(
                f"Überprivilegierte App-Registrierung: {name}", "access_control",
                Severity.HOCH, tenant,
                f"admin_consent=true, Berechtigungen={list(perms)[:3]}",
                location=f"{tenant}/app/{name}", cwe="CWE-250",
            ))
    return out


def _analyze_sharing(sharing: Any, tenant: str) -> list[Finding]:
    if isinstance(sharing, dict) and sharing.get("anonymous_links_enabled"):
        return [_mk(
            "Anonyme Freigabelinks aktiviert (SharePoint/OneDrive)", "personal_data",
            Severity.MITTEL, tenant,
            "sharing.anonymous_links_enabled=true - DSGVO-Risiko", cwe="CWE-284",
        )]
    return []


def analyze_entra(data: dict[str, Any]) -> list[Finding]:
    """Führt alle Entra-ID-/M365-Prüfungen aus und liefert die Findings."""
    if not isinstance(data, dict):
        return []
    tenant = str(data.get("tenant", "M365-Tenant"))
    findings: list[Finding] = []
    findings += _analyze_baseline(data, tenant)
    findings += _analyze_roles(data.get("roles") or {}, tenant)
    for user in (data.get("users") or []):
        if isinstance(user, dict):
            findings += _analyze_user(user, tenant)
    findings += _analyze_apps(data.get("app_registrations"), tenant)
    findings += _analyze_sharing(data.get("sharing"), tenant)
    return findings
