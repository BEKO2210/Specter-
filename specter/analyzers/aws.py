"""Defensive AWS-Analyse aus bereitgestellten Exporten.

Wertet einen lokalen JSON-Export einer AWS-Umgebung aus (IAM, S3, Security
Groups, Passwort-Policy) und leitet typische Cloud-Risiken ab - ohne jede
Live-Verbindung zum Konto, ohne Credential-Nutzung, ohne Ausnutzung.

Erwartete Struktur (alle Felder optional):

    {
      "account_id": "123456789012",
      "root_account": {"mfa_enabled": false, "access_keys": 1},
      "password_policy": {"minimum_length": 8, "require_symbols": false,
                          "max_age_days": 0},
      "users": [
        {"name": "deploy", "mfa_enabled": false, "console_access": true,
         "attached_policies": ["AdministratorAccess"],
         "access_keys": [{"age_days": 400, "last_used_days": 300}]}
      ],
      "roles": [
        {"name": "ci", "trust": "*", "attached_policies": ["AdministratorAccess"]}
      ],
      "s3_buckets": [
        {"name": "kunden-backups", "public": true, "encryption": false}
      ],
      "security_groups": [
        {"name": "db-sg", "open_to_world_ports": [3306, 22]}
      ]
    }
"""

from __future__ import annotations

from typing import Any

from ..findings import Finding, Severity

MIN_PASSWORD_LENGTH = 14
ACCESS_KEY_MAX_AGE = 180
ACCESS_KEY_UNUSED_DAYS = 180
# Aus dem Internet besonders kritische Ports.
SENSITIVE_PORTS = {22, 3389, 3306, 1433, 5432, 27017, 6379, 9200, 5900}
# Als "administrativ" geltende AWS-Policies bzw. Wildcards.
ADMIN_POLICIES = {"administratoraccess", "*", "*:*", "iamfullaccess"}


def _mk(title, category, severity, asset, evidence, *, location="", cwe="",
        owner="Cloud-/AWS-Team") -> Finding:
    return Finding(
        title=title, category=category, severity=severity, asset=asset,
        location=location or asset, evidence=evidence, cwe=cwe, owner=owner,
        source="aws_analyzer", status="offen",
    )


def _is_admin(policies: Any) -> bool:
    return any(str(p).strip().lower() in ADMIN_POLICIES for p in (policies or []))


def _analyze_root(root: dict[str, Any], account: str) -> list[Finding]:
    out: list[Finding] = []
    if not root:
        return out
    if root.get("mfa_enabled") is False:
        out.append(_mk(
            "Root-Konto ohne MFA", "auth_weakness", Severity.KRITISCH, account,
            "root_account.mfa_enabled=false", cwe="CWE-308",
        ))
    keys = root.get("access_keys")
    if isinstance(keys, int) and keys > 0:
        out.append(_mk(
            "Root-Konto besitzt Access-Keys", "access_control", Severity.KRITISCH,
            account, f"root_account.access_keys={keys} (Root-Keys vermeiden)",
            cwe="CWE-250",
        ))
    return out


def _analyze_password_policy(pol: dict[str, Any], account: str) -> list[Finding]:
    out: list[Finding] = []
    if not pol:
        return out
    ml = pol.get("minimum_length")
    if isinstance(ml, int) and ml < MIN_PASSWORD_LENGTH:
        out.append(_mk(
            f"Schwache IAM-Passwort-Policy (Mindestlaenge {ml})", "auth_weakness",
            Severity.MITTEL, account, f"password_policy.minimum_length={ml}",
            cwe="CWE-521",
        ))
    if pol.get("require_symbols") is False:
        out.append(_mk(
            "IAM-Passwort-Policy ohne Sonderzeichen-Pflicht", "auth_weakness",
            Severity.NIEDRIG, account, "password_policy.require_symbols=false",
        ))
    if pol.get("max_age_days") == 0:
        out.append(_mk(
            "IAM-Passwoerter laufen nie ab", "auth_weakness", Severity.NIEDRIG,
            account, "password_policy.max_age_days=0",
        ))
    return out


def _analyze_user(user: dict[str, Any], account: str) -> list[Finding]:
    out: list[Finding] = []
    name = str(user.get("name", "iam-user"))
    loc = f"{account}/user/{name}"
    if user.get("console_access") and user.get("mfa_enabled") is False:
        out.append(_mk(
            f"IAM-Konsolenzugriff ohne MFA: {name}", "auth_weakness",
            Severity.HOCH, name, "console_access=true, mfa_enabled=false",
            location=loc, cwe="CWE-308",
        ))
    if _is_admin(user.get("attached_policies")):
        out.append(_mk(
            f"Ueberprivilegierter IAM-User (Admin): {name}", "access_control",
            Severity.HOCH, name,
            f"attached_policies={list(user.get('attached_policies'))[:3]}",
            location=loc, cwe="CWE-269",
        ))
    for key in (user.get("access_keys") or []):
        if not isinstance(key, dict):
            continue
        age = key.get("age_days")
        if isinstance(age, int) and age > ACCESS_KEY_MAX_AGE:
            out.append(_mk(
                f"Alter Access-Key ({age} Tage): {name}", "access_control",
                Severity.MITTEL, name, f"access_key age_days={age}", location=loc,
                cwe="CWE-798",
            ))
        used = key.get("last_used_days")
        if used is None or (isinstance(used, int) and used > ACCESS_KEY_UNUSED_DAYS):
            out.append(_mk(
                f"Ungenutzter Access-Key: {name}", "access_control",
                Severity.NIEDRIG, name, f"access_key last_used_days={used}",
                location=loc,
            ))
    return out


def _analyze_role(role: dict[str, Any], account: str) -> list[Finding]:
    name = str(role.get("name", "iam-role"))
    loc = f"{account}/role/{name}"
    trust_open = str(role.get("trust", "")).strip() == "*"
    admin = _is_admin(role.get("attached_policies"))
    if trust_open and admin:
        return [_mk(
            f"Admin-Rolle von beliebigem Prinzipal annehmbar: {name}",
            "access_control", Severity.KRITISCH, name,
            "trust='*' und administrative Policy", location=loc, cwe="CWE-284",
        )]
    if trust_open:
        return [_mk(
            f"Rolle von beliebigem Prinzipal annehmbar: {name}", "access_control",
            Severity.HOCH, name, "trust='*'", location=loc, cwe="CWE-284",
        )]
    return []


def _analyze_bucket(bucket: dict[str, Any], account: str) -> list[Finding]:
    out: list[Finding] = []
    name = str(bucket.get("name", "s3-bucket"))
    loc = f"s3://{name}"
    if bucket.get("public"):
        out.append(_mk(
            f"Oeffentlicher S3-Bucket: {name}", "cloud_storage", Severity.HOCH,
            loc, "public=true - ohne Zugangskontrolle erreichbar", cwe="CWE-284",
        ))
    if bucket.get("encryption") is False:
        out.append(_mk(
            f"S3-Bucket ohne Verschluesselung: {name}", "misconfiguration",
            Severity.NIEDRIG, loc, "encryption=false", cwe="CWE-311",
        ))
    return out


def _analyze_sg(sg: dict[str, Any], account: str) -> list[Finding]:
    out: list[Finding] = []
    name = str(sg.get("name", "sg"))
    ports = sg.get("open_to_world_ports") or []
    for port in ports:
        try:
            pnum = int(port)
        except (TypeError, ValueError):
            continue
        sev = Severity.HOCH if pnum in SENSITIVE_PORTS else Severity.MITTEL
        out.append(_mk(
            f"Security-Group offen ins Internet (0.0.0.0/0) auf Port {pnum}",
            "exposed_service", sev, f"{account}/sg/{name}",
            f"open_to_world_ports enthaelt {pnum}", location=f"{account}/sg/{name}",
            cwe="CWE-284",
        ))
    return out


def analyze_aws(data: dict[str, Any]) -> list[Finding]:
    """Fuehrt alle AWS-Pruefungen aus und liefert die Findings."""
    if not isinstance(data, dict):
        return []
    account = str(data.get("account_id", "AWS-Konto"))
    findings: list[Finding] = []
    findings += _analyze_root(data.get("root_account") or {}, account)
    findings += _analyze_password_policy(data.get("password_policy") or {}, account)
    for user in (data.get("users") or []):
        if isinstance(user, dict):
            findings += _analyze_user(user, account)
    for role in (data.get("roles") or []):
        if isinstance(role, dict):
            findings += _analyze_role(role, account)
    for bucket in (data.get("s3_buckets") or []):
        if isinstance(bucket, dict):
            findings += _analyze_bucket(bucket, account)
    for sg in (data.get("security_groups") or []):
        if isinstance(sg, dict):
            findings += _analyze_sg(sg, account)
    return findings
