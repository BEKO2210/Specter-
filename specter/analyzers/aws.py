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
from ._util import as_bool, as_int, as_list

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


def _normalize_policies(policies: Any) -> list[Any]:
    if isinstance(policies, str):
        return [policies]
    return policies if isinstance(policies, list) else []


def _is_admin(policies: Any) -> bool:
    return any(str(p).strip().lower() in ADMIN_POLICIES
              for p in _normalize_policies(policies))


def _analyze_root(root: dict[str, Any], account: str) -> list[Finding]:
    out: list[Finding] = []
    if not isinstance(root, dict) or not root:
        return out
    if as_bool(root.get("mfa_enabled")) is False:
        out.append(_mk(
            "Root-Konto ohne MFA", "auth_weakness", Severity.KRITISCH, account,
            "root_account.mfa_enabled=false", cwe="CWE-308",
        ))
    keys = as_int(root.get("access_keys"))
    if keys is not None and keys > 0:
        out.append(_mk(
            "Root-Konto besitzt Access-Keys", "access_control", Severity.KRITISCH,
            account, f"root_account.access_keys={keys} (Root-Keys vermeiden)",
            cwe="CWE-250",
        ))
    return out


def _analyze_password_policy(pol: dict[str, Any], account: str) -> list[Finding]:
    out: list[Finding] = []
    if not isinstance(pol, dict) or not pol:
        return out
    ml = as_int(pol.get("minimum_length"))
    if ml is not None and ml < MIN_PASSWORD_LENGTH:
        out.append(_mk(
            f"Schwache IAM-Passwort-Policy (Mindestlänge {ml})", "auth_weakness",
            Severity.MITTEL, account, f"password_policy.minimum_length={ml}",
            cwe="CWE-521",
        ))
    if as_bool(pol.get("require_symbols")) is False:
        out.append(_mk(
            "IAM-Passwort-Policy ohne Sonderzeichen-Pflicht", "auth_weakness",
            Severity.NIEDRIG, account, "password_policy.require_symbols=false",
        ))
    if as_int(pol.get("max_age_days")) == 0:
        out.append(_mk(
            "IAM-Passwörter laufen nie ab", "auth_weakness", Severity.NIEDRIG,
            account, "password_policy.max_age_days=0",
        ))
    return out


def _analyze_user(user: dict[str, Any], account: str) -> list[Finding]:
    out: list[Finding] = []
    name = str(user.get("name", "iam-user"))
    loc = f"{account}/user/{name}"
    if as_bool(user.get("console_access"), False) and as_bool(user.get("mfa_enabled")) is False:
        out.append(_mk(
            f"IAM-Konsolenzugriff ohne MFA: {name}", "auth_weakness",
            Severity.HOCH, name, "console_access=true, mfa_enabled=false",
            location=loc, cwe="CWE-308",
        ))
    pols = _normalize_policies(user.get("attached_policies"))
    if _is_admin(pols):
        out.append(_mk(
            f"Überprivilegierter IAM-User (Admin): {name}", "access_control",
            Severity.HOCH, name,
            f"attached_policies={pols[:3]}",
            location=loc, cwe="CWE-269",
        ))
    for idx, key in enumerate(as_list(user.get("access_keys"))):
        if not isinstance(key, dict):
            continue
        # Schlüssel-Identität, damit zwei Keys desselben Users nicht durch die
        # Dedup (Kategorie/Asset/Location/Titel) zu einem Finding verschmelzen.
        kid = str(key.get("id") or key.get("access_key_id") or f"#{idx + 1}")
        age = as_int(key.get("age_days"))
        if age is not None and age > ACCESS_KEY_MAX_AGE:
            out.append(_mk(
                f"Alter Access-Key ({age} Tage): {name} [{kid}]", "access_control",
                Severity.MITTEL, name, f"access_key {kid} age_days={age}",
                location=f"{loc}#{kid}", cwe="CWE-798",
            ))
        raw_used = key.get("last_used_days")
        used = as_int(raw_used)
        if raw_used is None or (used is not None and used > ACCESS_KEY_UNUSED_DAYS):
            out.append(_mk(
                f"Ungenutzter Access-Key: {name} [{kid}]", "access_control",
                Severity.NIEDRIG, name, f"access_key {kid} last_used_days={used}",
                location=f"{loc}#{kid}",
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
    if as_bool(bucket.get("public"), False):
        out.append(_mk(
            f"Öffentlicher S3-Bucket: {name}", "cloud_storage", Severity.HOCH,
            loc, "public=true - ohne Zugangskontrolle erreichbar", cwe="CWE-284",
        ))
    if as_bool(bucket.get("encryption")) is False:
        out.append(_mk(
            f"S3-Bucket ohne Verschlüsselung: {name}", "misconfiguration",
            Severity.NIEDRIG, loc, "encryption=false", cwe="CWE-311",
        ))
    return out


def _analyze_sg(sg: dict[str, Any], account: str) -> list[Finding]:
    out: list[Finding] = []
    name = str(sg.get("name", "sg"))
    raw_ports = sg.get("open_to_world_ports")
    ports = raw_ports if isinstance(raw_ports, list) else []
    for port in ports:
        try:
            pnum = int(port)
        except (TypeError, ValueError):
            continue
        sev = Severity.HOCH if pnum in SENSITIVE_PORTS else Severity.MITTEL
        out.append(_mk(
            f"Security-Group offen ins Internet (0.0.0.0/0) auf Port {pnum}",
            "exposed_service", sev, f"{account}/sg/{name}",
            f"open_to_world_ports enthält {pnum}", location=f"{account}/sg/{name}",
            cwe="CWE-284",
        ))
    return out


def analyze_aws(data: dict[str, Any]) -> list[Finding]:
    """Führt alle AWS-Prüfungen aus und liefert die Findings."""
    if not isinstance(data, dict):
        return []
    account = str(data.get("account_id", "AWS-Konto"))
    findings: list[Finding] = []
    findings += _analyze_root(data.get("root_account") or {}, account)
    findings += _analyze_password_policy(data.get("password_policy") or {}, account)
    for user in as_list(data.get("users")):
        if isinstance(user, dict):
            findings += _analyze_user(user, account)
    for role in as_list(data.get("roles")):
        if isinstance(role, dict):
            findings += _analyze_role(role, account)
    for bucket in as_list(data.get("s3_buckets")):
        if isinstance(bucket, dict):
            findings += _analyze_bucket(bucket, account)
    for sg in as_list(data.get("security_groups")):
        if isinstance(sg, dict):
            findings += _analyze_sg(sg, account)
    return findings
