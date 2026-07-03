"""Reiner Parser für echte AWS-CLI-Ausgaben -> Analyzer-Export.

Statt eines von Hand vorgeformten Exports akzeptiert Specter hier ein Bündel
aus den *unveränderten* Antworten der AWS CLI (PascalCase, wie `aws ... --output
json` sie liefert) und normalisiert sie deterministisch in die flache Struktur,
die der Offline-Analyzer `analyze_aws` erwartet. Die sicherheitsrelevante
Bewertung (öffentlich? MFA? offen ins Internet?) wird hier aus den Roh-Daten
*abgeleitet* — nicht vom Einreicher vorweggenommen.

Erwartetes Bündel (eine JSON-Datei, alle Schlüssel optional):

    {
      "account_id": "123456789012",            # oder caller_identity.Account
      "account_summary":  <aws iam get-account-summary>,
      "password_policy":  <aws iam get-account-password-policy>,
      "users": [
        {"User": <aws iam get-user>.User,      # oder direkt UserName
         "LoginProfile": <aws iam get-login-profile>.LoginProfile,
         "MFADevices": <aws iam list-mfa-devices>.MFADevices,
         "AttachedPolicies": <aws iam list-attached-user-policies>.AttachedPolicies,
         "AccessKeys": [<aws iam list-access-keys>.AccessKeyMetadata
                        + optional "AccessKeyLastUsed"]}
      ],
      "roles": [
        {"Role": <aws iam get-role>.Role,
         "AttachedPolicies": <aws iam list-attached-role-policies>.AttachedPolicies}
      ],
      "buckets": [
        {"Name": "...",
         "PolicyStatus": <aws s3api get-bucket-policy-status>.PolicyStatus,
         "Encryption": <aws s3api get-bucket-encryption> | null}
      ],
      "security_groups": <aws ec2 describe-security-groups>
    }

Zeitabhängige Ableitungen (Schlüssel-Alter, letzte Nutzung) rechnen gegen ein
injizierbares Referenzdatum (`now`), damit Tests und Benchmark deterministisch
bleiben.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from .analyzers.aws import SENSITIVE_PORTS

# CIDR-Notationen, die "offen für die ganze Welt" bedeuten.
_WORLD_CIDRS = {"0.0.0.0/0", "::/0"}


def _days_since(value: Any, now: date) -> int | None:
    """Tage seit einem ISO-Zeitstempel der CLI (z. B. '2024-01-01T00:00:00Z')."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        stamp = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return max(0, (now - stamp.date()).days)


def _policy_names(entries: Any) -> list[str]:
    """`AttachedPolicies`-Liste der CLI -> flache Policy-Namen."""
    out: list[str] = []
    if isinstance(entries, list):
        for e in entries:
            if isinstance(e, dict) and e.get("PolicyName"):
                out.append(str(e["PolicyName"]))
            elif isinstance(e, str) and e.strip():
                out.append(e)
    return out


def _principal_is_world(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        aws = principal.get("AWS")
        if aws == "*":
            return True
        if isinstance(aws, list) and "*" in aws:
            return True
    return False


def _trust_from_document(doc: Any) -> str:
    """Leitet aus dem echten AssumeRolePolicyDocument die Vertrauensweite ab."""
    if not isinstance(doc, dict):
        return ""
    statements = doc.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return ""
    for st in statements:
        if not isinstance(st, dict):
            continue
        if str(st.get("Effect", "")).lower() != "allow":
            continue
        if _principal_is_world(st.get("Principal")):
            return "*"
    return ""


def _normalize_user(raw: dict[str, Any], now: date) -> dict[str, Any]:
    inner = raw.get("User") if isinstance(raw.get("User"), dict) else {}
    user: dict[str, Any] = {
        "name": str(inner.get("UserName") or raw.get("UserName") or "iam-user"),
        "console_access": bool(raw.get("LoginProfile")),
    }
    if "MFADevices" in raw:
        devices = raw.get("MFADevices")
        user["mfa_enabled"] = bool(devices) if isinstance(devices, list) else False
    if "AttachedPolicies" in raw:
        user["attached_policies"] = _policy_names(raw.get("AttachedPolicies"))
    keys_raw = raw.get("AccessKeys")
    if isinstance(keys_raw, list):
        keys: list[dict[str, Any]] = []
        for k in keys_raw:
            if not isinstance(k, dict):
                continue
            entry: dict[str, Any] = {"id": str(k.get("AccessKeyId") or "")}
            age = _days_since(k.get("CreateDate"), now)
            if age is not None:
                entry["age_days"] = age
            last_used = k.get("AccessKeyLastUsed")
            if isinstance(last_used, dict):
                used = _days_since(last_used.get("LastUsedDate"), now)
                if used is not None:
                    entry["last_used_days"] = used
            keys.append(entry)
        user["access_keys"] = keys
    return user


def _normalize_role(raw: dict[str, Any]) -> dict[str, Any]:
    inner = raw.get("Role") if isinstance(raw.get("Role"), dict) else {}
    role: dict[str, Any] = {
        "name": str(inner.get("RoleName") or raw.get("RoleName") or "iam-role"),
        "trust": _trust_from_document(inner.get("AssumeRolePolicyDocument")
                                      or raw.get("AssumeRolePolicyDocument")),
    }
    if "AttachedPolicies" in raw:
        role["attached_policies"] = _policy_names(raw.get("AttachedPolicies"))
    return role


def _normalize_bucket(raw: dict[str, Any]) -> dict[str, Any]:
    bucket: dict[str, Any] = {"name": str(raw.get("Name") or "s3-bucket")}
    status = raw.get("PolicyStatus")
    if isinstance(status, dict) and "IsPublic" in status:
        bucket["public"] = bool(status.get("IsPublic"))
    if "Encryption" in raw:
        enc = raw.get("Encryption")
        bucket["encryption"] = bool(
            isinstance(enc, dict) and enc.get("ServerSideEncryptionConfiguration")
        )
    return bucket


def _open_ports(permission: dict[str, Any]) -> list[int]:
    """Weltoffene Ports einer einzelnen IpPermission (echte CLI-Struktur)."""
    world = any(
        isinstance(r, dict) and r.get("CidrIp") in _WORLD_CIDRS
        for r in permission.get("IpRanges") or []
    ) or any(
        isinstance(r, dict) and r.get("CidrIpv6") in _WORLD_CIDRS
        for r in permission.get("Ipv6Ranges") or []
    )
    if not world:
        return []
    if str(permission.get("IpProtocol", "")) == "-1":
        # "Alle Protokolle": die sicherheitskritischen Ports gelten als offen.
        return sorted(SENSITIVE_PORTS)
    try:
        from_port = int(permission.get("FromPort"))
        to_port = int(permission.get("ToPort", from_port))
    except (TypeError, ValueError):
        return []
    ports = {from_port}
    ports.update(p for p in SENSITIVE_PORTS if from_port <= p <= to_port)
    return sorted(ports)


def _normalize_sg(raw: dict[str, Any]) -> dict[str, Any]:
    ports: list[int] = []
    for perm in raw.get("IpPermissions") or []:
        if isinstance(perm, dict):
            ports += _open_ports(perm)
    return {
        "name": str(raw.get("GroupName") or raw.get("GroupId") or "sg"),
        "open_to_world_ports": sorted(set(ports)),
    }


def looks_like_raw_aws(data: Any) -> bool:
    """Erkennt ein Bündel echter AWS-CLI-Antworten (PascalCase-Marker).

    Der bereits normalisierte Analyzer-Export (kleingeschriebene Felder wie
    ``root_account``/``s3_buckets``) wird nie als roh eingestuft.
    """
    if not isinstance(data, dict):
        return False
    if isinstance(data.get("account_summary"), dict) and \
            "SummaryMap" in data["account_summary"]:
        return True
    if isinstance(data.get("password_policy"), dict) and \
            "PasswordPolicy" in data["password_policy"]:
        return True
    sgs = data.get("security_groups")
    if isinstance(sgs, dict) and "SecurityGroups" in sgs:
        return True
    if isinstance(sgs, list) and any(
            isinstance(g, dict) and ("IpPermissions" in g or "GroupName" in g)
            for g in sgs):
        return True
    for key in ("users", "roles"):
        entries = data.get(key)
        if isinstance(entries, list) and any(
                isinstance(e, dict) and
                ("User" in e or "UserName" in e or "Role" in e or "RoleName" in e)
                for e in entries):
            return True
    return isinstance(data.get("buckets"), list)


def normalize_aws_bundle(data: dict[str, Any], *,
                         now: date | None = None) -> dict[str, Any]:
    """Wandelt ein Bündel echter AWS-CLI-Antworten in den Analyzer-Export."""
    if not isinstance(data, dict):
        return {}
    ref = now or date.today()
    out: dict[str, Any] = {}

    caller = data.get("caller_identity")
    account = data.get("account_id") or (
        caller.get("Account") if isinstance(caller, dict) else None)
    if account:
        out["account_id"] = str(account)

    summary = data.get("account_summary")
    if isinstance(summary, dict) and isinstance(summary.get("SummaryMap"), dict):
        sm = summary["SummaryMap"]
        root: dict[str, Any] = {}
        if "AccountMFAEnabled" in sm:
            root["mfa_enabled"] = bool(sm.get("AccountMFAEnabled"))
        if "AccountAccessKeysPresent" in sm:
            try:
                root["access_keys"] = int(sm.get("AccountAccessKeysPresent"))
            except (TypeError, ValueError):
                pass
        if root:
            out["root_account"] = root

    policy_wrap = data.get("password_policy")
    if isinstance(policy_wrap, dict) and \
            isinstance(policy_wrap.get("PasswordPolicy"), dict):
        pp = policy_wrap["PasswordPolicy"]
        policy: dict[str, Any] = {}
        if "MinimumPasswordLength" in pp:
            policy["minimum_length"] = pp.get("MinimumPasswordLength")
        if "RequireSymbols" in pp:
            policy["require_symbols"] = pp.get("RequireSymbols")
        # Ohne Ablauf-Pflicht laufen Passwörter nie ab (max_age_days=0).
        if pp.get("ExpirePasswords"):
            if "MaxPasswordAge" in pp:
                policy["max_age_days"] = pp.get("MaxPasswordAge")
        else:
            policy["max_age_days"] = 0
        if policy:
            out["password_policy"] = policy

    users = data.get("users")
    if isinstance(users, list):
        out["users"] = [_normalize_user(u, ref) for u in users
                        if isinstance(u, dict)]

    roles = data.get("roles")
    if isinstance(roles, list):
        out["roles"] = [_normalize_role(r) for r in roles if isinstance(r, dict)]

    buckets = data.get("buckets")
    if isinstance(buckets, list):
        out["s3_buckets"] = [_normalize_bucket(b) for b in buckets
                             if isinstance(b, dict)]

    sgs = data.get("security_groups")
    if isinstance(sgs, dict):
        sgs = sgs.get("SecurityGroups")
    if isinstance(sgs, list):
        out["security_groups"] = [_normalize_sg(g) for g in sgs
                                  if isinstance(g, dict)]
    return out


def coerce_aws_export(data: Any) -> Any:
    """Normalisiert rohe AWS-CLI-Bündel; alles andere bleibt unverändert."""
    if looks_like_raw_aws(data):
        return normalize_aws_bundle(data)
    return data
