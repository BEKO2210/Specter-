"""Tests für den AWS-CLI-Roh-Normalisierer (offline, deterministisch)."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

from specter.analyzers.aws import analyze_aws
from specter.aws_raw import (
    coerce_aws_export,
    looks_like_raw_aws,
    normalize_aws_bundle,
)

_NOW = date(2026, 7, 1)

# Das mitgelieferte Beispiel-Bündel ist zugleich Test-Fixture: was wir
# dokumentieren, muss auch funktionieren.
_EXAMPLE = json.loads(
    (Path(__file__).parent.parent / "examples" / "data"
     / "aws_cli_export.example.json").read_text(encoding="utf-8"))


def test_normalize_full_bundle_end_to_end():
    export = normalize_aws_bundle(_EXAMPLE, now=_NOW)
    assert export["account_id"] == "123456789012"
    assert export["root_account"] == {"mfa_enabled": False, "access_keys": 1}
    assert export["password_policy"] == {
        "minimum_length": 8, "require_symbols": False, "max_age_days": 0}

    deploy, backup = export["users"]
    assert deploy["name"] == "deploy-bot"
    assert deploy["console_access"] is True
    assert deploy["mfa_enabled"] is False
    assert deploy["attached_policies"] == ["AdministratorAccess"]
    key = deploy["access_keys"][0]
    assert key["id"] == "AKIAEXAMPLE111"
    assert key["age_days"] == (_NOW - date(2024, 5, 1)).days
    assert key["last_used_days"] == (_NOW - date(2024, 7, 1)).days
    assert backup["console_access"] is False and backup["mfa_enabled"] is True

    role = export["roles"][0]
    assert role["name"] == "ci-deploy" and role["trust"] == "*"
    assert role["attached_policies"] == ["AdministratorAccess"]

    pub, priv = export["s3_buckets"]
    assert pub == {"name": "mustermann-kunden-backups", "public": True,
                   "encryption": False}
    assert priv["public"] is False and priv["encryption"] is True

    db_sg, web_sg = export["security_groups"]
    assert db_sg == {"name": "db-sg", "open_to_world_ports": [22]}
    assert web_sg == {"name": "web-sg", "open_to_world_ports": [443]}

    # Und der echte Analyzer erkennt die Risiken aus den Roh-Daten.
    titles = " ".join(f.title for f in analyze_aws(export))
    assert "Root-Konto ohne MFA" in titles
    assert "Root-Konto besitzt Access-Keys" in titles
    assert "Schwache IAM-Passwort-Policy" in titles
    assert "IAM-Konsolenzugriff ohne MFA: deploy-bot" in titles
    assert "Überprivilegierter IAM-User (Admin): deploy-bot" in titles
    assert "Alter Access-Key" in titles
    assert "Admin-Rolle von beliebigem Prinzipal annehmbar: ci-deploy" in titles
    assert "Öffentlicher S3-Bucket: mustermann-kunden-backups" in titles
    assert "Port 22" in titles


def test_detection_accepts_raw_and_rejects_normalized():
    assert looks_like_raw_aws(_EXAMPLE) is True
    # Einzelne Marker reichen.
    assert looks_like_raw_aws(
        {"account_summary": {"SummaryMap": {"AccountMFAEnabled": 1}}}) is True
    assert looks_like_raw_aws(
        {"password_policy": {"PasswordPolicy": {}}}) is True
    assert looks_like_raw_aws(
        {"security_groups": {"SecurityGroups": []}}) is True
    assert looks_like_raw_aws(
        {"security_groups": [{"GroupName": "sg", "IpPermissions": []}]}) is True
    assert looks_like_raw_aws({"users": [{"UserName": "a"}]}) is True
    assert looks_like_raw_aws({"roles": [{"RoleName": "r"}]}) is True
    assert looks_like_raw_aws({"buckets": []}) is True
    # Der normalisierte Export darf NICHT als roh eingestuft werden.
    normalized = {
        "root_account": {"mfa_enabled": False},
        "password_policy": {"minimum_length": 8},
        "users": [{"name": "deploy", "mfa_enabled": False}],
        "security_groups": [{"name": "db-sg", "open_to_world_ports": [22]}],
        "s3_buckets": [{"name": "b", "public": True}],
    }
    assert looks_like_raw_aws(normalized) is False
    assert looks_like_raw_aws("nope") is False
    assert looks_like_raw_aws({}) is False


def test_coerce_normalizes_raw_and_passes_through():
    coerced = coerce_aws_export(_EXAMPLE)
    assert coerced["root_account"]["mfa_enabled"] is False
    normalized = {"root_account": {"mfa_enabled": False}}
    assert coerce_aws_export(normalized) is normalized


def test_password_policy_with_expiry_and_summary_junk():
    export = normalize_aws_bundle({
        "account_summary": {"SummaryMap": {
            "AccountMFAEnabled": 1, "AccountAccessKeysPresent": "kaputt"}},
        "password_policy": {"PasswordPolicy": {
            "MinimumPasswordLength": 16, "RequireSymbols": True,
            "ExpirePasswords": True, "MaxPasswordAge": 90}},
    }, now=_NOW)
    # Kaputter Zähler wird verworfen, MFA bleibt erhalten.
    assert export["root_account"] == {"mfa_enabled": True}
    assert export["password_policy"]["max_age_days"] == 90
    # Ablauf-Pflicht ohne MaxPasswordAge: kein max_age_days-Feld.
    export2 = normalize_aws_bundle({
        "password_policy": {"PasswordPolicy": {"ExpirePasswords": True}}},
        now=_NOW)
    assert "password_policy" not in export2


def test_user_edge_cases():
    export = normalize_aws_bundle({"users": [
        # Nackter UserName, MFADevices falsch typisiert, Key ohne LastUsed.
        {"UserName": "roh", "MFADevices": "kaputt",
         "AccessKeys": [{"AccessKeyId": "AKIA3", "CreateDate": "2026-06-01T00:00:00Z"},
                        "junk"]},
        # Ohne alles: Default-Name, kein MFA-Feld.
        {},
        "junk",
    ]}, now=_NOW)
    roh, leer = export["users"]
    assert roh["name"] == "roh" and roh["mfa_enabled"] is False
    assert roh["access_keys"] == [{"id": "AKIA3", "age_days": 30}]
    assert leer["name"] == "iam-user" and "mfa_enabled" not in leer
    # Fehlendes last_used_days => der Analyzer meldet den Key als ungenutzt.
    titles = " ".join(f.title for f in analyze_aws(export))
    assert "Ungenutzter Access-Key: roh [AKIA3]" in titles


def test_role_trust_variants():
    def trust(doc):
        return normalize_aws_bundle(
            {"roles": [{"Role": {"RoleName": "r",
                                 "AssumeRolePolicyDocument": doc}}]},
        )["roles"][0]["trust"]

    assert trust({"Statement": {"Effect": "Allow", "Principal": "*"}}) == "*"
    assert trust({"Statement": [{"Effect": "Allow",
                                 "Principal": {"AWS": ["*"]}}]}) == "*"
    # Deny-Statement mit '*' öffnet nichts; Service-Principal auch nicht.
    assert trust({"Statement": [{"Effect": "Deny", "Principal": "*"}]}) == ""
    assert trust({"Statement": [
        {"Effect": "Allow",
         "Principal": {"Service": "ec2.amazonaws.com"}}]}) == ""
    assert trust({"Statement": ["junk", 5]}) == ""
    assert trust("kein-dict") == ""
    assert trust({"Statement": "kaputt"}) == ""


def test_bucket_without_status_or_encryption_stays_unbewertet():
    export = normalize_aws_bundle({"buckets": [{"Name": "nur-name"}]})
    # Ohne PolicyStatus/Encryption-Daten wird nichts unterstellt.
    assert export["s3_buckets"] == [{"name": "nur-name"}]
    assert analyze_aws(export) == []


def test_security_group_variants():
    export = normalize_aws_bundle({"security_groups": [
        # Alle Protokolle weltoffen -> sensible Ports gelten als offen.
        {"GroupName": "any", "IpPermissions": [
            {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]},
        # Portbereich enthält sensible Ports (3306 MySQL, 3389 RDP).
        {"GroupName": "range", "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 3300, "ToPort": 3400,
             "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]},
        # Weltoffen, aber FromPort fehlt/kaputt -> keine Port-Ableitung.
        {"GroupName": "kaputt", "IpPermissions": [
            {"IpProtocol": "tcp", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            "junk"]},
        # Nur intern offen -> nichts.
        {"GroupId": "sg-0815", "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
             "IpRanges": [{"CidrIp": "10.0.0.0/8"}, "junk"]}]},
    ]})
    any_sg, range_sg, kaputt, intern = export["security_groups"]
    assert 3389 in any_sg["open_to_world_ports"]
    assert range_sg["open_to_world_ports"] == [3300, 3306, 3389]
    assert kaputt["open_to_world_ports"] == []
    assert intern == {"name": "sg-0815", "open_to_world_ports": []}


def test_defensive_top_level_and_dates():
    assert normalize_aws_bundle("kein-dict") == {}
    assert normalize_aws_bundle({}) == {}
    # caller_identity als Konto-Quelle; kaputte Zeitstempel werden verworfen.
    export = normalize_aws_bundle({
        "caller_identity": {"Account": "999888777666"},
        "users": [{"UserName": "u", "AccessKeys": [
            {"AccessKeyId": "A", "CreateDate": "gestern"},
            {"AccessKeyId": "B", "CreateDate": 42}]}],
        "account_summary": {"SummaryMap": "kaputt"},
        "password_policy": {"PasswordPolicy": "kaputt"},
        "security_groups": {"SecurityGroups": "kaputt"},
        "roles": "kaputt",
        "buckets": "kaputt",
    }, now=_NOW)
    assert export["account_id"] == "999888777666"
    assert export["users"][0]["access_keys"] == [{"id": "A"}, {"id": "B"}]
    assert "root_account" not in export and "password_policy" not in export
    assert "security_groups" not in export
    # Zeitstempel in der Zukunft werden auf 0 Tage gekappt.
    export2 = normalize_aws_bundle({"users": [{"UserName": "u", "AccessKeys": [
        {"AccessKeyId": "C", "CreateDate": "2030-01-01T00:00:00Z"}]}]}, now=_NOW)
    assert export2["users"][0]["access_keys"][0]["age_days"] == 0


def test_policy_names_mixed_types():
    export = normalize_aws_bundle({"users": [{
        "UserName": "u",
        "AttachedPolicies": [{"PolicyName": "AdministratorAccess"},
                             "ReadOnly", {"kein": "name"}, 5],
    }]})
    assert export["users"][0]["attached_policies"] == [
        "AdministratorAccess", "ReadOnly"]
