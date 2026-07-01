"""Tests fuer die Offline-Analyzer (Active Directory, Exchange)."""

from __future__ import annotations

import json

from specter.analyzers.active_directory import (
    analyze_ad, normalize_bloodhound_users,
)
from specter.analyzers.entra_id import analyze_entra
from specter.analyzers.exchange import analyze_exchange
from specter.findings import Severity


# ============================ Active Directory ============================

def _cats(findings):
    return {f.category for f in findings}


def test_ad_weak_password_policy():
    data = {"domain": "corp.de", "password_policy": {
        "min_length": 8, "complexity": False, "lockout_threshold": 0,
        "max_age_days": 0, "history_length": 2}}
    findings = analyze_ad(data)
    titles = " ".join(f.title for f in findings)
    assert "Mindestlaenge" in titles
    assert "Komplexitaet" in titles
    assert "Lockout" in titles
    assert all(f.category == "auth_weakness" for f in findings)


def test_ad_strong_policy_no_findings():
    data = {"domain": "corp.de", "password_policy": {
        "min_length": 14, "complexity": True, "lockout_threshold": 5,
        "max_age_days": 90, "history_length": 24}}
    assert analyze_ad(data) == []


def test_ad_krbtgt_old():
    findings = analyze_ad({"domain": "corp.de", "krbtgt_password_age_days": 1200})
    assert any("krbtgt" in f.title for f in findings)
    assert findings[0].severity is Severity.HOCH


def test_ad_too_many_domain_admins():
    data = {"domain": "corp.de", "privileged_groups": {"Domain Admins": ["u"] * 15}}
    findings = analyze_ad(data)
    assert any("privilegierte Konten" in f.title for f in findings)
    assert findings[0].category == "access_control"


def test_ad_privileged_group_non_list_ignored():
    # Fehlerhafte Struktur (kein Listenwert) wird robust uebersprungen.
    data = {"domain": "corp.de", "privileged_groups": {"Domain Admins": "kaputt"}}
    assert analyze_ad(data) == []


def test_ad_privileged_never_expires():
    data = {"domain": "corp.de", "users": [{
        "name": "admin1", "enabled": True, "privileged": True,
        "password_never_expires": True}]}
    findings = analyze_ad(data)
    assert any("nie ablaufendem Passwort" in f.title for f in findings)


def test_ad_stale_account():
    data = {"domain": "corp.de", "users": [{
        "name": "alt", "enabled": True, "last_logon_days": 400}]}
    findings = analyze_ad(data)
    assert any("ungenutztes Konto" in f.title for f in findings)


def test_ad_disabled_but_privileged():
    data = {"domain": "corp.de", "users": [{
        "name": "exadmin", "enabled": False, "groups": ["Domain Admins"]}]}
    findings = analyze_ad(data)
    assert any("Deaktiviertes Konto" in f.title for f in findings)


def test_ad_spn_and_asrep():
    data = {"domain": "corp.de", "users": [{
        "name": "svc", "enabled": True, "service_principal_names": ["MSSQL/db"],
        "kerberos_preauth": False}]}
    findings = analyze_ad(data)
    assert any("SPN" in f.title for f in findings)
    assert any("AS-REP" in f.title for f in findings)


def test_ad_adminsdholder_leftover():
    data = {"domain": "corp.de", "users": [{
        "name": "old", "enabled": True, "admin_count": 1, "groups": []}]}
    findings = analyze_ad(data)
    assert any("AdminSDHolder" in f.title for f in findings)


def test_ad_invalid_input():
    assert analyze_ad("kein dict") == []
    assert analyze_ad({}) == []


def test_bloodhound_normalizer():
    bh = {"meta": {"type": "users"}, "data": [
        {"Properties": {"name": "SVC@CORP", "enabled": True, "admincount": True,
                        "pwdneverexpires": True, "dontreqpreauth": True,
                        "serviceprincipalnames": ["MSSQL/db"]},
         "ObjectIdentifier": "S-1-5-..."}]}
    users = normalize_bloodhound_users(bh)
    assert len(users) == 1
    assert users[0]["name"] == "SVC@CORP"
    assert users[0]["kerberos_preauth"] is False    # dontreqpreauth invertiert
    # Ueber analyze_ad direkt verwendbar (Auto-Erkennung).
    findings = analyze_ad(bh)
    assert any("AS-REP" in f.title or "SPN" in f.title for f in findings)


def test_bloodhound_normalizer_invalid():
    assert normalize_bloodhound_users("x") == []
    assert normalize_bloodhound_users({"data": "nope"}) == []
    assert normalize_bloodhound_users({"data": [{"Properties": {}}]}) == []


# ================================ Exchange ================================

def test_exchange_outdated_build():
    data = {"host": "mail.de", "product": "Exchange 2016", "build": "15.1.2000.1"}
    findings = analyze_exchange(data)
    assert any("Veraltete Exchange" in f.title for f in findings)
    assert findings[0].severity is Severity.KRITISCH
    assert "ProxyLogon" in findings[0].evidence


def test_exchange_eol():
    findings = analyze_exchange({"host": "mail.de", "build": "14.3.123.0"})
    assert any("End-of-Life" in f.title for f in findings)


def test_exchange_patched_build_ok():
    findings = analyze_exchange({"host": "mail.de", "build": "15.1.2600.10"})
    assert findings == []


def test_exchange_ecp_exposed():
    findings = analyze_exchange({"host": "mail.de",
                                 "external_services": ["OWA", "ECP", "Autodiscover"]})
    cats = _cats(findings)
    assert any("ECP" in f.title for f in findings)
    assert "misconfiguration" in cats and "exposed_service" in cats


def test_exchange_weak_tls():
    findings = analyze_exchange({"host": "mail.de",
                                 "tls": {"protocols": ["TLSv1.0", "TLSv1.2"]}})
    assert any("TLS" in f.title for f in findings)
    assert findings[0].category == "transport_security"


def test_exchange_missing_headers_and_banner():
    findings = analyze_exchange({"host": "mail.de",
                                 "headers": {"Strict-Transport-Security": None,
                                             "X-Frame-Options": "DENY",
                                             "X-Content-Type-Options": None},
                                 "server_header": "Microsoft-IIS/10.0"})
    titles = " ".join(f.title for f in findings)
    assert "HSTS" in titles
    assert "X-Content-Type-Options" in titles
    assert "X-Frame-Options" not in titles          # ist gesetzt
    assert "Server-Header" in titles


def test_exchange_invalid_input_and_bad_build():
    assert analyze_exchange("x") == []
    assert analyze_exchange({"host": "m", "build": "keine-zahl"}) == []
    assert analyze_exchange({"host": "m", "build": "15.1"}) == []


def test_exchange_clean():
    data = {"host": "mail.de", "build": "15.2.1600.5", "external_services": [],
            "tls": {"protocols": ["TLSv1.2", "TLSv1.3"]},
            "headers": {"Strict-Transport-Security": "max-age=31536000",
                        "X-Frame-Options": "DENY",
                        "X-Content-Type-Options": "nosniff"}}
    assert analyze_exchange(data) == []


# ============================== Entra ID / M365 ===========================

def test_entra_no_baseline_protection():
    data = {"tenant": "contoso.de", "security_defaults_enabled": False,
            "conditional_access_policies": []}
    findings = analyze_entra(data)
    titles = " ".join(f.title for f in findings)
    assert "Weder Security Defaults noch Conditional Access" in titles
    assert "Keine MFA-Erzwingung" in titles


def test_entra_legacy_auth_not_blocked():
    data = {"tenant": "contoso.de", "security_defaults_enabled": True,
            "legacy_auth_allowed": True,
            "conditional_access_policies": [
                {"name": "MFA", "state": "enabled", "requires_mfa": True,
                 "blocks_legacy_auth": False}]}
    findings = analyze_entra(data)
    assert any("Legacy-Authentifizierung nicht blockiert" in f.title for f in findings)


def test_entra_too_many_global_admins():
    data = {"tenant": "contoso.de", "security_defaults_enabled": True,
            "conditional_access_policies": [
                {"state": "enabled", "requires_mfa": True}],
            "roles": {"Global Administrator": [f"a{i}@x" for i in range(9)]}}
    findings = analyze_entra(data)
    assert any("Zu viele Konten in 'Global Administrator'" in f.title for f in findings)


def test_entra_privileged_without_mfa_is_critical():
    data = {"tenant": "contoso.de", "security_defaults_enabled": True,
            "conditional_access_policies": [{"state": "enabled", "requires_mfa": True}],
            "users": [{"upn": "admin@x", "enabled": True, "privileged": True,
                       "mfa_registered": False}]}
    findings = analyze_entra(data)
    crit = [f for f in findings if f.severity is Severity.KRITISCH]
    assert crit and "ohne MFA" in crit[0].title


def test_entra_normal_user_without_mfa_is_medium():
    data = {"tenant": "contoso.de", "security_defaults_enabled": True,
            "conditional_access_policies": [{"state": "enabled", "requires_mfa": True}],
            "users": [{"upn": "user@x", "enabled": True, "mfa_registered": False}]}
    findings = analyze_entra(data)
    assert any(f.severity is Severity.MITTEL and "ohne MFA" in f.title for f in findings)


def test_entra_stale_guest():
    data = {"tenant": "contoso.de", "security_defaults_enabled": True,
            "conditional_access_policies": [{"state": "enabled", "requires_mfa": True}],
            "users": [{"upn": "gast@extern", "enabled": True, "guest": True,
                       "mfa_registered": True, "last_sign_in_days": 200}]}
    findings = analyze_entra(data)
    assert any("Inaktives Gastkonto" in f.title for f in findings)


def test_entra_overprivileged_app():
    data = {"tenant": "contoso.de", "security_defaults_enabled": True,
            "conditional_access_policies": [{"state": "enabled", "requires_mfa": True}],
            "app_registrations": [
                {"name": "Legacy Sync", "admin_consent": True,
                 "high_privilege_permissions": ["Directory.ReadWrite.All"]}]}
    findings = analyze_entra(data)
    assert any("Ueberprivilegierte App" in f.title for f in findings)


def test_entra_anonymous_sharing():
    data = {"tenant": "contoso.de", "security_defaults_enabled": True,
            "conditional_access_policies": [{"state": "enabled", "requires_mfa": True}],
            "sharing": {"anonymous_links_enabled": True}}
    findings = analyze_entra(data)
    assert any(f.category == "personal_data" for f in findings)


def test_entra_invalid_input_and_non_list_role():
    assert analyze_entra("x") == []
    data = {"tenant": "contoso.de", "security_defaults_enabled": True,
            "conditional_access_policies": [{"state": "enabled", "requires_mfa": True}],
            "roles": {"Global Administrator": "kaputt"}}
    assert analyze_entra(data) == []


def test_entra_non_dict_app_ignored():
    # Fehlerhafte App-Struktur (kein Dict) wird robust uebersprungen.
    data = {"tenant": "contoso.de", "security_defaults_enabled": True,
            "conditional_access_policies": [{"state": "enabled", "requires_mfa": True}],
            "app_registrations": ["kaputt", None]}
    assert analyze_entra(data) == []


def test_entra_clean_tenant():
    data = {"tenant": "contoso.de", "security_defaults_enabled": True,
            "legacy_auth_allowed": False,
            "conditional_access_policies": [
                {"name": "Block Legacy + MFA", "state": "enabled",
                 "requires_mfa": True, "blocks_legacy_auth": True}],
            "roles": {"Global Administrator": ["a@x", "b@x"]},
            "users": [{"upn": "admin@x", "enabled": True, "privileged": True,
                       "mfa_registered": True}],
            "app_registrations": [],
            "sharing": {"anonymous_links_enabled": False}}
    assert analyze_entra(data) == []
