"""Tests fuer die Offline-Analyzer (Active Directory, Exchange)."""

from __future__ import annotations

import json

from specter.analyzers.active_directory import (
    analyze_ad, normalize_bloodhound_users,
)
from specter.analyzers.aws import analyze_aws
from specter.analyzers.azure import analyze_azure
from specter.analyzers.backup import analyze_backup
from specter.analyzers.dependency import (
    _satisfies, _split_op, analyze_dependencies,
)
from specter.analyzers.email_security import analyze_email_security
from specter.analyzers.entra_id import analyze_entra
from specter.analyzers.exchange import analyze_exchange
from specter.analyzers.firewall import analyze_firewall
from specter.analyzers.http_headers import analyze_http_headers
from specter.analyzers.tls_certificates import analyze_tls
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


# ================================== AWS ===================================

def test_aws_root_without_mfa_and_keys():
    findings = analyze_aws({"account_id": "123", "root_account": {
        "mfa_enabled": False, "access_keys": 1}})
    titles = " ".join(f.title for f in findings)
    assert "Root-Konto ohne MFA" in titles
    assert "Access-Keys" in titles
    assert all(f.severity is Severity.KRITISCH for f in findings)


def test_aws_weak_password_policy():
    findings = analyze_aws({"account_id": "123", "password_policy": {
        "minimum_length": 8, "require_symbols": False, "max_age_days": 0}})
    assert any("Passwort-Policy" in f.title or "Passwoerter" in f.title for f in findings)


def test_aws_overprivileged_user_and_no_mfa():
    findings = analyze_aws({"account_id": "123", "users": [{
        "name": "deploy", "console_access": True, "mfa_enabled": False,
        "attached_policies": ["AdministratorAccess"]}]})
    titles = " ".join(f.title for f in findings)
    assert "Konsolenzugriff ohne MFA" in titles
    assert "Ueberprivilegierter IAM-User" in titles


def test_aws_old_and_unused_access_key():
    findings = analyze_aws({"account_id": "123", "users": [{
        "name": "svc", "access_keys": [{"age_days": 400, "last_used_days": 300}]}]})
    titles = " ".join(f.title for f in findings)
    assert "Alter Access-Key" in titles
    assert "Ungenutzter Access-Key" in titles


def test_aws_role_wildcard_trust():
    findings = analyze_aws({"account_id": "123", "roles": [
        {"name": "open", "trust": "*"},
        {"name": "admin", "trust": "*", "attached_policies": ["AdministratorAccess"]}]})
    sevs = {f.title: f.severity for f in findings}
    assert any("beliebigem Prinzipal" in t for t in sevs)
    assert any(s is Severity.KRITISCH for s in sevs.values())


def test_aws_public_and_unencrypted_bucket():
    findings = analyze_aws({"account_id": "123", "s3_buckets": [
        {"name": "kunden-backups", "public": True, "encryption": False}]})
    cats = {f.category for f in findings}
    assert "cloud_storage" in cats and "misconfiguration" in cats


def test_aws_security_group_sensitive_port():
    findings = analyze_aws({"account_id": "123", "security_groups": [
        {"name": "db", "open_to_world_ports": [3306, 8080, "kaputt"]}]})
    ports_hoch = [f for f in findings if f.severity is Severity.HOCH]
    ports_mittel = [f for f in findings if f.severity is Severity.MITTEL]
    assert ports_hoch and ports_mittel        # 3306 hoch, 8080 mittel, kaputt ignoriert


def test_aws_non_dict_access_key_ignored():
    findings = analyze_aws({"account_id": "123", "users": [{
        "name": "svc", "access_keys": ["kaputt", None]}]})
    assert findings == []


def test_aws_role_normal_trust_no_finding():
    findings = analyze_aws({"account_id": "123", "roles": [{
        "name": "app", "trust": "arn:aws:iam::123:root",
        "attached_policies": ["ReadOnlyAccess"]}]})
    assert findings == []


def test_aws_invalid_input_and_empty():
    assert analyze_aws("x") == []
    assert analyze_aws({}) == []
    # Nicht-Dict-Elemente werden robust uebersprungen.
    assert analyze_aws({"users": ["kaputt"], "roles": [None],
                        "s3_buckets": [1], "security_groups": ["x"]}) == []


# ================================= Azure ==================================

def test_azure_storage_all_issues():
    findings = analyze_azure({"subscription_id": "sub-1", "storage_accounts": [
        {"name": "sa1", "public_blob_access": True, "https_only": False,
         "encryption": False, "min_tls": "TLS1.0"}]})
    cats = {f.category for f in findings}
    assert cats == {"cloud_storage", "transport_security", "misconfiguration"}
    assert any("Oeffentlicher Blob-Zugriff" in f.title for f in findings)
    assert any(f.severity is Severity.HOCH for f in findings)


def test_azure_storage_clean_no_findings():
    findings = analyze_azure({"storage_accounts": [
        {"name": "ok", "public_blob_access": False, "https_only": True,
         "encryption": True, "min_tls": "TLS1.2"}]})
    assert findings == []


def test_azure_nsg_sensitive_and_normal_ports():
    findings = analyze_azure({"network_security_groups": [
        {"name": "nsg-db", "open_to_internet_ports": [3389, 8080, "kaputt", None]}]})
    hoch = [f for f in findings if f.severity is Severity.HOCH]
    mittel = [f for f in findings if f.severity is Severity.MITTEL]
    assert len(hoch) == 1 and len(mittel) == 1     # 3389 hoch, 8080 mittel, Rest ignoriert
    assert all(f.category == "exposed_service" for f in findings)


def test_azure_vm_public_outdated_and_unencrypted():
    findings = analyze_azure({"virtual_machines": [
        {"name": "vm1", "public_ip": True, "disk_encryption": False,
         "os": "Windows Server 2012"}]})
    cats = {f.category for f in findings}
    assert cats == {"exposed_service", "outdated_component", "misconfiguration"}
    assert any(f.severity is Severity.HOCH for f in findings)


def test_azure_vm_modern_clean():
    findings = analyze_azure({"virtual_machines": [
        {"name": "vm2", "public_ip": False, "disk_encryption": True,
         "os": "Windows Server 2022"}]})
    assert findings == []


def test_azure_key_vault_issues():
    findings = analyze_azure({"key_vaults": [
        {"name": "kv1", "public_network_access": True, "purge_protection": False}]})
    titles = " ".join(f.title for f in findings)
    assert "Key Vault oeffentlich erreichbar" in titles
    assert "Purge-Protection" in titles
    assert any(f.severity is Severity.HOCH for f in findings)


def test_azure_key_vault_clean():
    findings = analyze_azure({"key_vaults": [
        {"name": "kv2", "public_network_access": False, "purge_protection": True}]})
    assert findings == []


def test_azure_sql_public_and_no_tde():
    findings = analyze_azure({"sql_servers": [
        {"name": "sql1", "public_access": True, "tde_enabled": False}]})
    cats = {f.category for f in findings}
    assert cats == {"exposed_service", "crypto_weakness"}


def test_azure_sql_clean():
    findings = analyze_azure({"sql_servers": [
        {"name": "sql2", "public_access": False, "tde_enabled": True}]})
    assert findings == []


def test_azure_rbac_too_many_owners():
    owners = [{"principal": f"u{i}@x", "role": "Owner", "scope": "subscription"}
              for i in range(4)]
    findings = analyze_azure({"subscription_id": "sub-x", "role_assignments": owners})
    assert len(findings) == 1
    assert findings[0].category == "access_control"
    assert findings[0].severity is Severity.HOCH


def test_azure_rbac_within_limit_no_finding():
    owners = [{"principal": f"u{i}@x", "role": "Owner", "scope": "subscription"}
              for i in range(3)]
    findings = analyze_azure({"role_assignments": owners})
    assert findings == []


def test_azure_invalid_input_and_robust_skips():
    assert analyze_azure("x") == []
    assert analyze_azure({}) == []
    # Nicht-Dict-Elemente in allen Listen werden robust uebersprungen.
    assert analyze_azure({
        "storage_accounts": ["kaputt"], "network_security_groups": [None],
        "virtual_machines": [1], "key_vaults": ["x"], "sql_servers": [2],
        "role_assignments": ["nope", None]}) == []


# ============================ E-Mail-Security ==============================

def test_email_all_missing():
    findings = analyze_email_security({"domain": "x.de"})
    titles = " ".join(f.title for f in findings)
    assert "Kein SPF-Eintrag" in titles
    assert "Kein DMARC-Eintrag" in titles
    assert "Kein DKIM-Schluessel" in titles


def test_email_spf_weak_allall():
    findings = analyze_email_security({"domain": "x.de", "spf": "v=spf1 +all"})
    assert any("beliebige Absender" in f.title and f.severity is Severity.HOCH
               for f in findings)


def test_email_spf_no_all_mechanism():
    findings = analyze_email_security(
        {"domain": "x.de", "spf": "v=spf1 include:_spf.google.com"})
    assert any("ohne abschliessenden all-Mechanismus" in f.title
               and f.severity is Severity.MITTEL for f in findings)


def test_email_spf_strict_ok():
    # -all + gueltiges DMARC + starkes DKIM -> keine SPF/DMARC/DKIM-Befunde
    findings = analyze_email_security({
        "domain": "x.de",
        "spf": "v=spf1 include:_spf.google.com -all",
        "dmarc": "v=DMARC1; p=reject; rua=mailto:d@x.de",
        "dkim": [{"selector": "g", "key_bits": 2048, "present": True}]})
    assert findings == []


def test_email_dmarc_pnone_and_no_rua():
    findings = analyze_email_security(
        {"domain": "x.de", "spf": "v=spf1 -all", "dmarc": "v=DMARC1; p=none",
         "dkim": [{"selector": "g", "key_bits": 2048}]})
    titles = " ".join(f.title for f in findings)
    assert "Monitoring-Modus (p=none)" in titles
    assert "ohne Auswertungs-Reports" in titles


def test_email_dkim_weak_and_dated_keys():
    weak = analyze_email_security(
        {"domain": "x.de", "dkim": [{"selector": "s", "key_bits": 512}]})
    assert any("zu schwach" in f.title and f.severity is Severity.HOCH for f in weak)
    dated = analyze_email_security(
        {"domain": "x.de", "dkim": [{"selector": "s", "key_bits": 1024}]})
    assert any("nicht mehr zeitgemaess" in f.title and f.severity is Severity.NIEDRIG
               for f in dated)


def test_email_dkim_present_false_counts_as_missing():
    findings = analyze_email_security(
        {"domain": "x.de", "dkim": [{"selector": "old", "present": False}]})
    assert any("Kein DKIM-Schluessel" in f.title for f in findings)


def test_email_dkim_invalid_bits_ignored():
    # Nicht-numerische Bitangabe -> kein Krypto-Befund (robust).
    findings = analyze_email_security(
        {"domain": "x.de", "spf": "v=spf1 -all",
         "dmarc": "v=DMARC1; p=reject; rua=mailto:d@x.de",
         "dkim": [{"selector": "s", "key_bits": "kaputt"}]})
    assert findings == []


def test_email_invalid_input():
    assert analyze_email_security("x") == []
    # Leeres Dict = alles fehlt -> SPF/DMARC/DKIM je ein Befund.
    assert len(analyze_email_security({})) == 3
    # Nicht-Dict-DKIM-Elemente werden robust uebersprungen (gilt als kein DKIM).
    assert any("Kein DKIM-Schluessel" in f.title
               for f in analyze_email_security({"domain": "x.de", "spf": "v=spf1 -all",
                                                "dmarc": "v=DMARC1; p=reject; rua=mailto:d@x.de",
                                                "dkim": ["kaputt", None]}))


# ====================== SCA / Abhaengigkeiten (CVE) ========================

_LOG4J_ADV = {"name": "log4j-core", "ecosystem": "maven", "vulnerable": "<2.15.0",
              "fixed": "2.17.1", "cve": "CVE-2021-44228", "severity": "kritisch",
              "title": "Log4Shell RCE"}


def test_sca_known_cve_match():
    findings = analyze_dependencies({
        "project": "p",
        "dependencies": [{"name": "log4j-core", "version": "2.14.1", "ecosystem": "maven"}],
        "advisories": [_LOG4J_ADV]})
    assert len(findings) == 1
    f = findings[0]
    assert "Verwundbare Abhaengigkeit: log4j-core 2.14.1 (CVE-2021-44228)" in f.title
    assert f.severity is Severity.KRITISCH
    assert f.category == "outdated_component" and f.cwe == "CWE-1395"
    assert "behoben in 2.17.1" in f.evidence and "Log4Shell RCE" in f.evidence


def test_sca_no_match_when_version_is_fixed():
    # 2.17.1 erfuellt '<2.15.0' NICHT -> kein CVE-Finding (nur gepinnt, kein Befund).
    findings = analyze_dependencies({
        "dependencies": [{"name": "log4j-core", "version": "2.17.1", "ecosystem": "maven"}],
        "advisories": [_LOG4J_ADV]})
    assert findings == []


def test_sca_ecosystem_mismatch_no_match():
    findings = analyze_dependencies({
        "dependencies": [{"name": "log4j-core", "version": "2.14.1", "ecosystem": "pypi"}],
        "advisories": [_LOG4J_ADV]})
    assert findings == []


def test_sca_name_mismatch_no_match():
    findings = analyze_dependencies({
        "dependencies": [{"name": "something-else", "version": "1.0.0"}],
        "advisories": [_LOG4J_ADV]})
    assert findings == []


def test_sca_deprecated_component():
    findings = analyze_dependencies({
        "dependencies": [{"name": "lodash", "version": "4.17.11", "ecosystem": "npm",
                          "deprecated": True}]})
    assert len(findings) == 1
    assert "Nicht mehr gepflegte Abhaengigkeit: lodash" in findings[0].title
    assert findings[0].severity is Severity.MITTEL and findings[0].cwe == "CWE-1104"


def test_sca_unpinned_versions():
    for pin in ("*", "", "latest", "any", "x"):
        findings = analyze_dependencies({
            "dependencies": [{"name": "requests", "version": pin, "ecosystem": "pypi"}]})
        assert any("Ungepinnte Abhaengigkeit" in f.title
                   and f.severity is Severity.NIEDRIG for f in findings)


def test_sca_deprecated_and_unpinned_combined():
    findings = analyze_dependencies({
        "dependencies": [{"name": "old", "version": "*", "deprecated": True}]})
    titles = " ".join(f.title for f in findings)
    assert "Nicht mehr gepflegte" in titles and "Ungepinnte" in titles


def test_sca_match_suppresses_deprecated_and_unpinned():
    # Trifft ein Advisory zu, zaehlt nur der konkrete CVE-Befund.
    findings = analyze_dependencies({
        "dependencies": [{"name": "log4j-core", "version": "2.14.1", "ecosystem": "maven",
                          "deprecated": True}],
        "advisories": [_LOG4J_ADV]})
    assert len(findings) == 1 and "CVE-2021-44228" in findings[0].title


def test_sca_default_and_invalid_severity_fall_back_to_hoch():
    no_sev = analyze_dependencies({
        "dependencies": [{"name": "a", "version": "1.0.0"}],
        "advisories": [{"name": "a", "vulnerable": "<2.0.0"}]})
    assert no_sev[0].severity is Severity.HOCH
    bad_sev = analyze_dependencies({
        "dependencies": [{"name": "a", "version": "1.0.0"}],
        "advisories": [{"name": "a", "vulnerable": "<2.0.0", "severity": "banane"}]})
    assert bad_sev[0].severity is Severity.HOCH


def test_sca_advisory_without_fixed_or_title_or_cve():
    findings = analyze_dependencies({
        "dependencies": [{"name": "a", "version": "1.0.0"}],
        "advisories": [{"name": "a", "vulnerable": "==1.0.0"}]})
    assert len(findings) == 1
    assert "ohne CVE-ID" in findings[0].title
    assert "behoben in" not in findings[0].evidence


def test_sca_invalid_input_and_robustness():
    assert analyze_dependencies("nope") == []
    assert analyze_dependencies({}) == []
    # Nicht-Dict-Eintraege in dependencies/advisories werden robust uebersprungen.
    findings = analyze_dependencies({
        "dependencies": ["kaputt", None, {"name": "a", "version": "1.0.0"}],
        "advisories": ["kaputt", {"name": "a", "vulnerable": "<2.0.0", "cve": "CVE-X"}]})
    assert len(findings) == 1 and "CVE-X" in findings[0].title


def test_sca_version_constraint_operators():
    # Deckt alle Vergleichsoperatoren + Default (==) ab.
    assert _satisfies("1.0.0", "<2.0.0") is True
    assert _satisfies("2.0.0", "<2.0.0") is False
    assert _satisfies("2.0.0", "<=2.0.0") is True
    assert _satisfies("2.0.1", "<=2.0.0") is False
    assert _satisfies("3.0.0", ">2.0.0") is True
    assert _satisfies("2.0.0", ">2.0.0") is False
    assert _satisfies("2.0.0", ">=2.0.0") is True
    assert _satisfies("1.9.0", ">=2.0.0") is False
    assert _satisfies("1.0.0", "==1.0.0") is True
    assert _satisfies("1.0.1", "==1.0.0") is False
    assert _satisfies("1.0.0", "!=2.0.0") is True
    assert _satisfies("2.0.0", "!=2.0.0") is False
    # Bereich (kommagetrennt), Default-Operator (bare = ==) und Rand.
    assert _satisfies("2.1.0", ">=2.0.0,<3.0.0") is True
    assert _satisfies("1.0.0", "1.0.0") is True
    # Leere / unvollstaendige Constraints matchen nicht.
    assert _satisfies("1.0.0", "") is False
    assert _satisfies("1.0.0", ",") is False
    assert _satisfies("1.0.0", ">=") is False
    # Trailing-Komma wird ignoriert, restlicher Constraint zaehlt.
    assert _satisfies("1.5.0", ">=1.0.0,") is True
    # Nicht-numerische Versionsbestandteile werden robust auf 0 gesetzt.
    assert _satisfies("1.0.0-beta", "<2.0.0") is True


def test_sca_split_op_helper():
    assert _split_op(">=2.0.0") == (">=", "2.0.0")
    assert _split_op("<1.0") == ("<", "1.0")
    assert _split_op("3.1.4") == ("==", "3.1.4")


# ====================== Firewall-/VPN-Konfiguration =========================

def test_fw_any_any_rule():
    findings = analyze_firewall({"device": "fw", "rules": [
        {"name": "permit-all", "action": "allow", "source": "any",
         "destination": "any", "service": "any"}]})
    assert len(findings) == 1
    assert "Any-Any-Freigabe" in findings[0].title
    assert findings[0].category == "misconfiguration" and findings[0].severity is Severity.HOCH


def test_fw_denied_rule_is_ignored():
    findings = analyze_firewall({"rules": [
        {"name": "deny-all", "action": "deny", "source": "any",
         "destination": "any", "service": "any"}]})
    assert findings == []


def test_fw_non_any_source_ignored():
    findings = analyze_firewall({"rules": [
        {"name": "internal", "action": "allow", "source": "10.0.0.0/8",
         "destination": "any", "service": "any"}]})
    assert findings == []


def test_fw_rdp_from_internet_via_port():
    findings = analyze_firewall({"rules": [
        {"name": "rdp", "action": "allow", "source": "0.0.0.0/0",
         "destination": "10.0.0.5", "service": "RDP", "port": 3389}]})
    assert len(findings) == 1
    assert "RDP aus dem Internet" in findings[0].title
    assert findings[0].category == "remote_access" and findings[0].severity is Severity.HOCH


def test_fw_ssh_from_internet_via_service_name():
    # Kein numerisches Port-Feld -> Auswertung ueber den Servicenamen.
    findings = analyze_firewall({"rules": [
        {"name": "ssh", "action": "allow", "source": "any",
         "destination": "10.0.0.5", "service": "ssh"}]})
    assert "SSH aus dem Internet" in findings[0].title
    assert findings[0].category == "remote_access"


def test_fw_sensitive_service_from_internet():
    findings = analyze_firewall({"rules": [
        {"name": "db", "action": "allow", "source": "0.0.0.0/0",
         "destination": "10.0.0.30", "service": "MSSQL", "port": 1433}]})
    assert "Sensibler Dienst offen ins Internet (MSSQL)" in findings[0].title
    assert findings[0].category == "exposed_service"


def test_fw_all_ports_to_specific_host():
    # source any, service any, aber Ziel konkret -> alle Ports offen.
    findings = analyze_firewall({"rules": [
        {"name": "host-any", "action": "allow", "source": "any",
         "destination": "10.0.0.9", "service": "any"}]})
    assert "Alle Ports aus dem Internet" in findings[0].title
    assert findings[0].category == "exposed_service"


def test_fw_internet_source_unknown_port_no_finding():
    # source any, konkreter aber unkritischer Dienst -> kein Befund.
    findings = analyze_firewall({"rules": [
        {"name": "web", "action": "allow", "source": "0.0.0.0/0",
         "destination": "10.0.0.40", "service": "https", "port": 443}]})
    assert findings == []


def test_fw_rule_port_invalid_value():
    # Ungueltiges Port-Feld -> Fallback auf Servicenamen (hier unbekannt -> 0).
    findings = analyze_firewall({"rules": [
        {"name": "x", "action": "allow", "source": "any",
         "destination": "10.0.0.1", "service": "https", "port": "kaputt"}]})
    assert findings == []


def test_fw_vpn_weak_crypto_ikev1_no_mfa_eol():
    findings = analyze_firewall({"vpn": [
        {"name": "legacy", "encryption": "3des", "ike_version": 1,
         "mfa": False, "eol": True}]})
    titles = " ".join(f.title for f in findings)
    cats = {f.category for f in findings}
    assert "schwacher Kryptographie" in titles
    assert "veraltetes IKEv1" in titles
    assert "ohne MFA" in titles
    assert "abgekuendigtes VPN-Gateway" in titles
    assert cats == {"crypto_weakness", "misconfiguration", "remote_access", "outdated_component"}


def test_fw_vpn_outdated_flag_alias():
    findings = analyze_firewall({"vpn": [
        {"name": "old", "encryption": "aes256", "ike_version": 2, "outdated": True}]})
    assert any(f.category == "outdated_component" for f in findings)


def test_fw_vpn_clean_no_findings():
    findings = analyze_firewall({"vpn": [
        {"name": "modern", "encryption": "aes256", "ike_version": 2, "mfa": True}]})
    assert findings == []


def test_fw_management_public_with_ssh():
    findings = analyze_firewall({"device": "fw", "management": {
        "public": True, "exposed_interfaces": ["https", "ssh"]}})
    cats = {f.category for f in findings}
    assert cats == {"exposed_service", "remote_access"}
    assert any("Management-Interface aus dem Internet" in f.title for f in findings)


def test_fw_management_public_without_ssh():
    findings = analyze_firewall({"management": {
        "public": True, "exposed_interfaces": ["https"]}})
    assert len(findings) == 1 and findings[0].category == "exposed_service"


def test_fw_management_not_public_ignored():
    findings = analyze_firewall({"management": {"public": False}})
    assert findings == []


def test_fw_invalid_input_and_robustness():
    assert analyze_firewall("nope") == []
    assert analyze_firewall({}) == []
    # Nicht-Dict-Eintraege in rules/vpn und Nicht-Dict-management robust behandeln.
    findings = analyze_firewall({
        "rules": ["kaputt", None, {"name": "r", "action": "allow", "source": "any",
                                   "destination": "any", "service": "any"}],
        "vpn": ["kaputt", {"name": "v", "mfa": False}],
        "management": "kaputt"})
    assert any(f.category == "misconfiguration" for f in findings)
    assert any(f.category == "remote_access" for f in findings)


# ========================= TLS / Zertifikate ===============================

def test_tls_expired_certificate():
    findings = analyze_tls({"host": "a.de", "certificate": {"days_until_expiry": -3}})
    assert any("abgelaufen" in f.title and f.category == "transport_security"
               and f.severity is Severity.HOCH for f in findings)


def test_tls_expired_via_flag():
    findings = analyze_tls({"host": "a.de", "certificate": {"expired": True}})
    assert any("abgelaufen" in f.title for f in findings)


def test_tls_expiring_soon():
    findings = analyze_tls({"host": "a.de", "certificate": {"days_until_expiry": 10}})
    assert any("laeuft in 10 Tagen ab" in f.title and f.severity is Severity.MITTEL
               for f in findings)


def test_tls_valid_expiry_no_finding():
    findings = analyze_tls({"host": "a.de", "certificate": {
        "days_until_expiry": 200, "signature_algorithm": "sha256WithRSAEncryption",
        "key_type": "RSA", "key_bits": 2048}})
    assert findings == []


def test_tls_invalid_days_ignored():
    # Nicht-numerisches days_until_expiry ohne expired-Flag -> kein Ablauf-Befund.
    findings = analyze_tls({"host": "a.de", "certificate": {"days_until_expiry": "n/a"}})
    assert findings == []


def test_tls_weak_signature():
    for sig in ("sha1WithRSAEncryption", "md5WithRSAEncryption"):
        findings = analyze_tls({"host": "a.de", "certificate": {
            "days_until_expiry": 100, "signature_algorithm": sig}})
        assert any("schwacher Signatur" in f.title and f.category == "crypto_weakness"
                   for f in findings)


def test_tls_short_rsa_key():
    findings = analyze_tls({"host": "a.de", "certificate": {
        "days_until_expiry": 100, "key_type": "RSA", "key_bits": 1024}})
    assert any("zu kurzem Schluessel" in f.title and f.severity is Severity.HOCH
               for f in findings)


def test_tls_ec_key_not_flagged():
    # EC-Schluessel mit wenig Bits sind gleichwertig -> kein Krypto-Befund.
    findings = analyze_tls({"host": "a.de", "certificate": {
        "days_until_expiry": 100, "key_type": "EC", "key_bits": 256}})
    assert findings == []


def test_tls_invalid_key_bits_ignored():
    findings = analyze_tls({"host": "a.de", "certificate": {
        "days_until_expiry": 100, "key_type": "RSA", "key_bits": "kaputt"}})
    assert findings == []


def test_tls_self_signed():
    findings = analyze_tls({"host": "a.de", "certificate": {
        "days_until_expiry": 100, "self_signed": True}})
    assert any("Selbstsigniertes" in f.title and f.category == "misconfiguration"
               for f in findings)


def test_tls_weak_protocols():
    findings = analyze_tls({"host": "a.de", "protocols": ["SSLv3", "TLSv1.0", "TLSv1.3"]})
    titles = " ".join(f.title for f in findings)
    assert "SSLv3" in titles and "TLSv1.0" in titles
    # SSLv3 -> HOCH, TLSv1.0 -> MITTEL, TLSv1.3 -> kein Befund.
    assert len(findings) == 2
    sslv3 = next(f for f in findings if "SSLv3" in f.title)
    assert sslv3.severity is Severity.HOCH


def test_tls_weak_ciphers():
    findings = analyze_tls({"host": "a.de", "ciphers": [
        "ECDHE-RSA-AES256-GCM-SHA384", "RC4-SHA", "DES-CBC3-SHA", "NULL-MD5"]})
    # RC4, 3DES(DES-), NULL/MD5 -> schwach; AES-GCM -> ok.
    assert len(findings) == 3
    assert all(f.category == "crypto_weakness" for f in findings)


def test_tls_endpoints_list_and_multiple():
    findings = analyze_tls({"endpoints": [
        {"host": "a.de", "certificate": {"expired": True}},
        {"host": "b.de", "protocols": ["SSLv3"]}]})
    hosts = {f.asset.split("/")[0] for f in findings}
    assert hosts == {"a.de", "b.de"}


def test_tls_invalid_input_and_robustness():
    assert analyze_tls("nope") == []
    assert analyze_tls({}) == []
    # certificate kein Dict -> uebersprungen; Nicht-Dict-Endpunkte robust.
    findings = analyze_tls({"endpoints": ["kaputt", None,
                                          {"host": "a.de", "certificate": "x",
                                           "protocols": ["SSLv3"]}]})
    assert len(findings) == 1 and "SSLv3" in findings[0].title


# ================== Backup / Ransomware-Resilienz ==========================

def test_backup_single_copy_and_no_immutable():
    findings = analyze_backup({"organization": "GmbH", "backups": [
        {"name": "fs", "copies": 1, "offline_or_immutable": False}]})
    titles = " ".join(f.title for f in findings)
    assert "Single Point of Failure" in titles
    assert "Immutable" in titles
    assert all(f.category == "backup_resilience" for f in findings)
    assert all(f.source == "backup_analyzer" for f in findings)


def test_backup_too_few_copies_medium():
    findings = analyze_backup({"backups": [{"name": "fs", "copies": 2}]})
    assert any("Zu wenige Backup-Kopien" in f.title and f.severity is Severity.MITTEL
               for f in findings)


def test_backup_invalid_copies_ignored():
    findings = analyze_backup({"backups": [{"name": "fs", "copies": "viele"}]})
    assert findings == []


def test_backup_no_offsite():
    findings = analyze_backup({"backups": [{"name": "fs", "offsite": False}]})
    assert any("Keine Offsite-Kopie" in f.title and f.severity is Severity.HOCH
               for f in findings)


def test_backup_restore_never_tested():
    findings = analyze_backup({"backups": [{"name": "fs", "restore_tested": False}]})
    assert any("nie getestet" in f.title and f.severity is Severity.HOCH
               for f in findings)


def test_backup_restore_test_overdue():
    findings = analyze_backup({"backups": [
        {"name": "fs", "restore_tested": True, "last_restore_test_days": 400}]})
    assert any("ueberfaellig" in f.title and f.severity is Severity.HOCH
               for f in findings)


def test_backup_restore_recent_ok():
    # Kuerzlich getestet -> kein Restore-Befund.
    findings = analyze_backup({"backups": [
        {"name": "fs", "restore_tested": True, "last_restore_test_days": 100}]})
    assert findings == []


def test_backup_restore_invalid_age_ignored():
    findings = analyze_backup({"backups": [
        {"name": "fs", "restore_tested": True, "last_restore_test_days": "nie"}]})
    assert findings == []


def test_backup_console_without_mfa():
    findings = analyze_backup({"backups": [{"name": "fs", "mfa_on_console": False}]})
    assert any("Konsole ohne MFA" in f.title and f.severity is Severity.MITTEL
               for f in findings)


def test_backup_not_encrypted():
    findings = analyze_backup({"backups": [{"name": "fs", "encrypted": False}]})
    assert any("nicht verschluesselt" in f.title and f.severity is Severity.MITTEL
               for f in findings)


def test_backup_short_retention():
    findings = analyze_backup({"backups": [{"name": "fs", "retention_days": 7}]})
    assert any("Zu kurze Backup-Aufbewahrung" in f.title for f in findings)


def test_backup_retention_ok_and_invalid():
    ok = analyze_backup({"backups": [{"name": "fs", "retention_days": 90}]})
    assert ok == []
    bad = analyze_backup({"backups": [{"name": "fs", "retention_days": "lang"}]})
    assert bad == []


def test_backup_policy_not_documented():
    findings = analyze_backup({"policy": {"documented": False}})
    assert len(findings) == 1
    assert "Kein dokumentiertes Backup-" in findings[0].title
    assert findings[0].severity is Severity.NIEDRIG


def test_backup_policy_documented_ok():
    assert analyze_backup({"policy": {"documented": True}}) == []


def test_backup_fully_resilient_no_findings():
    findings = analyze_backup({"backups": [
        {"name": "erp", "copies": 3, "offsite": True, "offline_or_immutable": True,
         "encrypted": True, "restore_tested": True, "last_restore_test_days": 30,
         "mfa_on_console": True, "retention_days": 90}],
        "policy": {"documented": True}})
    assert findings == []


def test_backup_invalid_input_and_robustness():
    assert analyze_backup("nope") == []
    assert analyze_backup({}) == []
    # Nicht-Dict-Backups und Nicht-Dict-policy robust behandeln.
    findings = analyze_backup({
        "backups": ["kaputt", None, {"name": "fs", "offsite": False}],
        "policy": "kaputt"})
    assert len(findings) == 1 and "Keine Offsite-Kopie" in findings[0].title


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


# ==================== HTTP-Security-Header / Cookies ========================

def test_http_missing_hsts():
    findings = analyze_http_headers({"url": "https://a.de", "headers": {}})
    assert any("Kein HSTS" in f.title and f.category == "transport_security"
               and f.severity is Severity.HOCH for f in findings)


def test_http_hsts_too_short():
    findings = analyze_http_headers({"url": "https://a.de", "headers": {
        "Strict-Transport-Security": "max-age=3600"}})
    assert any("zu kurzer Gültigkeit" in f.title and f.severity is Severity.NIEDRIG
               for f in findings)


def test_http_hsts_strong_no_finding_for_hsts():
    findings = analyze_http_headers({"url": "https://a.de", "headers": {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains"}})
    assert not any("HSTS" in f.title for f in findings)


def test_http_hsts_without_maxage_flags_short():
    # HSTS-Header vorhanden aber ohne max-age -> age=0 -> zu kurz.
    findings = analyze_http_headers({"url": "https://a.de", "headers": {
        "strict-transport-security": "includeSubDomains"}})
    assert any("zu kurzer Gültigkeit (0s)" in f.title for f in findings)


def test_http_missing_csp_and_xfo():
    findings = analyze_http_headers({"url": "https://a.de", "headers": {}})
    titles = " ".join(f.title for f in findings)
    assert "Keine Content-Security-Policy" in titles
    assert "Clickjacking-Schutz fehlt" in titles


def test_http_content_type_options():
    bad = analyze_http_headers({"url": "https://a.de", "headers": {"X-Content-Type-Options": "off"}})
    assert any("nicht 'nosniff'" in f.title for f in bad)
    good = analyze_http_headers({"url": "https://a.de", "headers": {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'", "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()"}})
    assert not any("X-Content-Type-Options" in f.title for f in good)


def test_http_missing_referrer_and_permissions_policy():
    findings = analyze_http_headers({"url": "https://a.de", "headers": {}})
    titles = " ".join(f.title for f in findings)
    assert "Keine Referrer-Policy" in titles
    assert "Keine Permissions-Policy" in titles


def test_http_banner_leaks():
    findings = analyze_http_headers({"url": "https://a.de", "headers": {
        "Server": "Apache/2.4.29", "X-Powered-By": "PHP/7.2"}})
    titles = " ".join(f.title for f in findings)
    assert "Server-Banner verrät Software: Apache/2.4.29" in titles
    assert "X-Powered-By verrät Software: PHP/7.2" in titles


def test_http_cookie_flags():
    findings = analyze_http_headers({"url": "https://a.de", "headers": {}, "cookies": [
        {"name": "SID", "secure": False, "httponly": False, "samesite": "None"}]})
    titles = " ".join(f.title for f in findings)
    assert "Cookie ohne Secure-Flag: SID" in titles
    assert "Cookie ohne HttpOnly-Flag: SID" in titles
    assert "Cookie ohne SameSite-Schutz: SID" in titles


def test_http_cookie_secure_ok_and_non_dict_skipped():
    findings = analyze_http_headers({"url": "https://a.de", "headers": {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'", "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()"},
        "cookies": ["kaputt", {"name": "ok", "secure": True, "httponly": True,
                               "samesite": "Strict"}]})
    assert findings == []


def test_http_endpoints_list_and_non_dict_headers():
    findings = analyze_http_headers({"endpoints": [
        {"url": "https://a.de", "headers": "kaputt"},
        "kaputt",
        {"url": "https://b.de", "headers": {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "x", "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "x"}}]})
    # a.de: headers kein Dict -> als leer behandelt -> mehrere Befunde; b.de sauber.
    assert findings
    assert all(f.asset == "https://a.de" for f in findings)


def test_http_invalid_input():
    assert analyze_http_headers("nope") == []
    assert len(analyze_http_headers({})) >= 1  # leerer Endpunkt -> fehlende Header
