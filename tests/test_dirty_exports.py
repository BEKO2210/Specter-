"""Härtung gegen „schmutzige" Exporte: Strings statt Bools/Ints, Müll-Typen.

Reale Kundenexporte kommen aus CSV, YAML, PowerShell oder handgepflegten
Fragebögen — dort steht ``"false"`` statt ``false`` und ``"8"`` statt ``8``.
Vor dieser Härtung führte das zu VERPASSTEN Funden (String ``"8"`` ist kein
``int`` → Regel übersprungen) und sogar zu FEHLALARMEN (String ``"false"``
ist truthy → „offener Zonentransfer" gemeldet, obwohl keiner offen ist).

Diese Tests sind der stehende Wächter dagegen — plus ein deterministischer
Mutations-Sweep, der garantiert, dass kein Analyzer auf kaputten Eingaben
abstürzt (fail-safe statt Stacktrace).
"""

from __future__ import annotations

import json
from pathlib import Path

from specter.analyzers import (
    analyze_ad, analyze_aws, analyze_azure, analyze_backup, analyze_container,
    analyze_database, analyze_dependencies, analyze_dns, analyze_email_security,
    analyze_entra, analyze_exchange, analyze_firewall, analyze_http_headers,
    analyze_tls,
)
from specter.analyzers._util import as_bool, as_int, as_str_list

DATA = Path(__file__).parent.parent / "examples" / "data"

ALL_ANALYZERS = [
    (analyze_ad, "ad_export.example.json"),
    (analyze_aws, "aws_export.example.json"),
    (analyze_azure, "azure_export.example.json"),
    (analyze_backup, "backup.example.json"),
    (analyze_container, "container.example.json"),
    (analyze_database, "database.example.json"),
    (analyze_dependencies, "dependencies.example.json"),
    (analyze_dns, "dns.example.json"),
    (analyze_email_security, "email_security.example.json"),
    (analyze_entra, "entra_export.example.json"),
    (analyze_exchange, "exchange.example.json"),
    (analyze_firewall, "firewall.example.json"),
    (analyze_http_headers, "http_headers.example.json"),
    (analyze_tls, "tls.example.json"),
]


def _titles(findings) -> list[str]:
    return [f.title for f in findings]


# ============================ as_bool / as_int ============================

def test_as_bool_passes_through_real_bools():
    assert as_bool(True) is True
    assert as_bool(False) is False


def test_as_bool_parses_zero_one_numbers():
    assert as_bool(0) is False
    assert as_bool(1) is True
    assert as_bool(0.0) is False
    assert as_bool(1.0) is True
    assert as_bool(2) is None          # mehrdeutig -> nicht bewertbar
    assert as_bool(3.14, "d") == "d"


def test_as_bool_parses_word_variants():
    for word in ("true", "TRUE", " yes ", "Ja", "on", "enabled", "aktiv", "1"):
        assert as_bool(word) is True, word
    for word in ("false", "No", " nein ", "off", "disabled", "inaktiv", "0"):
        assert as_bool(word) is False, word


def test_as_bool_unknown_returns_default():
    assert as_bool("vielleicht") is None
    assert as_bool(None) is None
    assert as_bool([], True) is True
    assert as_bool({}, False) is False


def test_as_int_accepts_numbers_and_numeric_strings():
    assert as_int(8) == 8
    assert as_int("8") == 8
    assert as_int(" 8 ") == 8
    assert as_int("8.0") == 8
    assert as_int(8.0) == 8
    assert as_int(-3) == -3


def test_as_int_rejects_bools_and_junk():
    assert as_int(True) is None        # bool ist keine Zahlangabe
    assert as_int(False, 7) == 7
    assert as_int("acht") is None
    assert as_int("8.5") is None       # nicht ganzzahlig -> nicht bewertbar
    assert as_int(8.5) is None
    assert as_int(None, 0) == 0
    assert as_int([], 0) == 0


def test_as_str_list_normalizes_names():
    assert as_str_list(["Domain Admins", "", 5]) == ["Domain Admins", "5"]
    assert as_str_list("Domain Admins") == ["Domain Admins"]
    assert as_str_list("   ") == []
    assert as_str_list(5) == []
    assert as_str_list(None) == []


# ==================== Verpasste Funde durch String-Werte ====================

def test_dns_string_false_means_inactive_not_active():
    """dnssec="false" heißt AUS -> der Fund muss feuern."""
    out = analyze_dns({"domain": "x.de", "dnssec": "false",
                       "caa": ['0 issue "x"']})
    assert any("DNSSEC nicht aktiv" in t for t in _titles(out))


def test_dns_string_false_does_not_false_positive():
    """zone_transfer="false"/wildcard="0" sind truthy Strings — früher Fehlalarm."""
    out = analyze_dns({"domain": "x.de", "dnssec": True,
                       "caa": ['0 issue "x"'],
                       "zone_transfer": "false", "wildcard": "0"})
    assert out == []


def test_ad_numeric_strings_are_assessed():
    out = analyze_ad({
        "domain": "corp", "krbtgt_password_age_days": "1450",
        "password_policy": {"min_length": "8", "lockout_threshold": "0",
                            "max_age_days": "0", "history_length": "3"},
    })
    titles = _titles(out)
    assert any("Passwort-Mindestlänge zu gering (8" in t for t in titles)
    assert any("Keine Account-Lockout-Policy" in t for t in titles)
    assert any("Passwörter laufen nie ab" in t for t in titles)
    assert any("Passwort-Historie zu kurz (3)" in t for t in titles)
    assert any("krbtgt-Passwort veraltet (1450" in t for t in titles)


def test_ad_string_bools_and_bare_group_string():
    out = analyze_ad({"domain": "corp", "users": [
        {"name": "svc", "enabled": "true", "privileged": "yes",
         "password_never_expires": "ja",
         "service_principal_names": "MSSQL/db01",
         "kerberos_preauth": "false", "last_logon_days": "400"},
        {"name": "ex", "enabled": "false", "groups": "Domain Admins"},
    ]})
    titles = _titles(out)
    assert any("nie ablaufendem Passwort: svc" in t for t in titles)
    assert any("Kerberoasting-Exposition): svc" in t for t in titles)
    assert any("AS-REP-Roasting): svc" in t for t in titles)
    assert any("ungenutztes Konto (seit 400 Tagen): svc" in t for t in titles)
    assert any("Deaktiviertes Konto weiterhin in privilegierter Gruppe: ex" in t
               for t in titles)


def test_database_string_flags():
    out = analyze_database({"databases": [
        {"engine": "redis", "port": "6379", "public": "true",
         "auth_required": "false", "tls": "no", "default_creds": "nein"},
    ]})
    titles = _titles(out)
    assert any("öffentlich erreichbar" in t for t in titles)
    assert any("ohne Authentifizierung" in t for t in titles)
    assert any("Unverschlüsselter Datenbank-Transport" in t for t in titles)
    # default_creds="nein" darf NICHT als kritischer Fund fehlinterpretiert werden
    assert not any("Default-Zugangsdaten" in t for t in titles)


def test_container_string_flags():
    out = analyze_container({"containers": [
        {"name": "web", "image": "nginx:1.25", "privileged": "true",
         "docker_socket_mounted": "yes", "host_network": "false",
         "user": "1000", "ports": []},
    ]})
    titles = _titles(out)
    assert any("Privilegierter Container" in t for t in titles)
    assert any("Docker-Socket" in t for t in titles)
    assert not any("Host-Networking" in t for t in titles)


def test_backup_numeric_strings_and_word_bools():
    out = analyze_backup({"organization": "X", "backups": [
        {"name": "nas", "copies": "1", "offsite": "nein",
         "offline_or_immutable": "no", "encrypted": "false",
         "restore_tested": "ja", "last_restore_test_days": "400",
         "mfa_on_console": "off", "retention_days": "7"},
    ]})
    titles = _titles(out)
    assert any("Höchstens eine Backup-Kopie" in t for t in titles)
    assert any("Keine Offsite-Kopie" in t for t in titles)
    assert any("Kein offline-/unveränderbares" in t for t in titles)
    assert any("Backup nicht verschlüsselt" in t for t in titles)
    assert any("Restore-Test überfällig (400" in t for t in titles)
    assert any("Backup-Konsole ohne MFA" in t for t in titles)
    assert any("Zu kurze Backup-Aufbewahrung (7" in t for t in titles)
    # restore_tested="ja" -> "nie getestet" darf NICHT feuern
    assert not any("nie getestet" in t for t in titles)


def test_firewall_string_flags():
    out = analyze_firewall({
        "device": "fw",
        "vpn": [{"name": "v", "encryption": "aes256", "ike_version": 2,
                 "mfa": "false", "eol": "true"}],
        "management": {"public": "false", "exposed_interfaces": ["ssh"]},
    })
    titles = _titles(out)
    assert any("VPN-Zugang ohne MFA" in t for t in titles)
    assert any("Veraltetes/abgekündigtes VPN-Gateway" in t for t in titles)
    # management.public="false" darf keine Mgmt-Funde erzeugen
    assert not any("Management-Interface" in t for t in titles)


def test_aws_string_values():
    out = analyze_aws({
        "account_id": "1", "root_account": {"mfa_enabled": "false",
                                            "access_keys": "1"},
        "password_policy": {"minimum_length": "8", "require_symbols": "no",
                            "max_age_days": "0"},
        "users": [{"name": "bot", "console_access": "true",
                   "mfa_enabled": "false",
                   "access_keys": [{"age_days": "400",
                                    "last_used_days": "300"}]}],
    })
    titles = _titles(out)
    assert any("Root-Konto ohne MFA" in t for t in titles)
    assert any("Root-Konto besitzt Access-Keys" in t for t in titles)
    assert any("Mindestlänge 8" in t for t in titles)
    assert any("Sonderzeichen-Pflicht" in t for t in titles)
    assert any("laufen nie ab" in t for t in titles)
    assert any("IAM-Konsolenzugriff ohne MFA: bot" in t for t in titles)
    assert any("Alter Access-Key (400 Tage)" in t for t in titles)
    assert any("Ungenutzter Access-Key: bot" in t for t in titles)


def test_aws_unparseable_last_used_is_not_flagged():
    """Ein vorhandener, aber unlesbarer last_used-Wert wird nicht bewertet."""
    out = analyze_aws({"account_id": "1", "users": [
        {"name": "u", "access_keys": [{"age_days": 10,
                                       "last_used_days": "n/a"}]},
    ]})
    assert not any("Ungenutzter Access-Key" in t for t in _titles(out))


def test_azure_string_values():
    out = analyze_azure({
        "subscription_id": "s",
        "storage_accounts": [{"name": "sa", "public_blob_access": "true",
                              "https_only": "false", "encryption": "no",
                              "min_tls": "TLS1.2"}],
        "key_vaults": [{"name": "kv", "public_network_access": "yes",
                        "purge_protection": "false"}],
        "sql_servers": [{"name": "db", "public_access": "1",
                         "tde_enabled": "0"}],
        "virtual_machines": [{"name": "vm", "public_ip": "false",
                              "disk_encryption": "true",
                              "os": "Windows Server 2022"}],
    })
    titles = _titles(out)
    assert any("Öffentlicher Blob-Zugriff" in t for t in titles)
    assert any("kein HTTPS-only" in t for t in titles)
    assert any("ohne Verschlüsselung im Ruhezustand" in t for t in titles)
    assert any("Key Vault öffentlich erreichbar" in t for t in titles)
    assert any("ohne Purge-Protection" in t for t in titles)
    assert any("Azure-SQL-Server öffentlich" in t for t in titles)
    assert any("Transparent Data Encryption" in t for t in titles)
    # VM mit public_ip="false" -> kein Expositions-Fehlalarm
    assert not any("VM direkt aus dem Internet" in t for t in titles)


def test_entra_string_values():
    out = analyze_entra({
        "tenant": "t", "security_defaults_enabled": "false",
        "legacy_auth_allowed": "true",
        "conditional_access_policies": [
            {"name": "CA", "state": "enabled", "requires_mfa": "false",
             "blocks_legacy_auth": "false"}],
        "users": [{"upn": "a@t", "enabled": "true", "privileged": "true",
                   "mfa_registered": "false"},
                  {"upn": "g@t", "enabled": "true", "guest": "true",
                   "last_sign_in_days": "240"}],
        "app_registrations": [{"name": "App", "admin_consent": "true",
                               "high_privilege_permissions": "Directory.ReadWrite.All"}],
        "sharing": {"anonymous_links_enabled": "true"},
    })
    titles = _titles(out)
    assert any("Keine MFA-Erzwingung" in t for t in titles)
    assert any("Legacy-Authentifizierung nicht blockiert" in t for t in titles)
    assert any("Privilegiertes Konto ohne MFA: a@t" in t for t in titles)
    assert any("Inaktives Gastkonto (seit 240" in t for t in titles)
    assert any("Überprivilegierte App-Registrierung: App" in t for t in titles)
    assert any("Anonyme Freigabelinks" in t for t in titles)


def test_http_cookie_string_flags():
    out = analyze_http_headers({
        "url": "https://x.de",
        "headers": {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer", "Permissions-Policy": "x=()",
        },
        "cookies": [{"name": "sid", "secure": "false", "httponly": "false",
                     "samesite": "Lax"}],
    })
    titles = _titles(out)
    assert any("Cookie ohne Secure-Flag" in t for t in titles)
    assert any("Cookie ohne HttpOnly-Flag" in t for t in titles)


def test_email_dirty_dkim():
    out = analyze_email_security({
        "domain": "x.de", "spf": "v=spf1 -all",
        "dmarc": "v=DMARC1; p=reject; rua=mailto:d@x.de",
        "dkim": [{"selector": "a", "key_bits": "1024", "present": "true"},
                 {"selector": "b", "present": "false"}],
    })
    titles = _titles(out)
    assert any("nicht mehr zeitgemäß (1024" in t for t in titles)
    assert not any("Kein DKIM-Schlüssel" in t for t in titles)


def test_dependency_string_deprecated():
    out = analyze_dependencies({"project": "p", "dependencies": [
        {"name": "lodash", "version": "4.17.11", "ecosystem": "npm",
         "deprecated": "true"}], "advisories": []})
    assert any("Nicht mehr gepflegte" in t for t in _titles(out))


# ================= TLS: OpenSSL-Aliasse und EC-Schlüssel =================

def test_tls_openssl_protocol_aliases_detected():
    """OpenSSL nennt TLS 1.0 "TLSv1" — genau das liefert der Live-Kollektor."""
    out = analyze_tls({"endpoints": [
        {"host": "h:443", "protocols": ["TLSv1", "SSL3", "ssl2"]}]})
    titles = _titles(out)
    assert any("(TLSv1)" in t for t in titles)
    assert any("(SSL3)" in t for t in titles)
    assert any("(ssl2)" in t for t in titles)
    sev = {t: f.severity for t, f in zip(titles, out)}
    assert all(f.severity.label in ("Hoch", "Mittel") for f in out), sev


def test_tls_short_ec_key_flagged_strong_ec_not():
    weak = analyze_tls({"endpoints": [{"host": "h:443", "certificate": {
        "key_type": "EC", "key_bits": 192, "days_until_expiry": 200,
        "signature_algorithm": "ecdsa-with-SHA256"}}]})
    assert any("zu kurzem Schlüssel (192 Bit)" in t for t in _titles(weak))
    strong = analyze_tls({"endpoints": [{"host": "h:443", "certificate": {
        "key_type": "EC", "key_bits": 256, "days_until_expiry": 200,
        "signature_algorithm": "ecdsa-with-SHA256"}}]})
    assert strong == []


def test_tls_dirty_cert_fields():
    out = analyze_tls({"endpoints": [{"host": "h:443", "certificate": {
        "expired": "true", "self_signed": "ja", "key_type": "RSA",
        "key_bits": "1024"}}]})
    titles = _titles(out)
    assert any("abgelaufen" in t for t in titles)
    assert any("Selbstsigniertes" in t for t in titles)
    assert any("zu kurzem Schlüssel (1024" in t for t in titles)


# ===================== Mutations-Sweep (kein Absturz) =====================

_MUTANTS = [None, 5, 3.14, "kaputt", True, [], [None], [5], ["x"], {}, {"x": 1}]


def _paths(obj, prefix=()):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield prefix + (k,), v
            yield from _paths(v, prefix + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield prefix + (i,), v
            yield from _paths(v, prefix + (i,))


def _set_path(obj, path, value):
    node = obj
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value


def test_no_analyzer_crashes_on_mutated_exports():
    """Jeden Feldwert der Beispiel-Exporte durch falsche Typen ersetzen —
    kein Analyzer darf eine Exception werfen (fail-safe statt Stacktrace)."""
    for fn, name in ALL_ANALYZERS:
        base = json.loads((DATA / name).read_text())
        for mutant in _MUTANTS + ["", -1]:
            result = fn(mutant)
            assert isinstance(result, list), (fn.__name__, mutant)
        for path, _ in list(_paths(base)):
            for mutant in _MUTANTS:
                work = json.loads(json.dumps(base))
                _set_path(work, path, mutant)
                result = fn(work)
                assert isinstance(result, list), (fn.__name__, path, mutant)


def test_clean_examples_unchanged_by_hardening():
    """Regressionsanker: Auf den sauberen Beispiel-Exporten liefert jeder
    Analyzer weiterhin Funde (die Härtung hat nichts stummgeschaltet)."""
    for fn, name in ALL_ANALYZERS:
        base = json.loads((DATA / name).read_text())
        assert len(fn(base)) > 0, fn.__name__
