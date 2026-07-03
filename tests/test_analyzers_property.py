"""Property-Based-Tests (Hypothesis) für alle 14 Analyzer.

Statt einzelner Beispiele generiert Hypothesis tausende zufällig strukturierte
Exporte und prüft *Invarianten*, die für JEDE Eingabe gelten müssen. Das ist ein
stärkeres Robustheits-Netz als handverlesene Fälle: Es findet die Eingabe, die
eine Regel bricht, selbst wenn niemand an sie gedacht hat.

Invarianten je Analyzer und Eingabe:
  * kein Absturz (fail-safe);
  * Rückgabe ist immer ``list[Finding]``;
  * jeder Fund trägt eine gültige Kategorie, einen echten ``Severity`` und
    einen nicht-leeren Titel;
  * jede Finding-ID hat das stabile Format ``SPEC-<8 hex>``;
  * Determinismus: dieselbe Eingabe liefert exakt dieselben Funde.

Reproduzierbar: das Profil ``derandomize=True`` fixiert die Beispiele, damit
das 100-%-Coverage-Gate und die CI deterministisch bleiben.
"""

from __future__ import annotations

import copy
import re

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from specter.analyzers import (
    analyze_ad, analyze_aws, analyze_azure, analyze_backup, analyze_container,
    analyze_database, analyze_dependencies, analyze_dns, analyze_email_security,
    analyze_entra, analyze_exchange, analyze_firewall, analyze_http_headers,
    analyze_tls,
)
from specter.findings import CATEGORIES, Finding, Severity

settings.register_profile("specter", max_examples=60, deadline=None,
                          derandomize=True,
                          suppress_health_check=[HealthCheck.too_slow])
settings.load_profile("specter")

ANALYZERS = [
    analyze_ad, analyze_aws, analyze_azure, analyze_backup, analyze_container,
    analyze_database, analyze_dependencies, analyze_dns, analyze_email_security,
    analyze_entra, analyze_exchange, analyze_firewall, analyze_http_headers,
    analyze_tls,
]

_ID_RE = re.compile(r"^SPEC-[0-9a-f]{8}$")

# Feldnamen, die in den echten Export-Schemata vorkommen — so treffen die
# generierten Daten echte Code-Pfade statt nur den „unbekannte Struktur"-Zweig.
_KNOWN_KEYS = [
    "domain", "spf", "dmarc", "dkim", "selector", "key_bits", "present",
    "dnssec", "caa", "wildcard", "zone_transfer", "dangling_cnames",
    "endpoints", "url", "headers", "cookies", "name", "secure", "httponly",
    "samesite", "host", "certificate", "days_until_expiry", "expired",
    "signature_algorithm", "key_type", "self_signed", "protocols", "ciphers",
    "databases", "engine", "port", "public", "auth_required", "tls",
    "default_creds", "containers", "image", "privileged", "host_network",
    "cap_add", "user", "docker_socket_mounted", "ports", "password_policy",
    "min_length", "complexity", "lockout_threshold", "max_age_days",
    "history_length", "krbtgt_password_age_days", "privileged_groups", "users",
    "enabled", "last_logon_days", "service_principal_names", "kerberos_preauth",
    "admin_count", "groups", "account_id", "root_account", "mfa_enabled",
    "access_keys", "minimum_length", "require_symbols", "console_access",
    "attached_policies", "age_days", "last_used_days", "roles", "trust",
    "s3_buckets", "encryption", "security_groups", "open_to_world_ports",
    "subscription_id", "storage_accounts", "public_blob_access", "https_only",
    "min_tls", "network_security_groups", "open_to_internet_ports",
    "virtual_machines", "public_ip", "disk_encryption", "os", "key_vaults",
    "public_network_access", "purge_protection", "sql_servers", "public_access",
    "tde_enabled", "role_assignments", "role", "scope", "tenant",
    "security_defaults_enabled", "legacy_auth_allowed",
    "conditional_access_policies", "state", "requires_mfa", "blocks_legacy_auth",
    "mfa_registered", "guest", "last_sign_in_days", "app_registrations",
    "admin_consent", "high_privilege_permissions", "sharing",
    "anonymous_links_enabled", "product", "build", "external_services",
    "server_header", "device", "rules", "action", "source", "destination",
    "service", "vpn", "management", "backups", "copies", "offsite",
    "offline_or_immutable", "encrypted", "restore_tested",
    "last_restore_test_days", "mfa_on_console", "retention_days", "policy",
    "documented", "project", "dependencies", "version", "ecosystem",
    "deprecated", "advisories", "vulnerable", "fixed", "cve", "severity",
]

# Werte, wie sie in echten (auch schmutzigen) Exporten auftauchen.
_scalars = (
    st.none() | st.booleans()
    | st.integers(min_value=-10, max_value=100000)
    | st.floats(allow_nan=False, allow_infinity=False, width=32)
    | st.sampled_from(["", "true", "false", "ja", "nein", "0", "1", "8", "2048",
                       "TLSv1.0", "SSLv3", "RC4-SHA", "2.14.1", "<2.15.0",
                       "AdministratorAccess", "Owner", "subscription", "root",
                       "0.0.0.0", "any", "allow", "169.254.169.254"])
    | st.text(max_size=20)
)


def _export():
    """Rekursiver Strategie-Generator für zufällige, aber realistische Exporte."""
    keyed = st.dictionaries(st.sampled_from(_KNOWN_KEYS), _scalars, max_size=6)
    return st.recursive(
        _scalars | keyed,
        lambda children: (
            st.lists(children, max_size=4)
            | st.dictionaries(st.sampled_from(_KNOWN_KEYS), children, max_size=6)
        ),
        max_leaves=25,
    )


def _check_findings(findings) -> None:
    assert isinstance(findings, list)
    for f in findings:
        assert isinstance(f, Finding)
        assert f.category in CATEGORIES
        assert isinstance(f.severity, Severity)
        assert isinstance(f.title, str) and f.title.strip()
        assert _ID_RE.match(f.id), f.id


@pytest.mark.parametrize("analyzer", ANALYZERS, ids=lambda a: a.__name__)
@given(data=_export())
def test_analyzer_invariants_on_random_exports(analyzer, data):
    findings = analyzer(data)
    _check_findings(findings)


@pytest.mark.parametrize("analyzer", ANALYZERS, ids=lambda a: a.__name__)
@given(data=_export())
def test_analyzer_is_deterministic(analyzer, data):
    first = analyzer(copy.deepcopy(data))
    second = analyzer(copy.deepcopy(data))
    assert [f.id for f in first] == [f.id for f in second]
    assert [f.title for f in first] == [f.title for f in second]


@pytest.mark.parametrize("analyzer", ANALYZERS, ids=lambda a: a.__name__)
@given(junk=st.one_of(st.none(), st.integers(), st.text(), st.booleans(),
                      st.lists(st.integers()), st.floats(allow_nan=False)))
def test_analyzer_returns_empty_on_non_dict(analyzer, junk):
    assert analyzer(junk) == []


@pytest.mark.parametrize("analyzer", ANALYZERS, ids=lambda a: a.__name__)
@given(data=st.dictionaries(
    st.sampled_from(_KNOWN_KEYS),
    st.lists(st.dictionaries(st.sampled_from(_KNOWN_KEYS), _scalars, max_size=8),
             max_size=6),
    max_size=8))
def test_analyzer_on_lists_of_records(analyzer, data):
    """Viele Analyzer iterieren über Listen von Datensätzen (users, databases,
    endpoints …) — gezielt mit solchen Strukturen füttern."""
    _check_findings(analyzer(data))
