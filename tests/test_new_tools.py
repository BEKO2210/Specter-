"""Tests fuer die neuen Werkzeuge: analyze_ad, analyze_exchange, run_scanner."""

from __future__ import annotations

import json
import subprocess
from unittest.mock import patch

import pytest

from specter.audit import AuditLog
from specter.config import Config, Engagement, ScannerPolicy
from specter.safety import SafetyPolicy
from specter.state import EngagementState
from specter.tools.analyze_ad import AnalyzeAdTool
from specter.tools.analyze_aws import AnalyzeAwsTool
from specter.tools.analyze_azure import AnalyzeAzureTool
from specter.tools.analyze_backup import AnalyzeBackupTool
from specter.tools.analyze_container import AnalyzeContainerTool
from specter.tools.analyze_database import AnalyzeDatabaseTool
from specter.tools.analyze_dependencies import AnalyzeDependenciesTool
from specter.tools.analyze_dns import AnalyzeDnsTool
from specter.tools.analyze_email_security import AnalyzeEmailSecurityTool
from specter.tools.analyze_entra import AnalyzeEntraTool
from specter.tools.analyze_firewall import AnalyzeFirewallTool
from specter.tools.analyze_http_headers import AnalyzeHttpHeadersTool
from specter.tools.analyze_tls import AnalyzeTlsTool
from specter.tools.analyze_exchange import AnalyzeExchangeTool
from specter.tools.run_scanner import RunScannerTool


def _cfg(tmp_path, **ov) -> Config:
    allowed = tmp_path / "targets"
    allowed.mkdir(exist_ok=True)
    d = dict(
        engagement=Engagement("X", "Y", "R"),
        allowed_targets=["127.0.0.1", "10.10.0.0/16"], forbidden_targets=[],
        allowed_paths=[allowed.resolve()], max_file_bytes=100_000,
        allowed_binaries=["curl"], command_timeout=10, require_approval=False,
        max_iterations=5, model="claude-sonnet-5",
    )
    d.update(ov)
    return Config(**d)


def _write_json(tmp_path, name, obj) -> str:
    p = tmp_path / "targets" / name
    p.write_text(json.dumps(obj), encoding="utf-8")
    return str(p)


# ------------------------------- analyze_ad -------------------------------

def _ad_tool(cfg, tmp_path):
    state = EngagementState()
    return AnalyzeAdTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state), state


def test_analyze_ad_success(tmp_path):
    cfg = _cfg(tmp_path)
    tool, state = _ad_tool(cfg, tmp_path)
    path = _write_json(tmp_path, "ad.json", {
        "domain": "corp.de",
        "password_policy": {"min_length": 6, "complexity": False, "lockout_threshold": 0},
        "users": [{"name": "svc", "enabled": True, "kerberos_preauth": False}]})
    r = tool.run({"path": path})
    assert not r.is_error and "AD-Analyse" in r.content
    assert len(state.findings) >= 3


def test_analyze_ad_scope_denied(tmp_path):
    cfg = _cfg(tmp_path)
    tool, _ = _ad_tool(cfg, tmp_path)
    r = tool.run({"path": "/etc/passwd"})
    assert r.is_error and "VERWEIGERT" in r.content


def test_analyze_ad_missing_file(tmp_path):
    cfg = _cfg(tmp_path)
    tool, _ = _ad_tool(cfg, tmp_path)
    r = tool.run({"path": str(tmp_path / "targets" / "fehlt.json")})
    assert r.is_error and "existiert nicht" in r.content


def test_analyze_ad_invalid_json(tmp_path):
    cfg = _cfg(tmp_path)
    tool, _ = _ad_tool(cfg, tmp_path)
    p = tmp_path / "targets" / "kaputt.json"
    p.write_text("{nicht: valides json", encoding="utf-8")
    r = tool.run({"path": str(p)})
    assert r.is_error and "JSON" in r.content


def test_analyze_ad_too_large(tmp_path):
    cfg = _cfg(tmp_path, max_file_bytes=10)
    tool, _ = _ad_tool(cfg, tmp_path)
    path = _write_json(tmp_path, "big.json", {"domain": "x" * 100})
    r = tool.run({"path": path})
    assert r.is_error and "zu gross" in r.content


def test_analyze_ad_no_findings(tmp_path):
    cfg = _cfg(tmp_path)
    tool, state = _ad_tool(cfg, tmp_path)
    path = _write_json(tmp_path, "clean.json", {"domain": "corp.de"})
    r = tool.run({"path": path})
    assert not r.is_error and "ohne Befunde" in r.content
    assert len(state.findings) == 0


# ---------------------------- analyze_exchange ----------------------------

def test_analyze_exchange_success(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeExchangeTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "ex.json", {
        "host": "mail.de", "build": "15.1.2000.1",
        "external_services": ["ECP"], "tls": {"protocols": ["TLSv1.0"]}})
    r = tool.run({"path": path})
    assert not r.is_error and "Exchange-Analyse" in r.content
    assert len(state.findings) >= 3


def test_analyze_exchange_scope_denied(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeExchangeTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    r = tool.run({"path": "/etc/hosts"})
    assert r.is_error and "VERWEIGERT" in r.content


def test_analyze_exchange_missing_file(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeExchangeTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    r = tool.run({"path": str(tmp_path / "targets" / "weg.json")})
    assert r.is_error and "existiert nicht" in r.content


def test_analyze_exchange_invalid_json(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeExchangeTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    p = tmp_path / "targets" / "bad.json"
    p.write_text("<<<nope>>>", encoding="utf-8")
    r = tool.run({"path": str(p)})
    assert r.is_error and "JSON" in r.content


def test_analyze_exchange_too_large(tmp_path):
    cfg = _cfg(tmp_path, max_file_bytes=5)
    state = EngagementState()
    tool = AnalyzeExchangeTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "big.json", {"host": "x" * 50})
    r = tool.run({"path": path})
    assert r.is_error and "zu gross" in r.content


def test_analyze_exchange_no_findings(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeExchangeTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "clean.json", {"host": "mail.de", "build": "15.2.1600.5"})
    r = tool.run({"path": path})
    assert not r.is_error and "ohne Befunde" in r.content


# ------------------------------ analyze_entra -----------------------------

def test_analyze_entra_success(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeEntraTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "entra.json", {
        "tenant": "contoso.de", "security_defaults_enabled": False,
        "legacy_auth_allowed": True, "conditional_access_policies": [],
        "users": [{"upn": "admin@x", "enabled": True, "privileged": True,
                   "mfa_registered": False}]})
    r = tool.run({"path": path})
    assert not r.is_error and "M365-Analyse" in r.content
    assert len(state.findings) >= 3


def test_analyze_entra_scope_denied(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeEntraTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    r = tool.run({"path": "/etc/passwd"})
    assert r.is_error and "VERWEIGERT" in r.content


def test_analyze_entra_missing_file(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeEntraTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    r = tool.run({"path": str(tmp_path / "targets" / "weg.json")})
    assert r.is_error and "existiert nicht" in r.content


def test_analyze_entra_invalid_json(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeEntraTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    p = tmp_path / "targets" / "bad.json"
    p.write_text("nope", encoding="utf-8")
    r = tool.run({"path": str(p)})
    assert r.is_error and "JSON" in r.content


def test_analyze_entra_too_large(tmp_path):
    cfg = _cfg(tmp_path, max_file_bytes=5)
    state = EngagementState()
    tool = AnalyzeEntraTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "big.json", {"tenant": "x" * 50})
    r = tool.run({"path": path})
    assert r.is_error and "zu gross" in r.content


def test_analyze_entra_no_findings(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeEntraTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "clean.json", {
        "tenant": "contoso.de", "security_defaults_enabled": True,
        "conditional_access_policies": [{"state": "enabled", "requires_mfa": True}]})
    r = tool.run({"path": path})
    assert not r.is_error and "ohne Befunde" in r.content


# ------------------------------ analyze_aws -------------------------------

def test_analyze_aws_success(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeAwsTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "aws.json", {
        "account_id": "123456789012",
        "root_account": {"mfa_enabled": False, "access_keys": 1},
        "s3_buckets": [{"name": "kunden-backups", "public": True, "encryption": False}]})
    r = tool.run({"path": path})
    assert not r.is_error and "AWS-Analyse" in r.content
    assert len(state.findings) >= 3


def test_analyze_aws_scope_denied(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeAwsTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    r = tool.run({"path": "/etc/passwd"})
    assert r.is_error and "VERWEIGERT" in r.content


def test_analyze_aws_missing_file(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeAwsTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    r = tool.run({"path": str(tmp_path / "targets" / "weg.json")})
    assert r.is_error and "existiert nicht" in r.content


def test_analyze_aws_invalid_json(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeAwsTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    p = tmp_path / "targets" / "bad.json"
    p.write_text("nope", encoding="utf-8")
    r = tool.run({"path": str(p)})
    assert r.is_error and "JSON" in r.content


def test_analyze_aws_too_large(tmp_path):
    cfg = _cfg(tmp_path, max_file_bytes=5)
    state = EngagementState()
    tool = AnalyzeAwsTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "big.json", {"account_id": "x" * 50})
    r = tool.run({"path": path})
    assert r.is_error and "zu gross" in r.content


def test_analyze_aws_no_findings(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeAwsTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "clean.json", {
        "account_id": "123", "root_account": {"mfa_enabled": True, "access_keys": 0}})
    r = tool.run({"path": path})
    assert not r.is_error and "ohne Befunde" in r.content


# ------------------------------ analyze_azure -----------------------------

def test_analyze_azure_success(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeAzureTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "azure.json", {
        "subscription_id": "sub-1",
        "storage_accounts": [{"name": "sa1", "public_blob_access": True}],
        "sql_servers": [{"name": "sql1", "public_access": True, "tde_enabled": False}]})
    r = tool.run({"path": path})
    assert not r.is_error and "Azure-Analyse" in r.content
    assert len(state.findings) >= 3


def test_analyze_azure_scope_denied(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeAzureTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    r = tool.run({"path": "/etc/passwd"})
    assert r.is_error and "VERWEIGERT" in r.content


def test_analyze_azure_missing_file(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeAzureTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    r = tool.run({"path": str(tmp_path / "targets" / "weg.json")})
    assert r.is_error and "existiert nicht" in r.content


def test_analyze_azure_invalid_json(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeAzureTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    p = tmp_path / "targets" / "bad.json"
    p.write_text("nope", encoding="utf-8")
    r = tool.run({"path": str(p)})
    assert r.is_error and "JSON" in r.content


def test_analyze_azure_too_large(tmp_path):
    cfg = _cfg(tmp_path, max_file_bytes=5)
    state = EngagementState()
    tool = AnalyzeAzureTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "big.json", {"subscription_id": "x" * 50})
    r = tool.run({"path": path})
    assert r.is_error and "zu gross" in r.content


def test_analyze_azure_no_findings(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeAzureTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "clean.json", {
        "subscription_id": "sub-clean",
        "storage_accounts": [{"name": "ok", "public_blob_access": False,
                              "https_only": True, "encryption": True}]})
    r = tool.run({"path": path})
    assert not r.is_error and "ohne Befunde" in r.content


# ------------------------- analyze_email_security -------------------------

def test_analyze_email_security_success(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeEmailSecurityTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "mail.json", {
        "domain": "x.de", "spf": "v=spf1 +all", "dmarc": "v=DMARC1; p=none"})
    r = tool.run({"path": path})
    assert not r.is_error and "E-Mail-Security-Analyse" in r.content
    assert len(state.findings) >= 2


def test_analyze_email_security_scope_denied(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeEmailSecurityTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    r = tool.run({"path": "/etc/passwd"})
    assert r.is_error and "VERWEIGERT" in r.content


def test_analyze_email_security_missing_file(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeEmailSecurityTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    r = tool.run({"path": str(tmp_path / "targets" / "weg.json")})
    assert r.is_error and "existiert nicht" in r.content


def test_analyze_email_security_invalid_json(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeEmailSecurityTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    p = tmp_path / "targets" / "bad.json"
    p.write_text("nope", encoding="utf-8")
    r = tool.run({"path": str(p)})
    assert r.is_error and "JSON" in r.content


def test_analyze_email_security_too_large(tmp_path):
    cfg = _cfg(tmp_path, max_file_bytes=5)
    state = EngagementState()
    tool = AnalyzeEmailSecurityTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "big.json", {"domain": "x" * 50})
    r = tool.run({"path": path})
    assert r.is_error and "zu gross" in r.content


def test_analyze_email_security_no_findings(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeEmailSecurityTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "clean.json", {
        "domain": "x.de", "spf": "v=spf1 -all",
        "dmarc": "v=DMARC1; p=reject; rua=mailto:d@x.de",
        "dkim": [{"selector": "g", "key_bits": 2048, "present": True}]})
    r = tool.run({"path": path})
    assert not r.is_error and "ohne Befunde" in r.content


# ------------------------- analyze_dependencies ---------------------------

def _dep_export():
    return {
        "project": "p",
        "dependencies": [{"name": "log4j-core", "version": "2.14.1", "ecosystem": "maven"}],
        "advisories": [{"name": "log4j-core", "ecosystem": "maven",
                        "vulnerable": "<2.15.0", "fixed": "2.17.1",
                        "cve": "CVE-2021-44228", "severity": "kritisch"}]}


def test_analyze_dependencies_success(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeDependenciesTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "deps.json", _dep_export())
    r = tool.run({"path": path})
    assert not r.is_error and "SCA-/Abhaengigkeits-Analyse" in r.content
    assert len(state.findings) == 1


def test_analyze_dependencies_scope_denied(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeDependenciesTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    r = tool.run({"path": "/etc/passwd"})
    assert r.is_error and "VERWEIGERT" in r.content


def test_analyze_dependencies_missing_file(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeDependenciesTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    r = tool.run({"path": str(tmp_path / "targets" / "weg.json")})
    assert r.is_error and "existiert nicht" in r.content


def test_analyze_dependencies_invalid_json(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeDependenciesTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    p = tmp_path / "targets" / "bad.json"
    p.write_text("nope", encoding="utf-8")
    r = tool.run({"path": str(p)})
    assert r.is_error and "JSON" in r.content


def test_analyze_dependencies_too_large(tmp_path):
    cfg = _cfg(tmp_path, max_file_bytes=5)
    state = EngagementState()
    tool = AnalyzeDependenciesTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "big.json", _dep_export())
    r = tool.run({"path": path})
    assert r.is_error and "zu gross" in r.content


def test_analyze_dependencies_no_findings(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeDependenciesTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "clean.json", {
        "dependencies": [{"name": "fastapi", "version": "0.110.0", "ecosystem": "pypi"}]})
    r = tool.run({"path": path})
    assert not r.is_error and "ohne Befunde" in r.content


# --------------------------- analyze_firewall -----------------------------

def _fw_export():
    return {"device": "fw", "rules": [
        {"name": "permit-all", "action": "allow", "source": "any",
         "destination": "any", "service": "any"}]}


def test_analyze_firewall_success(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeFirewallTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "fw.json", _fw_export())
    r = tool.run({"path": path})
    assert not r.is_error and "Firewall-/VPN-Analyse" in r.content
    assert len(state.findings) == 1


def test_analyze_firewall_scope_denied(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeFirewallTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    r = tool.run({"path": "/etc/passwd"})
    assert r.is_error and "VERWEIGERT" in r.content


def test_analyze_firewall_missing_file(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeFirewallTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    r = tool.run({"path": str(tmp_path / "targets" / "weg.json")})
    assert r.is_error and "existiert nicht" in r.content


def test_analyze_firewall_invalid_json(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeFirewallTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    p = tmp_path / "targets" / "bad.json"
    p.write_text("nope", encoding="utf-8")
    r = tool.run({"path": str(p)})
    assert r.is_error and "JSON" in r.content


def test_analyze_firewall_too_large(tmp_path):
    cfg = _cfg(tmp_path, max_file_bytes=5)
    state = EngagementState()
    tool = AnalyzeFirewallTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "big.json", _fw_export())
    r = tool.run({"path": path})
    assert r.is_error and "zu gross" in r.content


def test_analyze_firewall_no_findings(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeFirewallTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "clean.json", {"rules": [
        {"name": "internal", "action": "allow", "source": "10.0.0.0/8",
         "destination": "10.0.0.1", "service": "https", "port": 443}]})
    r = tool.run({"path": path})
    assert not r.is_error and "ohne Befunde" in r.content


# ------------------------------ analyze_tls -------------------------------

def _tls_export():
    return {"host": "a.de", "certificate": {"days_until_expiry": -1},
            "protocols": ["SSLv3"]}


def test_analyze_tls_success(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeTlsTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "tls.json", _tls_export())
    r = tool.run({"path": path})
    assert not r.is_error and "TLS-/Zertifikatsanalyse" in r.content
    assert len(state.findings) == 2


def test_analyze_tls_scope_denied(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeTlsTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    r = tool.run({"path": "/etc/passwd"})
    assert r.is_error and "VERWEIGERT" in r.content


def test_analyze_tls_missing_file(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeTlsTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    r = tool.run({"path": str(tmp_path / "targets" / "weg.json")})
    assert r.is_error and "existiert nicht" in r.content


def test_analyze_tls_invalid_json(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeTlsTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    p = tmp_path / "targets" / "bad.json"
    p.write_text("nope", encoding="utf-8")
    r = tool.run({"path": str(p)})
    assert r.is_error and "JSON" in r.content


def test_analyze_tls_too_large(tmp_path):
    cfg = _cfg(tmp_path, max_file_bytes=5)
    state = EngagementState()
    tool = AnalyzeTlsTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "big.json", _tls_export())
    r = tool.run({"path": path})
    assert r.is_error and "zu gross" in r.content


def test_analyze_tls_no_findings(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeTlsTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "clean.json", {
        "host": "a.de", "certificate": {"days_until_expiry": 300},
        "protocols": ["TLSv1.2", "TLSv1.3"], "ciphers": ["ECDHE-RSA-AES256-GCM-SHA384"]})
    r = tool.run({"path": path})
    assert not r.is_error and "ohne Befunde" in r.content


# ----------------------------- analyze_backup -----------------------------

def _backup_export():
    return {"organization": "GmbH", "backups": [
        {"name": "fs", "copies": 1, "offline_or_immutable": False}]}


def test_analyze_backup_success(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeBackupTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "bk.json", _backup_export())
    r = tool.run({"path": path})
    assert not r.is_error and "Backup-/Resilienzanalyse" in r.content
    assert len(state.findings) == 2


def test_analyze_backup_scope_denied(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeBackupTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    r = tool.run({"path": "/etc/passwd"})
    assert r.is_error and "VERWEIGERT" in r.content


def test_analyze_backup_missing_file(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeBackupTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    r = tool.run({"path": str(tmp_path / "targets" / "weg.json")})
    assert r.is_error and "existiert nicht" in r.content


def test_analyze_backup_invalid_json(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeBackupTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    p = tmp_path / "targets" / "bad.json"
    p.write_text("nope", encoding="utf-8")
    r = tool.run({"path": str(p)})
    assert r.is_error and "JSON" in r.content


def test_analyze_backup_too_large(tmp_path):
    cfg = _cfg(tmp_path, max_file_bytes=5)
    state = EngagementState()
    tool = AnalyzeBackupTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "big.json", _backup_export())
    r = tool.run({"path": path})
    assert r.is_error and "zu gross" in r.content


def test_analyze_backup_no_findings(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeBackupTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "clean.json", {"backups": [
        {"name": "erp", "copies": 3, "offsite": True, "offline_or_immutable": True,
         "encrypted": True, "restore_tested": True, "last_restore_test_days": 30,
         "mfa_on_console": True, "retention_days": 90}], "policy": {"documented": True}})
    r = tool.run({"path": path})
    assert not r.is_error and "ohne Befunde" in r.content


# -------------------------- analyze_http_headers --------------------------

def _hdr_export():
    return {"url": "https://a.de", "headers": {"Server": "Apache/2.4.29"},
            "cookies": [{"name": "SID", "secure": False}]}


def test_analyze_http_headers_success(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeHttpHeadersTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "hdr.json", _hdr_export())
    r = tool.run({"path": path})
    assert not r.is_error and "HTTP-Header-Analyse" in r.content
    assert len(state.findings) >= 3


def test_analyze_http_headers_scope_denied(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeHttpHeadersTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    r = tool.run({"path": "/etc/passwd"})
    assert r.is_error and "VERWEIGERT" in r.content


def test_analyze_http_headers_missing_file(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeHttpHeadersTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    r = tool.run({"path": str(tmp_path / "targets" / "weg.json")})
    assert r.is_error and "existiert nicht" in r.content


def test_analyze_http_headers_invalid_json(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeHttpHeadersTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    p = tmp_path / "targets" / "bad.json"
    p.write_text("nope", encoding="utf-8")
    r = tool.run({"path": str(p)})
    assert r.is_error and "JSON" in r.content


def test_analyze_http_headers_too_large(tmp_path):
    cfg = _cfg(tmp_path, max_file_bytes=5)
    state = EngagementState()
    tool = AnalyzeHttpHeadersTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "big.json", _hdr_export())
    r = tool.run({"path": path})
    assert r.is_error and "zu gross" in r.content


def test_analyze_http_headers_no_findings(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeHttpHeadersTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "clean.json", {"url": "https://a.de", "headers": {
        "Strict-Transport-Security": "max-age=31536000", "Content-Security-Policy": "x",
        "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer", "Permissions-Policy": "x"}})
    r = tool.run({"path": path})
    assert not r.is_error and "ohne Befunde" in r.content


# ------------------------------ analyze_dns -------------------------------

def _dns_export():
    return {"domain": "a.de", "dnssec": False, "caa": [], "zone_transfer": True}


def test_analyze_dns_success(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeDnsTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "dns.json", _dns_export())
    r = tool.run({"path": path})
    assert not r.is_error and "DNS-Sicherheitsanalyse" in r.content
    assert len(state.findings) >= 3


def test_analyze_dns_scope_denied(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeDnsTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    r = tool.run({"path": "/etc/passwd"})
    assert r.is_error and "VERWEIGERT" in r.content


def test_analyze_dns_missing_file(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeDnsTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    r = tool.run({"path": str(tmp_path / "targets" / "weg.json")})
    assert r.is_error and "existiert nicht" in r.content


def test_analyze_dns_invalid_json(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeDnsTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    p = tmp_path / "targets" / "bad.json"
    p.write_text("nope", encoding="utf-8")
    r = tool.run({"path": str(p)})
    assert r.is_error and "JSON" in r.content


def test_analyze_dns_too_large(tmp_path):
    cfg = _cfg(tmp_path, max_file_bytes=5)
    state = EngagementState()
    tool = AnalyzeDnsTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "big.json", _dns_export())
    r = tool.run({"path": path})
    assert r.is_error and "zu gross" in r.content


def test_analyze_dns_no_findings(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeDnsTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "clean.json", {
        "domain": "a.de", "dnssec": True, "caa": ["0 issue \"letsencrypt.org\""]})
    r = tool.run({"path": path})
    assert not r.is_error and "ohne Befunde" in r.content


# ---------------------------- analyze_database ----------------------------

def _db_export():
    return {"databases": [
        {"engine": "redis", "port": 6379, "public": True,
         "auth_required": False, "tls": False}]}


def test_analyze_database_success(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeDatabaseTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "db.json", _db_export())
    r = tool.run({"path": path})
    assert not r.is_error and "Datenbank-Analyse" in r.content
    assert len(state.findings) >= 3


def test_analyze_database_scope_denied(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeDatabaseTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    r = tool.run({"path": "/etc/passwd"})
    assert r.is_error and "VERWEIGERT" in r.content


def test_analyze_database_missing_file(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeDatabaseTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    r = tool.run({"path": str(tmp_path / "targets" / "weg.json")})
    assert r.is_error and "existiert nicht" in r.content


def test_analyze_database_invalid_json(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeDatabaseTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    p = tmp_path / "targets" / "bad.json"
    p.write_text("nope", encoding="utf-8")
    r = tool.run({"path": str(p)})
    assert r.is_error and "JSON" in r.content


def test_analyze_database_too_large(tmp_path):
    cfg = _cfg(tmp_path, max_file_bytes=5)
    state = EngagementState()
    tool = AnalyzeDatabaseTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "big.json", _db_export())
    r = tool.run({"path": path})
    assert r.is_error and "zu gross" in r.content


def test_analyze_database_no_findings(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeDatabaseTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "clean.json", {"databases": [
        {"engine": "postgresql", "port": 5432, "public": False,
         "auth_required": True, "tls": True}]})
    r = tool.run({"path": path})
    assert not r.is_error and "ohne Befunde" in r.content


# --------------------------- analyze_container ----------------------------

def _container_export():
    return {"containers": [
        {"name": "web", "image": "nginx:latest", "privileged": True,
         "user": "root", "docker_socket_mounted": True}]}


def test_analyze_container_success(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeContainerTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "c.json", _container_export())
    r = tool.run({"path": path})
    assert not r.is_error and "Container-Analyse" in r.content
    assert len(state.findings) >= 3


def test_analyze_container_scope_denied(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeContainerTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    r = tool.run({"path": "/etc/passwd"})
    assert r.is_error and "VERWEIGERT" in r.content


def test_analyze_container_missing_file(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeContainerTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    r = tool.run({"path": str(tmp_path / "targets" / "weg.json")})
    assert r.is_error and "existiert nicht" in r.content


def test_analyze_container_invalid_json(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeContainerTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    p = tmp_path / "targets" / "bad.json"
    p.write_text("nope", encoding="utf-8")
    r = tool.run({"path": str(p)})
    assert r.is_error and "JSON" in r.content


def test_analyze_container_too_large(tmp_path):
    cfg = _cfg(tmp_path, max_file_bytes=5)
    state = EngagementState()
    tool = AnalyzeContainerTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "big.json", _container_export())
    r = tool.run({"path": path})
    assert r.is_error and "zu gross" in r.content


def test_analyze_container_no_findings(tmp_path):
    cfg = _cfg(tmp_path)
    state = EngagementState()
    tool = AnalyzeContainerTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state)
    path = _write_json(tmp_path, "clean.json", {"containers": [
        {"name": "app", "image": "registry.io/app:1.2.3", "privileged": False,
         "host_network": False, "cap_add": [], "user": "1000",
         "docker_socket_mounted": False, "ports": ["127.0.0.1:3000->3000/tcp"]}]})
    r = tool.run({"path": path})
    assert not r.is_error and "ohne Befunde" in r.content


# ------------------------------ run_scanner -------------------------------

def _scanner_tool(cfg, tmp_path, approval=None):
    state = EngagementState()
    tool = RunScannerTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state,
                          approval_fn=approval)
    return tool, state


def test_run_scanner_unknown(tmp_path):
    tool, _ = _scanner_tool(_cfg(tmp_path), tmp_path)
    r = tool.run({"scanner": "metasploit", "target": "127.0.0.1"})
    assert r.is_error and "Unbekannter Scanner" in r.content


def test_run_scanner_disabled(tmp_path):
    tool, _ = _scanner_tool(_cfg(tmp_path), tmp_path)   # keine scanners konfiguriert
    r = tool.run({"scanner": "nmap", "target": "127.0.0.1"})
    assert r.is_error and "nicht freigegeben" in r.content


def test_run_scanner_out_of_scope(tmp_path):
    cfg = _cfg(tmp_path, scanners={"nmap": ScannerPolicy(enabled=True)})
    tool, _ = _scanner_tool(cfg, tmp_path)
    r = tool.run({"scanner": "nmap", "target": "8.8.8.8"})
    assert r.is_error and "VERWEIGERT" in r.content


def test_run_scanner_forbidden_extra_arg(tmp_path):
    cfg = _cfg(tmp_path, scanners={"nmap": ScannerPolicy(enabled=True)})
    tool, _ = _scanner_tool(cfg, tmp_path)
    r = tool.run({"scanner": "nmap", "target": "127.0.0.1", "extra_args": ["-oN", "/etc/x"]})
    assert r.is_error and "VERWEIGERT" in r.content


def test_run_scanner_extra_args_not_list(tmp_path):
    cfg = _cfg(tmp_path, scanners={"nmap": ScannerPolicy(enabled=True)})
    tool, _ = _scanner_tool(cfg, tmp_path)
    r = tool.run({"scanner": "nmap", "target": "127.0.0.1", "extra_args": "nope"})
    assert r.is_error and "Liste" in r.content


def test_run_scanner_approval_rejected(tmp_path):
    cfg = _cfg(tmp_path, scanners={"nmap": ScannerPolicy(enabled=True)})
    tool, _ = _scanner_tool(cfg, tmp_path, approval=lambda _c: False)
    r = tool.run({"scanner": "nmap", "target": "127.0.0.1"})
    assert r.is_error and "abgelehnt" in r.content


def test_run_scanner_success_records_findings(tmp_path):
    cfg = _cfg(tmp_path, scanners={"nmap": ScannerPolicy(enabled=True)})
    tool, state = _scanner_tool(cfg, tmp_path)
    out = "22/tcp open ssh OpenSSH 8.9\n3389/tcp open ms-wbt-server\n"
    fake = subprocess.CompletedProcess([], 0, stdout=out, stderr="")
    with patch("subprocess.run", return_value=fake):
        r = tool.run({"scanner": "nmap", "target": "127.0.0.1", "ports": "22,3389",
                      "rationale": "Portscan"})
    assert not r.is_error
    assert len(state.findings) == 2
    assert len(state.scanner_runs) == 1
    assert state.scanner_runs[0]["scanner"] == "nmap"


def test_run_scanner_truncated_output_note(tmp_path):
    cfg = _cfg(tmp_path, scanners={
        "nmap": ScannerPolicy(enabled=True, max_output_bytes=50)})
    tool, state = _scanner_tool(cfg, tmp_path)
    big = "22/tcp open ssh\n" + ("x" * 500)
    fake = subprocess.CompletedProcess([], 0, stdout=big, stderr="")
    with patch("subprocess.run", return_value=fake):
        r = tool.run({"scanner": "nmap", "target": "127.0.0.1"})
    assert "gekuerzt" in r.content
    assert state.scanner_runs[0]["truncated"] is True


def test_run_scanner_runtime_error(tmp_path):
    cfg = _cfg(tmp_path, scanners={"nmap": ScannerPolicy(enabled=True)})
    tool, _ = _scanner_tool(cfg, tmp_path)
    with patch("subprocess.run", side_effect=FileNotFoundError()):
        r = tool.run({"scanner": "nmap", "target": "127.0.0.1"})
    assert r.is_error and "nicht installiert" in r.content


def test_run_scanner_aggressive_without_optin(tmp_path):
    cfg = _cfg(tmp_path, scanners={"nmap": ScannerPolicy(enabled=True)})
    tool, _ = _scanner_tool(cfg, tmp_path)
    r = tool.run({"scanner": "nmap", "target": "127.0.0.1", "aggressive": True})
    assert r.is_error and "VERWEIGERT" in r.content
