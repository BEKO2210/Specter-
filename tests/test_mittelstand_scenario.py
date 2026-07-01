"""Szenario-Tests: vollstaendiges Engagement gegen einen deutschen Mittelstaendler.

Deckt die typische Angriffsflaeche der Muster-GmbH ab: Webshop, Kunden-API,
ERP/DATEV, Infrastruktur (RDP/DB offen), personenbezogene Daten (DSGVO),
veraltete Komponenten - inklusive der realistischen Angriffspfade.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from specter.agent import SecurityAgent
from specter.attack_paths import correlate
from specter.audit import AuditLog
from specter.safety import SafetyPolicy
from specter.state import EngagementState
from specter.tools.base import build_registry

MITTELSTAND_FIXTURE = Path(__file__).parent / "fixtures" / "mittelstand"


# -- Hilfen fuer die simulierte Agenten-Steuerung --------------------------

def _text(t):
    return SimpleNamespace(type="text", text=t)


def _tool(tid, name, inp):
    return SimpleNamespace(type="tool_use", id=tid, name=name, input=inp)


def _resp(blocks, stop_reason):
    return SimpleNamespace(content=blocks, stop_reason=stop_reason)


class FakeLLM:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def create(self, system, messages, tools):
        self.calls.append(messages)
        return self._responses.pop(0)


def _tools(ms_config, tmp_path):
    state = EngagementState()
    audit = AuditLog(tmp_path / "audit")
    reg = build_registry(ms_config, SafetyPolicy(ms_config), audit, state)
    return reg, state


# -- Statischer White-Box-Scan der Muster-GmbH -----------------------------

def test_scan_covers_full_attack_surface(ms_config, tmp_path):
    reg, state = _tools(ms_config, tmp_path)
    reg["scan_code"].run({"path": str(MITTELSTAND_FIXTURE)})

    cats = {f.category for f in state.findings.all()}
    # Die fuer den Mittelstand typischen Klassen muessen auftauchen.
    for expected in {
        "secret_exposure", "injection", "crypto_weakness",
        "default_credentials", "personal_data", "outdated_component",
    }:
        assert expected in cats, f"Kategorie fehlt: {expected}"
    assert len(state.findings) >= 12


def test_no_false_positives_on_clean_file(ms_config, tmp_path):
    reg, state = _tools(ms_config, tmp_path)
    clean = MITTELSTAND_FIXTURE / "api" / "utils_clean.py"
    reg["scan_code"].run({"path": str(clean)})
    assert len(state.findings) == 0


def test_secrets_found_in_env(ms_config, tmp_path):
    reg, state = _tools(ms_config, tmp_path)
    reg["scan_code"].run({"path": str(MITTELSTAND_FIXTURE / "infra" / ".env")})
    secrets = [f for f in state.findings.all() if f.category == "secret_exposure"]
    assert len(secrets) >= 3          # JWT, AWS, SMTP, Stripe ...


# -- Realistische Angriffspfade des Mittelstands ---------------------------

def test_dsgvo_breach_path(ms_config, tmp_path):
    reg, state = _tools(ms_config, tmp_path)
    reg["scan_code"].run({"path": str(MITTELSTAND_FIXTURE)})
    # Webshop-SQLi + personenbezogene Daten -> DSGVO-Meldepflicht.
    paths = correlate(state.findings, state.assets)
    assert any("DSGVO" in p.title for p in paths)


def test_domain_takeover_via_rdp(ms_config, tmp_path):
    reg, state = _tools(ms_config, tmp_path)
    reg["scan_code"].run({"path": str(MITTELSTAND_FIXTURE)})
    # Aktiv erkannter offener RDP-Zugang als Finding erfassen ...
    reg["record_finding"].run({
        "title": "RDP-Gateway offen im Internet", "category": "remote_access",
        "severity": "hoch", "asset": "10.10.0.5",
        "location": "10.10.0.5:3389", "evidence": "3389/tcp open ms-wbt-server",
    })
    paths = correlate(state.findings, state.assets)
    # Zusammen mit Default-Credentials aus dem Scan -> Domaenenuebernahme.
    assert any("Domänenübernahme" in p.title for p in paths)


def test_outdated_component_path(ms_config, tmp_path):
    reg, state = _tools(ms_config, tmp_path)
    reg["scan_code"].run({"path": str(MITTELSTAND_FIXTURE)})
    reg["record_finding"].run({
        "title": "MySQL 5.6 aus dem Internet erreichbar",
        "category": "exposed_service", "severity": "hoch",
        "asset": "10.10.0.5", "location": "10.10.0.5:3306",
    })
    paths = correlate(state.findings, state.assets)
    assert any("veralteter Komponente" in p.title for p in paths)


# -- Vollstaendiger autonomer Lauf (simuliertes LLM) -----------------------

def test_full_autonomous_engagement(ms_config, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    state = EngagementState()
    audit = AuditLog(tmp_path / "audit")

    llm = FakeLLM([
        _resp([_tool("a1", "register_asset",
                     {"type": "code", "name": "mustermann-webshop"})], "tool_use"),
        _resp([_tool("a2", "register_asset",
                     {"type": "host", "name": "10.10.0.5", "note": "Server DMZ"})], "tool_use"),
        _resp([_tool("s1", "scan_code",
                     {"path": str(MITTELSTAND_FIXTURE)})], "tool_use"),
        _resp([_tool("f1", "record_finding",
                     {"title": "RDP offen", "category": "remote_access",
                      "severity": "hoch", "asset": "10.10.0.5",
                      "location": "10.10.0.5:3389"})], "tool_use"),
        _resp([_tool("c1", "correlate_paths", {})], "tool_use"),
        _resp([_tool("r1", "generate_report",
                     {"include_pr_drafts": True})], "tool_use"),
        _resp([_text("Engagement abgeschlossen. ABGESCHLOSSEN")], "end_turn"),
    ])
    agent = SecurityAgent(ms_config, llm, audit, printer=lambda _m: None, state=state)
    summary = agent.run("Fuehre einen vollstaendigen Pentest der Mustermann GmbH durch.")

    assert "ABGESCHLOSSEN" in summary
    assert len(state.findings) >= 12
    assert len(state.attack_paths) >= 3
    titles = {p.title for p in state.attack_paths}
    assert any("DSGVO" in t for t in titles)
    assert any("Domänenübernahme" in t for t in titles)
    # Bericht wurde geschrieben.
    assert (tmp_path / "reports").exists()


def test_report_contains_dsgvo_and_bsi_framing(ms_config, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    reg, state = _tools(ms_config, tmp_path)
    reg["scan_code"].run({"path": str(MITTELSTAND_FIXTURE)})
    reg["correlate_paths"].run({})
    reg["generate_report"].run({})
    md = sorted((tmp_path / "reports").glob("*.md"))[-1].read_text(encoding="utf-8")
    assert "DSGVO" in md
    assert "BSI IT-Grundschutz" in md
    assert "Management-Zusammenfassung" in md
