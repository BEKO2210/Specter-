"""Tests für die Agenten-Schleife mit einem simulierten LLM (kein API-Key nötig).

Bildet die echten Anthropic-Response-Objekte nach (content-Bloecke mit .type,
.text bzw. .id/.name/.input und .stop_reason), damit die vollständige
5-Phasen-Schleife inklusive Tool-Ausführung getestet werden kann.
"""

from __future__ import annotations

from types import SimpleNamespace

from specter.agent import SecurityAgent
from specter.audit import AuditLog
from specter.state import EngagementState


def _text(t):
    return SimpleNamespace(type="text", text=t)


def _tool(tid, name, inp):
    return SimpleNamespace(type="tool_use", id=tid, name=name, input=inp)


def _resp(blocks, stop_reason):
    return SimpleNamespace(content=blocks, stop_reason=stop_reason)


class FakeLLM:
    """Gibt eine vorgegebene Sequenz von Antworten zurück."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def create(self, system, messages, tools):
        self.calls.append({"system": system, "messages": messages, "tools": tools})
        return self._responses.pop(0)


def _agent(config, llm, tmp_path, state=None):
    audit = AuditLog(tmp_path / "audit")
    return SecurityAgent(
        config, llm, audit,
        printer=lambda _m: None,
        state=state or EngagementState(),
    )


def test_agent_runs_full_pipeline(config, tmp_path, targets_dir, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config.max_iterations = 10        # Pipeline braucht 6 LLM-Runden
    (targets_dir / "vuln.py").write_text('API_KEY = "sk-live-abc123def"\n')

    state = EngagementState()
    llm = FakeLLM([
        # 1) Recon
        _resp([_tool("t1", "register_asset",
                     {"type": "code", "name": "vuln.py"})], "tool_use"),
        # 2) Scan (erfasst Finding automatisch)
        _resp([_tool("t2", "scan_code", {"path": str(targets_dir)})], "tool_use"),
        # 3) Netzwerk-Finding erfassen
        _resp([_tool("t3", "record_finding",
                     {"title": "SSH offen", "category": "exposed_service",
                      "severity": "hoch", "asset": "127.0.0.1",
                      "location": "127.0.0.1:22"})], "tool_use"),
        # 4) Korrelation
        _resp([_tool("t4", "correlate_paths", {})], "tool_use"),
        # 5) Bericht
        _resp([_tool("t5", "generate_report", {"include_pr_drafts": True})], "tool_use"),
        # Abschluss
        _resp([_text("Prüfung fertig. ABGESCHLOSSEN")], "end_turn"),
    ])
    agent = _agent(config, llm, tmp_path, state)
    summary = agent.run("Prüfe die Anwendung.")

    assert "ABGESCHLOSSEN" in summary
    assert len(state.assets) >= 1
    assert len(state.findings) >= 2            # Secret (Scan) + SSH (manuell)
    assert len(state.attack_paths) >= 1        # toxische Kombination
    assert (tmp_path / "reports").exists()


def test_agent_stops_on_abgeschlossen_without_tools(config, tmp_path):
    llm = FakeLLM([_resp([_text("Nichts zu tun. ABGESCHLOSSEN")], "end_turn")])
    agent = _agent(config, llm, tmp_path)
    summary = agent.run("x")
    assert "ABGESCHLOSSEN" in summary
    assert len(llm.calls) == 1


def test_agent_handles_unknown_tool(config, tmp_path):
    llm = FakeLLM([
        _resp([_tool("t1", "gibt_es_nicht", {})], "tool_use"),
        _resp([_text("ok ABGESCHLOSSEN")], "end_turn"),
    ])
    agent = _agent(config, llm, tmp_path)
    summary = agent.run("x")
    assert "ABGESCHLOSSEN" in summary


def test_agent_respects_max_iterations(config, tmp_path, targets_dir):
    config.max_iterations = 3
    # Immer wieder ein Tool aufrufen, nie abschließen -> Grenze greift.
    def endless():
        while True:
            yield _resp([_tool("t", "register_asset",
                               {"type": "host", "name": "127.0.0.1"})], "tool_use")

    gen = endless()
    llm = FakeLLM([next(gen) for _ in range(10)])
    agent = _agent(config, llm, tmp_path)
    agent.run("x")
    assert len(llm.calls) == 3                 # exakt max_iterations Aufrufe


def test_agent_injects_approval_fn(config, tmp_path):
    calls = []
    llm = FakeLLM([_resp([_text("ABGESCHLOSSEN")], "end_turn")])
    audit = AuditLog(tmp_path / "audit")
    agent = SecurityAgent(config, llm, audit, printer=lambda _m: None,
                          approval_fn=lambda c: calls.append(c) or True)
    # Das run_command-Tool muss GENAU die injizierte Approval-Funktion
    # erhalten haben (durch die SafeTool-Hülle hindurch, unter .inner).
    from specter.tools.run_command import RunCommandTool
    injected = agent.approval_fn if hasattr(agent, "approval_fn") else None
    cmd_tool = agent.tools["run_command"].inner
    assert isinstance(cmd_tool, RunCommandTool)
    # Der Callback ist nicht mehr der Default — er ruft unser calls.append auf.
    cmd_tool.approval_fn("nmap -sV 127.0.0.1")
    assert calls == ["nmap -sV 127.0.0.1"]
