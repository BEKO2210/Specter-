#!/usr/bin/env python3
"""Self-Audit: Specter prueft den EIGENEN Quellcode.

Ein Reifenachweis fuer Kundengespraeche - wir setzen unser Werkzeug auf uns
selbst an. Der Datei-Scope zeigt ausschliesslich auf `specter/`; es werden
keine fremden Systeme und keine Netzwerkziele beruehrt.

Zwei Betriebsarten (dieselbe Scope-Datei examples/self_audit_scope.yaml):

  1. OHNE API-Key (Standard): deterministischer statischer Selbst-Scan.
         python examples/self_audit.py

  2. MIT API-Key: zusaetzlich der voll autonome KI-Lauf, gesteuert von dem in
     der Scope-Datei gewaehlten Modell (per Default `claude-fable-5`):
         export ANTHROPIC_API_KEY=sk-ant-...
         python examples/self_audit.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Repo-Wurzel in den Importpfad aufnehmen.
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from specter.audit import AuditLog                 # noqa: E402
from specter.config import Config                  # noqa: E402
from specter.safety import SafetyPolicy            # noqa: E402
from specter.state import EngagementState          # noqa: E402
from specter.tools.base import build_registry      # noqa: E402

SCOPE = REPO_ROOT / "examples" / "self_audit_scope.yaml"


def _summary_line(state: EngagementState) -> str:
    counts = state.findings.counts()
    return (
        f" Findings: {len(state.findings)}  "
        f"(Kritisch {counts.get('Kritisch', 0)}, Hoch {counts.get('Hoch', 0)}, "
        f"Mittel {counts.get('Mittel', 0)}, Niedrig {counts.get('Niedrig', 0)})"
    )


def deterministic_audit(config: Config, audit: AuditLog) -> EngagementState:
    """Ohne API-Key: statischer Selbst-Scan ueber den eigenen Code."""
    state = EngagementState()
    policy = SafetyPolicy(config)
    tools = build_registry(config, policy, audit, state)

    print("\n--- RECON: eigener Quellcode als Asset ---")
    print(tools["register_asset"].run(
        {"type": "code", "name": "specter", "note": "Specter-Quellcode (Self-Audit)"}
    ).content)

    print("\n--- SCAN: statische Codeanalyse ueber specter/ ---")
    print(tools["scan_code"].run({"path": str(REPO_ROOT / "specter")}).content)

    print("\n" + "=" * 70)
    print(" Statischer Selbst-Scan abgeschlossen.")
    print(_summary_line(state))
    print(" Hinweis: statische Treffer sind Kandidaten und muessen verifiziert")
    print(" werden (z. B. Muster-Definitionen im Scanner selbst sind erwartbar).")
    print("=" * 70)
    return state


def ai_audit(config: Config, audit: AuditLog) -> EngagementState:
    """Mit API-Key: voll autonomer Lauf, gesteuert vom konfigurierten Modell."""
    from specter.agent import SecurityAgent
    from specter.llm import AnthropicLLM

    llm = AnthropicLLM(model=config.model)
    state = EngagementState()
    agent = SecurityAgent(config, llm, audit, approval_fn=lambda _c: True, state=state)
    objective = (
        "Auditiere den Specter-Quellcode in ./specter rein statisch (White-Box). "
        "Erfasse die relevanten Bausteine als Assets, scanne den Code, belege "
        "jede plausible Schwachstelle mit einem Finding, korreliere die Findings "
        "zu Angriffspfaden und erstelle abschliessend den Bericht."
    )
    print(f"\n[KI-Lauf mit Modell: {config.model}]")
    summary = agent.run(objective)
    print("\n--- ZUSAMMENFASSUNG DES KI-LAUFS ---")
    print(summary or "(keine Zusammenfassung)")
    print("\n" + "=" * 70)
    print(_summary_line(state))
    print("=" * 70)
    return state


def main() -> int:
    print("=" * 70)
    print(" Specter - Self-Audit (das Werkzeug prueft sich selbst)")
    print("=" * 70)

    config = Config.load(SCOPE)
    audit = AuditLog(REPO_ROOT / "audit")
    print(f" Datei-Scope: specter/   ·   Modell fuer den KI-Lauf: {config.model}")

    deterministic_audit(config, audit)

    if os.environ.get("ANTHROPIC_API_KEY"):
        print(f"\n[i] ANTHROPIC_API_KEY erkannt - starte zusaetzlich den autonomen "
              f"KI-Lauf mit {config.model} ...")
        ai_audit(config, audit)
    else:
        print(f"\n[i] Kein ANTHROPIC_API_KEY gesetzt - der autonome KI-Lauf mit "
              f"{config.model} wird uebersprungen.")
        print("    Zum Aktivieren des vollen KI-Audits:")
        print("      export ANTHROPIC_API_KEY=sk-ant-...")
        print("      python examples/self_audit.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
