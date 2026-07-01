#!/usr/bin/env python3
"""Specter - CLI-Einstiegspunkt fuer den autonomen Sicherheits-Agenten.

Beispiel:
    export ANTHROPIC_API_KEY=sk-ant-...
    cp scope.example.yaml scope.yaml     # anpassen!
    python main.py --scope scope.yaml \\
        --objective "Pruefe den Code in ./targets auf Sicherheitsluecken."
"""

from __future__ import annotations

import argparse
import sys

from specter.agent import SecurityAgent
from specter.audit import AuditLog
from specter.config import Config, ScopeError
from specter.llm import AnthropicLLM, LLMError


def _make_approval_fn(require_approval: bool):
    if not require_approval:
        return lambda _cmd: True

    def ask(command: str) -> bool:
        try:
            answer = input(f"\n[?] Aktiven Befehl ausfuehren?\n    {command}\n    [j/N] ")
        except EOFError:
            return False
        return answer.strip().lower() in {"j", "ja", "y", "yes"}

    return ask


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Specter - autonomer Sicherheits-Agent (autorisiertes Pentesting)."
    )
    parser.add_argument("--scope", default="scope.yaml", help="Pfad zur Scope-Datei.")
    parser.add_argument(
        "--objective", required=True, help="Auftrag/Ziel fuer den Agenten."
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Bestaetigungen ueberspringen (nur fuer isolierte Testlabore!).",
    )
    args = parser.parse_args(argv)

    try:
        config = Config.load(args.scope)
    except ScopeError as exc:
        print(f"[Scope-Fehler] {exc}", file=sys.stderr)
        return 2

    print("=" * 70)
    print(f" Specter  |  Engagement: {config.engagement.name}")
    print(f" Autorisiert durch: {config.engagement.authorized_by}")
    print(f" Referenz: {config.engagement.authorization_ref}")
    print(f" Modell: {config.model}  |  Max. Iterationen: {config.max_iterations}")
    print("=" * 70)
    print(
        "\nHINWEIS: Nur gegen Systeme einsetzen, fuer die eine schriftliche\n"
        "Genehmigung vorliegt. Aktionen ausserhalb des Scopes werden verweigert.\n"
    )

    require_approval = config.require_approval and not args.yes
    approval_fn = _make_approval_fn(require_approval)

    try:
        llm = AnthropicLLM(model=config.model)
    except LLMError as exc:
        print(f"[LLM-Fehler] {exc}", file=sys.stderr)
        return 3

    audit = AuditLog()
    agent = SecurityAgent(config, llm, audit, approval_fn=approval_fn)

    try:
        summary = agent.run(args.objective)
    except LLMError as exc:
        print(f"[LLM-Fehler] {exc}", file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        print("\n[Abgebrochen durch Benutzer]", file=sys.stderr)
        return 130

    print("\n" + "=" * 70)
    print(" ERGEBNIS")
    print("=" * 70)
    print(summary or "(keine Zusammenfassung)")
    print(f"\nAudit-Log: {audit.path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
