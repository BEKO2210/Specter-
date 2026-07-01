"""Die Agenten-Schleife: das Modell entscheidet, welches Tool als Naechstes laeuft.

Ablauf (ReAct-artig):
  1. System-Prompt + Auftrag an das Modell.
  2. Modell antwortet mit Text und/oder Tool-Aufrufen.
  3. Tool-Aufrufe werden - durch die SafetyPolicy gefiltert - ausgefuehrt.
  4. Ergebnisse gehen zurueck ans Modell.
  5. Wiederholung bis "fertig" oder max_iterations erreicht.
"""

from __future__ import annotations

from typing import Any, Callable

from .audit import AuditLog
from .config import Config
from .llm import AnthropicLLM
from .safety import SafetyPolicy
from .tools import build_registry
from .tools.run_command import RunCommandTool

SYSTEM_PROMPT = """Du bist Specter, ein autonomer Assistent fuer AUTORISIERTES \
Pentesting und Code-Sicherheitsanalyse (Defensive Security).

Auftrag (Engagement): {engagement}
Autorisiert durch: {authorized_by} (Ref: {authorization_ref})

Verbindliche Regeln:
- Arbeite ausschliesslich innerhalb des freigegebenen Scopes. Alle Werkzeuge \
setzen den Scope technisch durch; Aktionen ausserhalb werden verweigert - \
versuche nicht, sie zu umgehen.
- Gehe methodisch vor: erst aufklaeren/lesen (read_file, scan_code), dann - nur \
wenn noetig - aktiv pruefen (run_command). Begruende aktive Schritte.
- Ziel ist das Finden UND Belegen von Schwachstellen sowie das Empfehlen von \
Gegenmassnahmen - nicht das Anrichten von Schaden. Keine destruktiven Aktionen \
(kein Loeschen, keine DoS, keine Datenexfiltration).
- Wenn ein Werkzeug "VERWEIGERT" meldet, akzeptiere das und waehle einen \
anderen, zulaessigen Weg.
- Wenn du genug Erkenntnisse hast, fasse zusammen: gefundene Schwachstellen \
(mit Beleg/Fundstelle und Schweregrad) und konkrete Empfehlungen. Beende dann \
mit dem Wort ABGESCHLOSSEN am Ende deiner Nachricht.

Sei praezise, nachvollziehbar und konservativ. Im Zweifel: nicht ausfuehren, \
sondern erklaeren."""


class SecurityAgent:
    def __init__(
        self,
        config: Config,
        llm: AnthropicLLM,
        audit: AuditLog,
        printer: Callable[[str], None] = print,
        approval_fn: Callable[[str], bool] | None = None,
    ) -> None:
        self.config = config
        self.llm = llm
        self.audit = audit
        self.printer = printer
        self.policy = SafetyPolicy(config)
        self.tools = build_registry(config, self.policy, audit)

        # Freigabe-Callback in das aktive Befehlstool injizieren.
        if approval_fn is not None:
            cmd_tool = self.tools.get("run_command")
            if isinstance(cmd_tool, RunCommandTool):
                cmd_tool.approval_fn = approval_fn

    @property
    def _system(self) -> str:
        eng = self.config.engagement
        return SYSTEM_PROMPT.format(
            engagement=eng.name,
            authorized_by=eng.authorized_by,
            authorization_ref=eng.authorization_ref,
        )

    def run(self, objective: str) -> str:
        self.audit.record(
            "agent.start",
            engagement=self.config.engagement.name,
            objective=objective,
        )
        messages: list[dict[str, Any]] = [{"role": "user", "content": objective}]
        specs = [t.spec for t in self.tools.values()]
        final_text = ""

        for iteration in range(1, self.config.max_iterations + 1):
            self.printer(f"\n=== Iteration {iteration}/{self.config.max_iterations} ===")
            response = self.llm.create(self._system, messages, specs)

            assistant_content: list[dict[str, Any]] = []
            tool_uses: list[Any] = []
            for block in response.content:
                if block.type == "text":
                    assistant_content.append({"type": "text", "text": block.text})
                    if block.text.strip():
                        self.printer(block.text.strip())
                        final_text = block.text.strip()
                elif block.type == "tool_use":
                    assistant_content.append(
                        {
                            "type": "tool_use",
                            "id": block.id,
                            "name": block.name,
                            "input": block.input,
                        }
                    )
                    tool_uses.append(block)

            messages.append({"role": "assistant", "content": assistant_content})

            # Kein Tool-Aufruf oder explizit fertig -> Ende.
            if not tool_uses or (response.stop_reason != "tool_use"):
                if "ABGESCHLOSSEN" in final_text or not tool_uses:
                    break

            tool_results: list[dict[str, Any]] = []
            for use in tool_uses:
                tool = self.tools.get(use.name)
                if tool is None:
                    result_text, is_error = f"Unbekanntes Tool: {use.name}", True
                else:
                    self.printer(f"-> {use.name}({_short(use.input)})")
                    result = tool.run(dict(use.input))
                    result_text, is_error = result.content, result.is_error
                    self.printer(f"<- {_short(result_text)}")
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": use.id,
                        "content": result_text,
                        "is_error": is_error,
                    }
                )
            messages.append({"role": "user", "content": tool_results})
        else:
            self.printer("\n[!] max_iterations erreicht - Schleife gestoppt.")
            self.audit.record("agent.max_iterations")

        self.audit.record("agent.finish", summary=final_text[:2000])
        return final_text


def _short(value: Any, limit: int = 300) -> str:
    text = str(value).replace("\n", " ")
    return text if len(text) <= limit else text[:limit] + " ..."
