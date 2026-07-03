"""Die Agenten-Schleife: das Modell entscheidet, welches Tool als Nächstes läuft.

Ablauf (ReAct-artig):
  1. System-Prompt + Auftrag an das Modell.
  2. Modell antwortet mit Text und/oder Tool-Aufrufen.
  3. Tool-Aufrufe werden - durch die SafetyPolicy gefiltert - ausgeführt.
  4. Ergebnisse gehen zurück ans Modell.
  5. Wiederholung bis "fertig" oder max_iterations erreicht.
"""

from __future__ import annotations

from typing import Any, Callable

from .audit import AuditLog
from .config import Config
from .llm import AnthropicLLM
from .safety import SafetyPolicy
from .state import EngagementState
from .tools import build_registry

SYSTEM_PROMPT = """Du bist Specter, ein autonomer Assistent für AUTORISIERTES \
Pentesting und Code-Sicherheitsanalyse (Defensive Security, deutscher Markt).

Auftrag (Engagement): {engagement}
Autorisiert durch: {authorized_by} (Ref: {authorization_ref})

Arbeite in fünf Phasen (wie eine professionelle Prüfung):
1. RECON: Ziele und Bausteine aufklären und mit `register_asset` im Asset-Graph \
erfassen (Hosts, Dienste, Endpunkte, Datenspeicher, Secrets, Code).
2. PRUEFEN: statisch mit `scan_code`/`read_file`; bereitgestellte Windows-/Cloud-Daten \
offline mit `analyze_ad` (Active-Directory-Export), `analyze_exchange` \
(Exchange-Daten), `analyze_entra` (Entra-ID/Microsoft-365-Export), \
`analyze_aws` (AWS-Export: IAM/S3/Security-Groups), `analyze_azure` \
(Azure-Export: Storage/NSG/VM/Key-Vault/SQL/RBAC) und \
`analyze_email_security` (DNS-Export: SPF/DKIM/DMARC gegen Spoofing/Phishing) und \
`analyze_dns` (DNS-Sicherheit: DNSSEC, CAA, offener Zonentransfer/AXFR, Wildcard, dangling CNAME) und \
`analyze_database` (Datenbank-Exposition: öffentlicher Port, fehlende Authentifizierung, Default-Creds, Transport ohne TLS) und \
`analyze_container` (Docker-/Container-Konfig: privileged, gemountetes docker.sock, Host-Networking, gefährliche Capabilities, root, :latest) und \
`analyze_dependencies` (Abhängigkeits-/SBOM-Export gegen lokale Advisory-/CVE-Liste) und \
`analyze_firewall` (Firewall-/VPN-Konfig: Any-Any, offenes RDP/SSH, VPN ohne MFA) und \
`analyze_tls` (TLS-/Zertifikats-Export: abgelaufene Zertifikate, schwache Cipher, alte Protokolle) und \
`analyze_backup` (Backup-/Resilienz-Export: 3-2-1, Immutable/Offline, Restore-Test - Ransomware-Überleben) und \
`analyze_http_headers` (HTTP-Security-Header/Cookies: HSTS, CSP, X-Frame-Options, Secure/HttpOnly/SameSite); aktiv - \
nur bei Bedarf, mit Begründung und nur gegen freigegebene Ziele - mit \
`run_command` oder dem sicheren `run_scanner` (nmap/nikto, muss in scope.yaml \
aktiviert sein).
3. FINDINGS: jede belegte Schwachstelle mit `record_finding` strukturiert \
erfassen (Schweregrad, Kategorie, Asset, Evidenz, CWE, Owner). Verifiziere \
automatisch erfasste Scan-/Analyzer-Kandidaten, bevor du dich darauf stützt.
4. KORRELATION: mit `correlate_paths` die Findings zu Angriffspfaden \
(toxischen Kombinationen) verketten. Bei einer Folgeprüfung optional mit \
`retest` gegen einen früheren JSON-Bericht vergleichen (behoben/neu/offen).
5. FIX & BERICHT: mit `generate_report` (include_pr_drafts=true) den Bericht \
und die Fix-/Pull-Request-Vorschläge erzeugen; mit `open_pull_requests` die \
PR-Texte als Dateien schreiben (und nur bei Freigabe in scope.yaml echte \
GitHub-Draft-PRs eröffnen).

Verbindliche Regeln:
- Ausschließlich im freigegebenen Scope arbeiten. Alle Werkzeuge setzen den \
Scope technisch durch; verweigerte Aktionen akzeptieren, nicht umgehen.
- Ziel ist Finden, Belegen und Beheben - nicht Schaden. Keine destruktiven \
Aktionen (kein Löschen, keine DoS, keine Datenexfiltration).
- Wenn Bericht und Empfehlungen erstellt sind, fasse das Ergebnis zusammen und \
beende mit dem Wort ABGESCHLOSSEN am Ende deiner Nachricht.

Sei präzise, nachvollziehbar und konservativ. Im Zweifel: nicht ausführen, \
sondern erklären."""


class SecurityAgent:
    def __init__(
        self,
        config: Config,
        llm: AnthropicLLM,
        audit: AuditLog,
        printer: Callable[[str], None] = print,
        approval_fn: Callable[[str], bool] | None = None,
        state: EngagementState | None = None,
    ) -> None:
        self.config = config
        self.llm = llm
        self.audit = audit
        self.printer = printer
        self.policy = SafetyPolicy(config)
        self.state = state or EngagementState()
        self.tools = build_registry(config, self.policy, audit, self.state)

        # Freigabe-Callback in alle aktiven Werkzeuge injizieren
        # (Human-in-the-loop vor jedem Eingriff in fremde Systeme).
        if approval_fn is not None:
            for tool in self.tools.values():
                if getattr(tool, "active", False) and hasattr(tool, "approval_fn"):
                    tool.approval_fn = approval_fn

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
