"""Tool: Firewall-/VPN-Konfigurations-Export offline analysieren."""

from __future__ import annotations

from ..analyzers import analyze_firewall
from .base import FileAnalysisTool


class AnalyzeFirewallTool(FileAnalysisTool):
    name = "analyze_firewall"
    label = "Firewall-/VPN-Analyse"
    description = (
        "Analysiert einen bereitgestellten Firewall-/VPN-Konfigurations-Export "
        "(JSON) rein defensiv und erfasst Perimeter-Risiken als Findings: "
        "Any-Any-Regeln, offene RDP-/SSH-Ports und sensible Dienste aus dem "
        "Internet, VPN ohne MFA oder mit schwacher Kryptographie/IKEv1, veraltete "
        "VPN-Gateways sowie öffentlich erreichbare Management-Interfaces. Keine "
        "Live-Verbindung zum Gerät, keine Ausnutzung - nur die lokale Datei im "
        "Scope."
    )
    analyzer = staticmethod(analyze_firewall)
