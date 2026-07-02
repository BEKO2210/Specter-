"""Offline-Analyzer fuer bereitgestellte Datenexporte (Active Directory, Exchange).

Rein defensiv: es werden ausschliesslich lokal bereitgestellte Exportdateien
ausgewertet. Keine Live-Verbindungen, keine Ausnutzung, keine Credential-Nutzung.
"""

from .active_directory import analyze_ad
from .aws import analyze_aws
from .azure import analyze_azure
from .dependency import analyze_dependencies
from .email_security import analyze_email_security
from .entra_id import analyze_entra
from .exchange import analyze_exchange
from .firewall import analyze_firewall

__all__ = [
    "analyze_ad", "analyze_aws", "analyze_azure", "analyze_dependencies",
    "analyze_email_security", "analyze_entra", "analyze_exchange",
    "analyze_firewall",
]
