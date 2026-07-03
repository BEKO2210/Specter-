"""Offline-Analyzer für bereitgestellte Datenexporte (Active Directory, Exchange).

Rein defensiv: es werden ausschließlich lokal bereitgestellte Exportdateien
ausgewertet. Keine Live-Verbindungen, keine Ausnutzung, keine Credential-Nutzung.
"""

from .active_directory import analyze_ad
from .aws import analyze_aws
from .azure import analyze_azure
from .backup import analyze_backup
from .container import analyze_container
from .database import analyze_database
from .dependency import analyze_dependencies
from .dns_security import analyze_dns
from .email_security import analyze_email_security
from .entra_id import analyze_entra
from .exchange import analyze_exchange
from .firewall import analyze_firewall
from .http_headers import analyze_http_headers
from .tls_certificates import analyze_tls

__all__ = [
    "analyze_ad", "analyze_aws", "analyze_azure", "analyze_backup",
    "analyze_container", "analyze_database", "analyze_dependencies",
    "analyze_dns", "analyze_email_security", "analyze_entra",
    "analyze_exchange", "analyze_firewall", "analyze_http_headers", "analyze_tls",
]
