"""Offline-Analyzer fuer bereitgestellte Datenexporte (Active Directory, Exchange).

Rein defensiv: es werden ausschliesslich lokal bereitgestellte Exportdateien
ausgewertet. Keine Live-Verbindungen, keine Ausnutzung, keine Credential-Nutzung.
"""

from .active_directory import analyze_ad
from .exchange import analyze_exchange

__all__ = ["analyze_ad", "analyze_exchange"]
