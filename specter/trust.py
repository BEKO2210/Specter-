"""Vertrauens-/Sicherheits-One-Pager fuer Kunden (HTML -> PDF) + Garantien.

Damit echte Firmen Specter an ihre Systeme lassen, braucht es einen klaren,
kundentauglichen Nachweis, *warum* die Pruefung sicher ist. Dieses Modul
buendelt die technischen Garantien maschinenlesbar (`trust_guarantees()`,
`data_protection_points()`) und erzeugt daraus einen markengerechten,
druckoptimierten One-Pager.

Die Garantien sind keine Marketing-Aussagen, sondern spiegeln das tatsaechliche
Verhalten der Software wider: offline-first, fail-closed Scope, keine
Ausnutzung, aktive Scanner standardmaessig aus, vollstaendiges Audit-Log.
"""

from __future__ import annotations

import datetime as _dt
import html
from pathlib import Path
from typing import Any

from ._brand_asset import SPECTER_MARK_DATA_URI

_MARK_IMG = (
    f'<img src="{SPECTER_MARK_DATA_URI}" alt="Specter" '
    'width="38" height="46" style="display:block">'
)

# Kern-Garantien (Titel, Zusage) - spiegeln das reale Verhalten der Software.
GUARANTEES: list[tuple[str, str]] = [
    ("Offline &amp; lesend",
     "Specter wertet ausschliesslich von Ihnen bereitgestellte Export-Dateien aus. "
     "Es baut keine Live-Verbindung zu Ihren Systemen auf und liest keine "
     "Produktivdaten direkt aus."),
    ("Keine Angriffe (kein Exploit)",
     "Es werden keine Schwachstellen ausgenutzt, keine Passwoerter geknackt, keine "
     "Rechte ausgeweitet, keine Dienste lahmgelegt (kein DoS) und keine Hintertueren "
     "hinterlassen."),
    ("Fail-closed Scope",
     "Nur was in der freigegebenen scope.yaml steht, wird betrachtet. Jede Aktion "
     "ausserhalb des Rahmens wird technisch verweigert - nicht nur unterlassen."),
    ("Aktive Scanner standardmaessig aus",
     "Netzwerk-Scanner (z. B. nmap/nikto) sind deaktiviert und muessen pro Auftrag "
     "ausdruecklich freigeschaltet werden - mit Freigabe und Vier-Augen-Prinzip."),
    ("Keine Veraenderung Ihrer Systeme",
     "Specter aendert, loescht oder installiert nichts in Ihrer Umgebung. Es prueft, "
     "dokumentiert und empfiehlt - die Umsetzung bleibt bei Ihnen."),
    ("Vollstaendiges Audit-Log",
     "Jede ausgefuehrte Aktion wird protokolliert. Sie erhalten auf Wunsch einen "
     "lueckenlosen Nachweis, was wann geprueft wurde."),
]

# Datenschutz-/DSGVO-Zusagen.
DATA_PROTECTION: list[tuple[str, str]] = [
    ("Datenminimierung",
     "Es werden nur die fuer die Pruefung noetigen Export-Dateien angefordert - "
     "nicht mehr."),
    ("Lokale Verarbeitung",
     "Die Auswertung erfolgt in Ihrer bzw. der vereinbarten Umgebung. Daten werden "
     "nicht an unbeteiligte Dritte weitergegeben."),
    ("Loeschkonzept",
     "Bereitgestellte Export-Dateien werden nach Abschluss des Auftrags gemaess "
     "Vereinbarung geloescht."),
    ("Auftragsverarbeitung",
     "Auf Wunsch wird ein Auftragsverarbeitungsvertrag (AVV, Art. 28 DSGVO) "
     "geschlossen."),
    ("Besondere Kategorien",
     "Personenbezogene und besonders schuetzenswerte Daten (Art. 9 DSGVO) werden, "
     "soweit ueberhaupt beruehrt, gesondert behandelt und nicht im Klartext "
     "berichtet."),
]

# Klarstellung, was Specter bewusst NICHT tut.
NOT_DOING: list[str] = [
    "keine Ausnutzung von Schwachstellen",
    "kein Auslesen/Abfluss von Zugangsdaten",
    "keine Denial-of-Service-Tests",
    "keine dauerhafte Einnistung (Persistenz)",
    "keine Rechteausweitung",
    "keine Umgehung von Schutzmechanismen",
]

_CSS = """
:root {
  --navy: #0D1B2A; --charcoal: #1F2937; --teal: #14B8A6;
  --light: #F3F4F6; --white: #FFFFFF; --border: #E5E7EB;
}
* { box-sizing: border-box; }
body {
  font-family: 'Inter', ui-sans-serif, system-ui, -apple-system, 'Segoe UI', sans-serif;
  color: var(--charcoal); margin: 0; padding: 0; line-height: 1.55; background: var(--white);
}
.wrap { max-width: 860px; margin: 0 auto; padding: 40px 32px; }
header.brand {
  display: flex; align-items: center; gap: 14px;
  border-bottom: 3px solid var(--teal); padding-bottom: 16px; margin-bottom: 8px;
}
header.brand .name { font-size: 26px; font-weight: 740; color: var(--navy); letter-spacing: -0.5px; }
header.brand .sub { color: var(--teal); font-size: 13px; font-weight: 600; }
.meta { color: #6B7280; font-size: 13px; margin: 8px 0 24px; }
h1.title { color: var(--navy); font-size: 27px; margin: 20px 0 4px; letter-spacing: -0.5px; }
h1.title + p { font-size: 15px; color: #6B7280; margin: 0 0 16px; }
h2 { color: var(--navy); font-size: 20px; margin: 30px 0 10px; border-left: 4px solid var(--teal); padding-left: 10px; }
p { margin: 8px 0; }
table { border-collapse: collapse; width: 100%; font-size: 13px; margin: 10px 0; }
th, td { border: 1px solid var(--border); padding: 9px 11px; text-align: left; vertical-align: top; }
th { background: var(--light); color: var(--navy); font-weight: 600; }
td.g { font-weight: 700; color: var(--navy); white-space: nowrap; width: 32%; }
.ok { border-left: 4px solid #14B8A6; background: #ECFDF5; padding: 10px 14px; border-radius: 0 6px 6px 0; margin: 14px 0; }
ul { margin: 6px 0; padding-left: 22px; } li { margin: 4px 0; }
.chips span { display: inline-block; background: var(--light); border: 1px solid var(--border);
  border-radius: 999px; padding: 4px 12px; margin: 3px 4px 3px 0; font-size: 12.5px; color: var(--navy); }
footer { margin-top: 36px; padding-top: 16px; border-top: 1px solid var(--border); color: #6B7280; font-size: 12px; }
@media print {
  .wrap { max-width: none; padding: 0 12mm; }
  h2 { page-break-after: avoid; }
  table, .ok { page-break-inside: avoid; }
  a { color: inherit; text-decoration: none; }
}
"""


def _e(text: Any) -> str:
    return html.escape(str(text))


def _now_iso() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d")


def trust_guarantees() -> list[tuple[str, str]]:
    """Maschinenlesbare Kern-Garantien (Titel, Zusage)."""
    return list(GUARANTEES)


def data_protection_points() -> list[tuple[str, str]]:
    """Maschinenlesbare Datenschutz-/DSGVO-Zusagen."""
    return list(DATA_PROTECTION)


def build_trust_html(customer_name: str = "Ihr Unternehmen",
                     generated_at: str | None = None) -> str:
    """Erzeugt den Vertrauens-/Sicherheits-One-Pager als HTML-String."""
    ts = generated_at or _now_iso()
    p: list[str] = []

    p.append("<!doctype html><html lang='de'><head><meta charset='utf-8'>")
    p.append("<title>Specter - Vertrauen &amp; Sicherheit</title>")
    p.append(f"<style>{_CSS}</style></head><body><div class='wrap'>")

    p.append("<header class='brand'>" + _MARK_IMG +
             "<div><div class='name'>Specter</div>"
             "<div class='sub'>Defensive Security Intelligence</div></div></header>")
    p.append(f"<div class='meta'>Vertrauens- &amp; Sicherheitszusage fuer "
             f"{_e(customer_name)} &middot; Stand: {_e(ts)}</div>")

    p.append("<h1 class='title'>Warum Sie Specter an Ihre Systeme lassen koennen</h1>")
    p.append("<p>Eine Pruefung darf niemals selbst zum Risiko werden. Deshalb ist "
             "Specter von Grund auf defensiv gebaut.</p>")

    p.append("<h2>Unsere technischen Garantien</h2>")
    p.append("<table><tr><th>Garantie</th><th>Was das fuer Sie bedeutet</th></tr>")
    for title, detail in GUARANTEES:
        p.append(f"<tr><td class='g'>{title}</td><td>{detail}</td></tr>")
    p.append("</table>")

    p.append("<h2>Was Specter bewusst nicht tut</h2>")
    p.append("<div class='chips'>")
    for item in NOT_DOING:
        p.append(f"<span>&#10007; {_e(item)}</span>")
    p.append("</div>")

    p.append("<h2>Datenschutz (DSGVO)</h2>")
    p.append("<table><tr><th>Prinzip</th><th>Umsetzung</th></tr>")
    for title, detail in DATA_PROTECTION:
        p.append(f"<tr><td class='g'>{_e(title)}</td><td>{detail}</td></tr>")
    p.append("</table>")

    p.append("<h2>Rechtlicher Rahmen</h2>")
    p.append("<p>Jede Pruefung erfolgt ausschliesslich auf Basis einer "
             "<strong>schriftlichen Beauftragung</strong> und innerhalb des "
             "vereinbarten Rahmens (&sect;202a-c StGB). Ohne Freigabe kein Zugriff. "
             "Der Pruefumfang, die Ziele und die Ausnahmen werden vorab festgelegt "
             "und dokumentiert.</p>")

    p.append("<h2>Nachweisbarkeit</h2>")
    p.append("<ul>"
             "<li>Lueckenloses <strong>Audit-Log</strong> aller Aktionen.</li>"
             "<li>Jedes Finding mit <strong>Beleg (Evidenz)</strong>, "
             "CVSS-Einstufung und <strong>BSI-IT-Grundschutz</strong>-Bezug.</li>"
             "<li><strong>Nachtest (Re-Test)</strong> belegt die Behebung nach der "
             "Umsetzung.</li></ul>")

    p.append("<div class='ok'><strong>Kurz gesagt:</strong> Specter prueft wie ein "
             "TueV - gruendlich, nachvollziehbar und ohne Ihre Systeme zu "
             "gefaehrden. Sie behalten jederzeit die Kontrolle.</div>")

    p.append("<footer>Vertrauens- &amp; Sicherheitszusage, erstellt mit Specter "
             "(autorisierte, defensive Sicherheitspruefung). Zur PDF-Ausgabe im "
             "Browser oeffnen und &bdquo;Drucken &rarr; Als PDF speichern&ldquo; "
             "waehlen.</footer>")
    p.append("</div></body></html>")
    return "".join(p)


def write_trust_onepager(directory: str | Path = "reports",
                         customer_name: str = "Ihr Unternehmen") -> Path:
    """Schreibt den Vertrauens-One-Pager als HTML-Datei und gibt den Pfad zurueck."""
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    html_path = out / "specter-vertrauen-onepager.html"
    html_path.write_text(
        build_trust_html(customer_name, _now_iso()), encoding="utf-8")
    return html_path
