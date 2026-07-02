"""Zielkunden-/Akquiseplan als markengerechtes HTML (-> PDF).

Ein interner Vertriebs-Leitfaden für die Neukundengewinnung im Mittelstand
(Schwerpunkt Ludwigsburg/Stuttgart): idealer Zielkunde, Zielbranchen, wo man
sie findet, ein konkreter Akquiseprozess, Nachfass-Rhythmus, Einwand-Antworten
und der rechtliche Rahmen (UWG). Im Browser über "Drucken -> Als PDF speichern"
zu einem sauberen Handout.
"""

from __future__ import annotations

import datetime as _dt
import html
from pathlib import Path
from typing import Any

from ._brand_asset import SPECTER_MARK_DATA_URI

_MARK_IMG = (
    f'<img src="{SPECTER_MARK_DATA_URI}" alt="Specter" '
    'width="34" height="41" style="display:block">'
)

# Merkmale des idealen Zielkunden.
ICP: list[str] = [
    "20–250 Mitarbeitende (groß genug für Budget, zu klein für eigenes Security-Team)",
    "Region Ludwigsburg/Stuttgart und Umkreis (persönliche Termine möglich)",
    "Arbeitet stark mit E-Mail, Microsoft 365 und Fernzugriff",
    "Verarbeitet sensible oder personenbezogene Daten (DSGVO-Druck)",
    "Hat oder braucht eine Cyber-Versicherung (Nachweispflichten)",
    "Kein spezialisiertes IT-Sicherheitspersonal im Haus",
]

# Zielbranchen: (Branche, warum besonders passend).
INDUSTRIES: list[tuple[str, str]] = [
    ("Steuerberater & Kanzleien", "Hochsensible Mandantendaten, strenge Verschwiegenheit, oft veraltete IT."),
    ("Versicherungsmakler & Finanzberater", "Kennen Cyber-Risiken, brauchen selbst saubere Nachweise."),
    ("Arztpraxen, MVZ & Pflegedienste", "Gesundheitsdaten (Art. 9 DSGVO), häufige Ransomware-Ziele."),
    ("Maschinenbau- & Automotive-Zulieferer", "Wertvolles Know-how, Lieferketten-Anforderungen (TISAX)."),
    ("Autohäuser & Kfz-Betriebe", "Viel Kundendaten, oft offene Fernwartung."),
    ("Handwerk & Mittelstand mit Onlineshop", "Zahlungsdaten, geringe Absicherung, hohe Ausfallkosten."),
    ("Immobilienverwalter & Hausverwaltungen", "Personenbezogene Daten vieler Mieter/Eigentümer."),
    ("Logistik & Spedition", "Ausfall = sofortiger Stillstand, hohe Ransomware-Motivation."),
]

# Wo man Zielkunden findet.
CHANNELS: list[str] = [
    "IHK-Firmenverzeichnis & Handelsregister (Region filtern)",
    "Google Maps/Branchensuche nach Ort + Branche",
    "LinkedIn (Geschäftsführer/IT-Leitung, lokale Gruppen)",
    "Wirtschaftsförderung & Gewerbevereine Ludwigsburg/Stuttgart",
    "Branchenverbände und lokale Unternehmer-Netzwerke (BNI, Rotary, Xing-Events)",
    "Empfehlungen bestehender Kontakte (der stärkste Kanal)",
]

# Akquiseprozess in Schritten: (Titel, Beschreibung).
PROCESS: list[tuple[str, str]] = [
    ("Liste aufbauen",
     "20–30 passende Firmen je Woche recherchieren (Name, Domain, Ansprechpartner, Quelle)."),
    ("Live-Check als Aufhänger",
     "Für jede Domain den kostenlosen E-Mail-Check laufen lassen "
     "(python examples/live_email_check.py) und das Ergebnis notieren."),
    ("Warmer Erstkontakt",
     "Erst über Empfehlung/LinkedIn/Anruf einen Anknüpfungspunkt schaffen, "
     "dann die personalisierte Erstkontakt-Mail schicken (build_outreach_email)."),
    ("Termin & Vertrauen",
     "Im Gespräch den Vertrauens-One-Pager und das Angebot zeigen; "
     "defensiv, offline, DSGVO betonen."),
    ("Einstieg verkaufen",
     "Mit dem Basis-Audit als niedrigschwelligem Einstieg starten, Voll-Audit als Upsell."),
    ("Nachfassen & binden",
     "Nach dem Audit Nachtest anbieten, jährliche Wiederholung und Empfehlungen erbitten."),
]

# Nachfass-Rhythmus: (Zeitpunkt, Aktion).
CADENCE: list[tuple[str, str]] = [
    ("Tag 0", "Erstkontakt (nach warmem Anknüpfungspunkt)."),
    ("Tag 3", "Freundliche Erinnerung mit konkretem Nutzen (Live-Check-Ergebnis)."),
    ("Tag 10", "Letzter kurzer Hinweis + Angebot eines 10-Minuten-Telefonats."),
    ("danach", "Kein weiterer Kontakt, außer der Kunde meldet Interesse."),
]

# Typische Einwände und knappe Antworten.
OBJECTIONS: list[tuple[str, str]] = [
    ("„Wir haben schon eine IT-Firma.“",
     "Gut — ich ergänze sie mit einem unabhängigen Sicherheitsblick, kein Ersatz."),
    ("„Wir sind zu klein, uns greift keiner an.“",
     "Gerade kleine Firmen sind Ziel automatisierter Angriffe (E-Mail, RDP)."),
    ("„Ist das nicht gefährlich/illegal?“",
     "Rein defensiv, nur mit Ihrer schriftlichen Freigabe, kein Eingriff (§202 StGB)."),
    ("„Keine Zeit/kein Budget.“",
     "Der Erst-Check ist kostenlos und dauert Minuten; Sie entscheiden danach."),
]

_CSS = """
:root{--navy:#0D1B2A;--charcoal:#1F2937;--teal:#14B8A6;--teal-d:#0E9384;
  --light:#F3F4F6;--white:#FFF;--border:#E5E7EB;--muted:#6B7280;}
*{box-sizing:border-box}
body{font-family:'Inter',ui-sans-serif,system-ui,-apple-system,'Segoe UI',sans-serif;
  color:var(--charcoal);margin:0;line-height:1.55;background:var(--white)}
.wrap{max-width:900px;margin:0 auto;padding:40px 32px}
header.brand{display:flex;align-items:center;gap:14px;border-bottom:3px solid var(--teal);
  padding-bottom:16px;margin-bottom:8px}
header.brand .name{font-size:26px;font-weight:740;color:var(--navy);letter-spacing:-.5px}
header.brand .sub{color:var(--teal);font-size:13px;font-weight:600}
.meta{color:var(--muted);font-size:13px;margin:8px 0 22px}
h1.title{color:var(--navy);font-size:28px;margin:20px 0 4px;letter-spacing:-.5px}
h1.title + p{color:var(--muted);font-size:15px;margin:0 0 20px;max-width:56ch}
h2{color:var(--navy);font-size:19px;margin:30px 0 12px;border-left:4px solid var(--teal);padding-left:10px}
ul{margin:6px 0;padding-left:20px}li{margin:5px 0}
table{border-collapse:collapse;width:100%;font-size:13.5px;margin:6px 0}
th,td{border:1px solid var(--border);padding:9px 11px;text-align:left;vertical-align:top}
th{background:var(--light);color:var(--navy);font-weight:600}
td.n{white-space:nowrap;font-weight:700;color:var(--navy);width:22%}
ol.steps{margin:6px 0;padding-left:22px}ol.steps li{margin:7px 0}
ol.steps b{color:var(--navy)}
.trust{background:var(--light);border-left:4px solid var(--teal);border-radius:0 8px 8px 0;
  padding:12px 16px;font-size:13.5px;margin-top:8px}
footer{margin-top:34px;padding-top:16px;border-top:1px solid var(--border);color:var(--muted);font-size:12px}
@media print{.wrap{max-width:none;padding:0 12mm}h2{page-break-after:avoid}
  table,.trust,ol.steps li{page-break-inside:avoid}}
"""


def _e(text: Any) -> str:
    return html.escape(str(text))


def _now_iso() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d")


def build_acquisition_html(region: str = "Ludwigsburg/Stuttgart",
                           generated_at: str | None = None) -> str:
    """Erzeugt den Zielkunden-/Akquiseplan als HTML-String."""
    ts = generated_at or _now_iso()
    p: list[str] = []

    p.append("<!doctype html><html lang='de'><head><meta charset='utf-8'>")
    p.append("<title>Specter - Zielkunden & Akquiseplan</title>")
    p.append(f"<style>{_CSS}</style></head><body><div class='wrap'>")

    p.append("<header class='brand'>" + _MARK_IMG +
             "<div><div class='name'>Specter</div>"
             "<div class='sub'>Defensive Security Intelligence</div></div></header>")
    p.append(f"<div class='meta'>Interner Vertriebs-Leitfaden &middot; Region "
             f"{_e(region)} &middot; Stand: {_e(ts)}</div>")

    p.append("<h1 class='title'>Zielkunden &amp; Akquiseplan</h1>")
    p.append(f"<p>So gewinnst du systematisch die richtigen Kunden im Mittelstand "
             f"rund um {_e(region)} — mit dem kostenlosen Live-Check als Türöffner.</p>")

    # ICP
    p.append("<h2>Idealer Zielkunde</h2><ul>")
    for item in ICP:
        p.append(f"<li>{_e(item)}</li>")
    p.append("</ul>")

    # Branchen
    p.append("<h2>Zielbranchen</h2>")
    p.append("<table><tr><th>Branche</th><th>Warum besonders passend</th></tr>")
    for name, why in INDUSTRIES:
        p.append(f"<tr><td class='n'>{_e(name)}</td><td>{_e(why)}</td></tr>")
    p.append("</table>")

    # Kanäle
    p.append("<h2>Wo du sie findest</h2><ul>")
    for c in CHANNELS:
        p.append(f"<li>{_e(c)}</li>")
    p.append("</ul>")

    # Prozess
    p.append("<h2>Akquise in sechs Schritten</h2><ol class='steps'>")
    for title, detail in PROCESS:
        p.append(f"<li><b>{_e(title)}:</b> {_e(detail)}</li>")
    p.append("</ol>")

    # Nachfass
    p.append("<h2>Nachfass-Rhythmus</h2>")
    p.append("<table><tr><th>Zeitpunkt</th><th>Aktion</th></tr>")
    for when, action in CADENCE:
        p.append(f"<tr><td class='n'>{_e(when)}</td><td>{_e(action)}</td></tr>")
    p.append("</table>")

    # Einwände
    p.append("<h2>Einwände &amp; Antworten</h2>")
    p.append("<table><tr><th>Einwand</th><th>Deine Antwort</th></tr>")
    for obj, ans in OBJECTIONS:
        p.append(f"<tr><td>{_e(obj)}</td><td>{_e(ans)}</td></tr>")
    p.append("</table>")

    # Recht
    p.append("<h2>Rechtlicher Rahmen (wichtig)</h2>")
    p.append("<div class='trust'>Unaufgeforderte Werbung an Unternehmen ist in "
             "Deutschland nach <strong>UWG</strong> heikel — auch am Telefon. Setze "
             "auf <strong>warme Kontakte</strong>: Empfehlung, LinkedIn, Netzwerk-"
             "Treffen, persönliches Gespräch. Die Erstkontakt-Mail ist für den "
             "<strong>individuellen</strong> Anschluss daran gedacht, nicht für "
             "Massenversand. Im Zweifel vorab kurz rechtlich abklären.</div>")

    p.append("<footer>Interner Leitfaden von Specter. Werkzeuge dazu: "
             "live_email_check.py (Türöffner), build_outreach_email.py "
             "(Erstkontakt), build_offer.py (Angebot), build_trust_onepager.py "
             "(Vertrauen). Zur PDF-Ausgabe im Browser &bdquo;Drucken &rarr; Als PDF "
             "speichern&ldquo; wählen.</footer>")
    p.append("</div></body></html>")
    return "".join(p)


def write_acquisition(directory: str | Path = "reports",
                      region: str = "Ludwigsburg/Stuttgart") -> Path:
    """Schreibt den Akquiseplan als HTML-Datei und gibt den Pfad zurück."""
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    html_path = out / "specter-akquiseplan.html"
    html_path.write_text(
        build_acquisition_html(region, _now_iso()), encoding="utf-8")
    return html_path
