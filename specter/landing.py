"""Markengerechte Landingpage fuer Specter (eigenstaendiges HTML).

Erzeugt eine professionelle, responsive Ein-Seiten-Website im Specter-Branding,
die den Nutzen fuer den Mittelstand erklaert, Vertrauen schafft und zum
kostenlosen E-Mail-Sicherheits-Check (Tueroeffner) fuehrt. Voll eigenstaendig
(inline CSS + eingebettetes Mark), laesst sich also ohne Build-Schritt hosten
oder per Datei weitergeben.
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

# Die drei groessten Mittelstands-Risiken (Aufhaenger im Problem-Abschnitt).
PROBLEMS: list[tuple[str, str]] = [
    ("E-Mail-Betrug (CEO-Fraud)",
     "Ohne SPF/DKIM/DMARC koennen Kriminelle in Ihrem Namen mailen - der "
     "teuerste Betrug im Mittelstand."),
    ("Ransomware ueber offenes RDP",
     "Ein aus dem Internet erreichbarer Fernzugang ist das haeufigste "
     "Einfallstor fuer Verschluesselungstrojaner."),
    ("Backups, die im Ernstfall versagen",
     "Ohne getestete, unveraenderbare Backups wird aus einem Vorfall schnell "
     "der Totalverlust."),
]

# Die zehn Pruefbereiche (Loesungs-Grid).
COVERAGE: list[tuple[str, str]] = [
    ("E-Mail-Schutz", "SPF, DKIM, DMARC gegen Spoofing &amp; Phishing"),
    ("Active Directory", "Schwache Policies, Kerberoasting, Golden-Ticket-Risiken"),
    ("Microsoft 365 / Entra", "MFA, Legacy-Auth, zu viele Admins, offene Freigaben"),
    ("AWS &amp; Azure", "Offene Speicher, zu weite Rechte, offene Ports"),
    ("Firewall &amp; VPN", "Any-Any-Regeln, offenes RDP/SSH, VPN ohne MFA"),
    ("TLS &amp; Zertifikate", "Abgelaufen, schwache Verschluesselung, alte Protokolle"),
    ("Software-Bibliotheken", "Bekannte Luecken (Log4Shell-Klasse), veraltete Pakete"),
    ("Exchange", "Veraltete Versionen, exponierte Dienste"),
    ("Backup-Resilienz", "3-2-1-Regel, Immutable-Backups, getestete Restores"),
    ("Angriffspfade", "Wie kleine Luecken zusammen gefaehrlich werden"),
]

# Angebots-Pakete (Preis-Abschnitt).
PACKAGES: list[tuple[str, str, str]] = [
    ("Quick-Check", "kostenlos",
     "E-Mail-Sicherheit (SPF/DKIM/DMARC) + TLS fuer eine Domain. In Minuten, "
     "ganz ohne Zugriff auf Ihre Systeme."),
    ("Basis-Audit", "ab 900 &euro;",
     "E-Mail, TLS, Firewall und Backup-Check mit verstaendlichem Bericht und "
     "Prioritaeten."),
    ("Voll-Audit", "ab 2.500 &euro;",
     "Alle zehn Pruefbereiche, BSI-IT-Grundschutz-Bericht, Angriffspfade und "
     "ein Nachtest nach der Behebung."),
]

# Ablauf in drei Schritten.
STEPS: list[tuple[str, str]] = [
    ("Kostenloser Erst-Check",
     "Wir pruefen oeffentlich sichtbare Punkte Ihrer Domain - unverbindlich."),
    ("Audit im vereinbarten Rahmen",
     "Sie stellen Export-Dateien bereit, wir werten sie offline aus. Kein "
     "Eingriff in Ihre Systeme."),
    ("Bericht &amp; Nachweis",
     "Sie erhalten einen klaren Bericht mit Prioritaeten - auch als Nachweis "
     "fuer Ihre Cyber-Versicherung."),
]

_CSS = """
:root {
  --navy: #0D1B2A; --charcoal: #1F2937; --teal: #14B8A6; --teal-d: #0E9384;
  --light: #F3F4F6; --white: #FFFFFF; --border: #E5E7EB; --muted: #6B7280;
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  font-family: 'Inter', ui-sans-serif, system-ui, -apple-system, 'Segoe UI', sans-serif;
  color: var(--charcoal); margin: 0; line-height: 1.6; background: var(--white);
}
a { color: var(--teal-d); text-decoration: none; }
.wrap { max-width: 1040px; margin: 0 auto; padding: 0 24px; }
nav {
  position: sticky; top: 0; z-index: 20; background: rgba(255,255,255,0.92);
  backdrop-filter: blur(8px); border-bottom: 1px solid var(--border);
}
nav .wrap { display: flex; align-items: center; gap: 12px; padding: 12px 24px; }
nav .name { font-weight: 740; color: var(--navy); font-size: 19px; letter-spacing: -0.4px; }
nav .links { margin-left: auto; display: flex; gap: 20px; font-size: 14px; font-weight: 600; }
nav .links a { color: var(--charcoal); }
nav .cta { background: var(--teal); color: #062b27; padding: 8px 16px; border-radius: 8px; }
.hero { background: linear-gradient(160deg, #0D1B2A 0%, #12293d 60%, #14B8A6 220%); color: #fff; }
.hero .wrap { padding: 76px 24px 84px; }
.hero .eyebrow { color: #7FEEDA; font-weight: 700; font-size: 13px; letter-spacing: 1.5px; text-transform: uppercase; }
.hero h1 { font-size: 44px; line-height: 1.12; margin: 12px 0 14px; letter-spacing: -1px; font-weight: 760; max-width: 16em; }
.hero p.lead { font-size: 19px; color: #D5DEE7; max-width: 34em; margin: 0 0 28px; }
.btn { display: inline-block; font-weight: 700; border-radius: 10px; padding: 14px 26px; font-size: 16px; }
.btn.primary { background: var(--teal); color: #062b27; }
.btn.ghost { border: 1px solid rgba(255,255,255,0.4); color: #fff; margin-left: 10px; }
.trustbar { display: flex; flex-wrap: wrap; gap: 10px 22px; margin-top: 34px; color: #B9C6D2; font-size: 13.5px; font-weight: 600; }
.trustbar span::before { content: "\\2713 "; color: #7FEEDA; }
section { padding: 60px 0; }
section.alt { background: var(--light); }
h2.sec { font-size: 29px; color: var(--navy); letter-spacing: -0.6px; margin: 0 0 8px; }
p.sub { color: var(--muted); font-size: 16px; margin: 0 0 30px; max-width: 40em; }
.grid { display: grid; gap: 18px; }
.g3 { grid-template-columns: repeat(3, 1fr); }
.g2 { grid-template-columns: repeat(2, 1fr); }
.card { background: #fff; border: 1px solid var(--border); border-radius: 14px; padding: 22px 20px; }
.card h3 { margin: 0 0 6px; color: var(--navy); font-size: 17px; }
.card p { margin: 0; color: var(--charcoal); font-size: 14.5px; }
.cover { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px 26px; }
.cover .item { border-left: 3px solid var(--teal); padding: 4px 0 4px 14px; }
.cover .item strong { color: var(--navy); display: block; font-size: 15px; }
.cover .item span { color: var(--muted); font-size: 13.5px; }
.price { text-align: center; position: relative; }
.price .amt { font-size: 26px; font-weight: 780; color: var(--teal-d); margin: 6px 0 10px; }
.price .name { font-size: 18px; font-weight: 720; color: var(--navy); }
.steps { counter-reset: s; display: grid; grid-template-columns: repeat(3,1fr); gap: 20px; }
.steps .step { position: relative; padding-top: 8px; }
.steps .step::before { counter-increment: s; content: counter(s); display: inline-flex; align-items: center; justify-content: center; width: 34px; height: 34px; border-radius: 50%; background: var(--teal); color: #062b27; font-weight: 800; margin-bottom: 10px; }
.steps h3 { margin: 0 0 4px; color: var(--navy); font-size: 16px; }
.steps p { margin: 0; color: var(--muted); font-size: 14px; }
.cta-band { background: var(--navy); color: #fff; text-align: center; }
.cta-band .wrap { padding: 56px 24px; }
.cta-band h2 { color: #fff; font-size: 28px; margin: 0 0 10px; letter-spacing: -0.5px; }
.cta-band p { color: #C7D2DC; margin: 0 0 24px; }
footer { background: #0a1620; color: #8FA0AD; font-size: 13px; padding: 30px 0; }
footer .wrap { display: flex; flex-wrap: wrap; gap: 8px 24px; align-items: center; }
footer .name { color: #fff; font-weight: 700; }
footer .sp { margin-left: auto; }
@media (max-width: 820px) {
  .hero h1 { font-size: 33px; } .g3, .steps { grid-template-columns: 1fr; }
  .g2, .cover { grid-template-columns: 1fr; } nav .links a:not(.cta) { display: none; }
}
"""


def _e(text: Any) -> str:
    return html.escape(str(text))


def _now_iso() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d")


def build_landing_html(brand: str = "Specter",
                       contact_email: str = "kontakt@specter-security.de",
                       generated_at: str | None = None) -> str:
    """Erzeugt die vollstaendige Landingpage als HTML-String."""
    ts = generated_at or _now_iso()
    mail = _e(contact_email)
    subject = "Kostenloser%20E-Mail-Sicherheits-Check"
    p: list[str] = []

    p.append("<!doctype html><html lang='de'><head><meta charset='utf-8'>")
    p.append("<meta name='viewport' content='width=device-width, initial-scale=1'>")
    p.append(f"<title>{_e(brand)} - Defensive IT-Sicherheit fuer den Mittelstand</title>")
    p.append("<meta name='description' content='Specter prueft die IT-Sicherheit "
             "kleiner und mittlerer Unternehmen - defensiv, offline und "
             "nachvollziehbar. Kostenloser E-Mail-Sicherheits-Check.'>")
    p.append(f"<style>{_CSS}</style></head><body>")

    # Navigation
    p.append("<nav><div class='wrap'>" + _MARK_IMG +
             f"<span class='name'>{_e(brand)}</span>"
             "<div class='links'>"
             "<a href='#leistungen'>Leistungen</a>"
             "<a href='#preise'>Preise</a>"
             "<a href='#vertrauen'>Vertrauen</a>"
             f"<a class='cta' href='mailto:{mail}?subject={subject}'>Gratis-Check</a>"
             "</div></div></nav>")

    # Hero
    p.append("<header class='hero'><div class='wrap'>")
    p.append("<div class='eyebrow'>Defensive Security Intelligence</div>")
    p.append("<h1>IT-Sicherheit, die Ihr Unternehmen versteht &ndash; und schuetzt.</h1>")
    p.append("<p class='lead'>Specter deckt die Schwachstellen auf, ueber die im "
             "Mittelstand wirklich Schaeden entstehen &ndash; verstaendlich "
             "erklaert, ohne Fachchinesisch und ohne Ihre Systeme zu gefaehrden.</p>")
    p.append(f"<a class='btn primary' href='mailto:{mail}?subject={subject}'>"
             "Kostenlosen E-Mail-Check anfordern</a>"
             "<a class='btn ghost' href='#leistungen'>Was wird geprueft?</a>")
    p.append("<div class='trustbar'><span>Offline &amp; lesend</span>"
             "<span>Keine Angriffe</span><span>DSGVO-konform</span>"
             "<span>Nur im vereinbarten Rahmen</span></div>")
    p.append("</div></header>")

    # Problem
    p.append("<section id='problem'><div class='wrap'>")
    p.append("<h2 class='sec'>Die drei teuersten Luecken im Mittelstand</h2>")
    p.append("<p class='sub'>Die meisten Schaeden entstehen nicht durch exotische "
             "Angriffe, sondern durch drei bekannte Schwachstellen:</p>")
    p.append("<div class='grid g3'>")
    for title, detail in PROBLEMS:
        p.append(f"<div class='card'><h3>{_e(title)}</h3><p>{_e(detail)}</p></div>")
    p.append("</div></div></section>")

    # Leistungen / Coverage
    p.append("<section id='leistungen' class='alt'><div class='wrap'>")
    p.append("<h2 class='sec'>Was Specter prueft</h2>")
    p.append("<p class='sub'>Zehn Pruefbereiche decken die Systeme ab, die im "
             "Mittelstand wirklich zaehlen &ndash; von E-Mail bis Backup.</p>")
    p.append("<div class='cover'>")
    for title, detail in COVERAGE:
        p.append(f"<div class='item'><strong>{title}</strong><span>{detail}</span></div>")
    p.append("</div></div></section>")

    # Vertrauen
    p.append("<section id='vertrauen'><div class='wrap'>")
    p.append("<h2 class='sec'>Warum Firmen uns an ihre Systeme lassen</h2>")
    p.append("<p class='sub'>Eine Pruefung darf nie selbst zum Risiko werden. "
             "Deshalb ist Specter von Grund auf defensiv gebaut.</p>")
    p.append("<div class='grid g2'>"
             "<div class='card'><h3>Offline &amp; ohne Eingriff</h3><p>Wir werten nur "
             "bereitgestellte Export-Dateien aus. Keine Live-Verbindung, keine "
             "Angriffe, keine Veraenderung Ihrer Systeme.</p></div>"
             "<div class='card'><h3>Im festen Rahmen</h3><p>Geprueft wird nur, was "
             "schriftlich freigegeben ist (&sect;202 StGB). Alles andere wird "
             "technisch verweigert.</p></div>"
             "<div class='card'><h3>DSGVO-konform</h3><p>Datenminimierung, lokale "
             "Verarbeitung, Loeschkonzept und auf Wunsch ein "
             "Auftragsverarbeitungsvertrag.</p></div>"
             "<div class='card'><h3>Nachvollziehbar</h3><p>Lueckenloses Audit-Log, "
             "CVSS-Bewertung und BSI-IT-Grundschutz-Bezug &ndash; die Sprache, die "
             "Ihre IT und Ihre Versicherung verstehen.</p></div>"
             "</div></div></section>")

    # Preise
    p.append("<section id='preise' class='alt'><div class='wrap'>")
    p.append("<h2 class='sec'>Angebote fuer jeden Einstieg</h2>")
    p.append("<p class='sub'>Starten Sie unverbindlich mit dem Gratis-Check und "
             "steigen Sie bei Bedarf auf ein vollstaendiges Audit um.</p>")
    p.append("<div class='grid g3'>")
    for name, amount, detail in PACKAGES:
        p.append(f"<div class='card price'><div class='name'>{_e(name)}</div>"
                 f"<div class='amt'>{amount}</div><p>{_e(detail)}</p></div>")
    p.append("</div>")
    p.append("<p class='sub' style='margin-top:18px'>Fuer Versicherungsnehmer: Das "
             "Audit liefert den Nachweis ueber MFA, getestete Backups und "
             "Patch-Management, den viele Cyber-Policen verlangen.</p>")
    p.append("</div></section>")

    # Ablauf
    p.append("<section id='ablauf'><div class='wrap'>")
    p.append("<h2 class='sec'>So einfach laeuft es ab</h2>")
    p.append("<div class='steps' style='margin-top:22px'>")
    for title, detail in STEPS:
        p.append(f"<div class='step'><h3>{title}</h3><p>{_e(detail)}</p></div>")
    p.append("</div></div></section>")

    # CTA-Band
    p.append("<section class='cta-band'><div class='wrap'>")
    p.append("<h2>Sehen Sie in 5 Minuten, ob Ihre Domain angreifbar ist</h2>")
    p.append("<p>Kostenlos, unverbindlich und ohne Zugriff auf Ihre Systeme.</p>")
    p.append(f"<a class='btn primary' href='mailto:{mail}?subject={subject}'>"
             "Gratis-Check anfordern</a>")
    p.append("</div></section>")

    # Footer
    p.append("<footer><div class='wrap'>" + _MARK_IMG +
             f"<span class='name'>{_e(brand)}</span>"
             "<span>Defensive IT-Sicherheit fuer den Mittelstand</span>"
             f"<span class='sp'>Kontakt: <a href='mailto:{mail}'>{mail}</a> "
             f"&middot; Stand {_e(ts)}</span></div></footer>")

    p.append("</body></html>")
    return "".join(p)


def write_landing(directory: str | Path = "reports",
                  brand: str = "Specter",
                  contact_email: str = "kontakt@specter-security.de") -> Path:
    """Schreibt die Landingpage als HTML-Datei und gibt den Pfad zurueck."""
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    html_path = out / "specter-landingpage.html"
    html_path.write_text(
        build_landing_html(brand, contact_email, _now_iso()), encoding="utf-8")
    return html_path
