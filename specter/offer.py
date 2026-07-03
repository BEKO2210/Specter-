"""Angebots-/Preis-One-Pager für Kunden (HTML -> PDF).

Erzeugt ein markengerechtes, druckoptimiertes Angebotsblatt im Specter-Branding:
die drei Pakete mit Preisen und Leistungen, optionale Zusatzleistungen, der
Ablauf und die Vertrauens-/DSGVO-Zusagen. Im Browser über "Drucken -> Als PDF
speichern" zu einem sauberen Kunden-PDF.
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

# Pakete: (Name, Preis, Kurzbeschreibung, Leistungen, hervorgehoben?)
PACKAGES: list[tuple[str, str, str, list[str], bool]] = [
    ("Quick-Check", "kostenlos",
     "Unverbindlicher Erst-Check der öffentlich sichtbaren E-Mail-Sicherheit.",
     ["E-Mail-Sicherheit: SPF, DKIM, DMARC",
      "TLS-Kurzprüfung einer Domain",
      "Kurzeinschätzung per E-Mail",
      "Ohne Zugriff auf Ihre Systeme"], False),
    ("Basis-Audit", "ab 900 €",
     "Der solide Einstieg für kleine und mittlere Unternehmen.",
     ["E-Mail-, TLS-, Firewall- und Backup-Prüfung",
      "Verständlicher Bericht mit Prioritäten",
      "Konkrete Handlungsempfehlungen",
      "CVSS-Bewertung je Finding"], True),
    ("Voll-Audit", "ab 2.500 €",
     "Das vollständige Lagebild über alle Prüfbereiche.",
     ["Alle vierzehn Prüfbereiche (AD, M365, Cloud, Web, DNS, DB, Container, …)",
      "BSI-IT-Grundschutz-Bericht",
      "Angriffspfad- und Choke-Point-Analyse",
      "Ein Nachtest nach der Behebung inklusive"], False),
]

# Optionale Zusatzleistungen: (Name, Preis, Beschreibung)
ADDONS: list[tuple[str, str, str]] = [
    ("Versicherungs-Nachweis", "ab 500 €",
     "Aufbereitung als Nachweis für Ihre Cyber-Versicherung (MFA, Backups, "
     "Patch-Management)."),
    ("Weiterer Nachtest", "ab 300 €",
     "Erneute Prüfung nach der Umsetzung – belegt, was geschlossen wurde."),
    ("Kurz-Schulung für Ihr Team", "auf Anfrage",
     "Verständliche Einweisung zu E-Mail-Betrug, Passwörtern und Backups."),
]

STEPS: list[tuple[str, str]] = [
    ("Kostenloser Erst-Check", "Wir prüfen öffentlich sichtbare Punkte – unverbindlich."),
    ("Audit im vereinbarten Rahmen", "Sie stellen Export-Dateien bereit, wir werten sie offline aus."),
    ("Bericht & Nachweis", "Klarer Bericht mit Prioritäten – auch für Ihre Versicherung."),
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
h1.title{color:var(--navy);font-size:29px;margin:20px 0 4px;letter-spacing:-.5px}
h1.title + p{color:var(--muted);font-size:15px;margin:0 0 20px;max-width:52ch}
h2{color:var(--navy);font-size:19px;margin:30px 0 12px;border-left:4px solid var(--teal);padding-left:10px}
.pkgs{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}
.pkg{border:1px solid var(--border);border-radius:14px;padding:20px 18px;display:flex;flex-direction:column}
.pkg.feat{border-color:var(--teal);box-shadow:0 10px 30px rgba(20,184,166,.12);position:relative}
.pkg .tag{position:absolute;top:-11px;right:16px;background:var(--teal);color:#04211d;
  font-size:11px;font-weight:700;padding:3px 11px;border-radius:999px}
.pkg .pname{font-weight:700;font-size:17px;color:var(--navy)}
.pkg .price{font-size:26px;font-weight:800;color:var(--teal-d);margin:6px 0 2px}
.pkg .desc{color:var(--muted);font-size:13px;margin:0 0 12px}
.pkg ul{list-style:none;padding:0;margin:auto 0 0}
.pkg li{position:relative;padding:5px 0 5px 20px;font-size:13.5px;color:var(--charcoal)}
.pkg li::before{content:"\\2713";position:absolute;left:0;color:var(--teal-d);font-weight:800}
table{border-collapse:collapse;width:100%;font-size:13.5px;margin:6px 0}
th,td{border:1px solid var(--border);padding:9px 11px;text-align:left;vertical-align:top}
th{background:var(--light);color:var(--navy);font-weight:600}
td.n{white-space:nowrap;font-weight:700;color:var(--navy);width:26%}
td.p{white-space:nowrap;color:var(--teal-d);font-weight:700;width:16%}
ol.steps{margin:6px 0;padding-left:20px} ol.steps li{margin:5px 0}
.trust{background:var(--light);border-left:4px solid var(--teal);border-radius:0 8px 8px 0;
  padding:12px 16px;font-size:13.5px;color:var(--charcoal);margin-top:8px}
footer{margin-top:34px;padding-top:16px;border-top:1px solid var(--border);color:var(--muted);font-size:12px}
.note{color:var(--muted);font-size:12px;margin-top:8px}
@media print{.wrap{max-width:none;padding:0 12mm}h2{page-break-after:avoid}
  .pkg,table,.trust{page-break-inside:avoid}a{color:inherit;text-decoration:none}}
"""


def _e(text: Any) -> str:
    return html.escape(str(text))


def _now_iso() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d")


def build_offer_html(customer_name: str = "Ihr Unternehmen",
                     contact_email: str = "kontakt@example.de",
                     generated_at: str | None = None) -> str:
    """Erzeugt den Angebots-/Preis-One-Pager als HTML-String."""
    ts = generated_at or _now_iso()
    mail = _e(contact_email)
    p: list[str] = []

    p.append("<!doctype html><html lang='de'><head><meta charset='utf-8'>")
    p.append("<title>Specter - Angebot & Preise</title>")
    p.append(f"<style>{_CSS}</style></head><body><div class='wrap'>")

    p.append("<header class='brand'>" + _MARK_IMG +
             "<div><div class='name'>Specter</div>"
             "<div class='sub'>Defensive Security Intelligence</div></div></header>")
    p.append(f"<div class='meta'>Angebot für {_e(customer_name)} &middot; "
             f"Stand: {_e(ts)} &middot; Preise netto zzgl. USt.</div>")

    p.append("<h1 class='title'>Angebot &amp; Preise</h1>")
    p.append("<p>Verständliche IT-Sicherheitsprüfung für den Mittelstand – "
             "defensiv, offline und nachvollziehbar. Starten Sie unverbindlich mit "
             "dem kostenlosen Quick-Check.</p>")

    # Pakete
    p.append("<div class='pkgs'>")
    for name, price, desc, feats, feat in PACKAGES:
        cls = "pkg feat" if feat else "pkg"
        tag = "<div class='tag'>Beliebt</div>" if feat else ""
        items = "".join(f"<li>{_e(x)}</li>" for x in feats)
        p.append(f"<div class='{cls}'>{tag}<div class='pname'>{_e(name)}</div>"
                 f"<div class='price'>{price}</div><div class='desc'>{_e(desc)}</div>"
                 f"<ul>{items}</ul></div>")
    p.append("</div>")

    # Zusatzleistungen
    p.append("<h2>Optionale Zusatzleistungen</h2>")
    p.append("<table><tr><th>Leistung</th><th>Preis</th><th>Beschreibung</th></tr>")
    for name, price, desc in ADDONS:
        p.append(f"<tr><td class='n'>{_e(name)}</td><td class='p'>{price}</td>"
                 f"<td>{_e(desc)}</td></tr>")
    p.append("</table>")

    # Ablauf
    p.append("<h2>So läuft es ab</h2><ol class='steps'>")
    for title, detail in STEPS:
        p.append(f"<li><strong>{_e(title)}:</strong> {_e(detail)}</li>")
    p.append("</ol>")

    # Vertrauen
    p.append("<h2>Sicher für Ihre Systeme</h2>")
    p.append("<div class='trust'>Specter prüft rein <strong>defensiv</strong>: "
             "keine Angriffe, kein Eingriff in Ihre Systeme, nur bereitgestellte bzw. "
             "öffentliche Daten. Ausschließlich im schriftlich vereinbarten Rahmen "
             "(&sect;202 StGB), DSGVO-konform, mit lückenlosem Audit-Log.</div>")

    p.append(f"<footer>Interesse oder Fragen? Schreiben Sie an "
             f"<a href='mailto:{mail}'>{mail}</a>. Dieses Angebot ist freibleibend; "
             f"der konkrete Aufwand wird vor Beauftragung abgestimmt. Zur PDF-Ausgabe "
             f"im Browser &bdquo;Drucken &rarr; Als PDF speichern&ldquo; wählen.</footer>")
    p.append("</div></body></html>")
    return "".join(p)


def write_offer(directory: str | Path = "reports",
                customer_name: str = "Ihr Unternehmen",
                contact_email: str = "kontakt@example.de") -> Path:
    """Schreibt den Angebots-One-Pager als HTML-Datei und gibt den Pfad zurück."""
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    html_path = out / "specter-angebot.html"
    html_path.write_text(
        build_offer_html(customer_name, contact_email, _now_iso()), encoding="utf-8")
    return html_path
