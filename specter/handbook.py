"""Markengerechtes Lern-/Bedien-Handbuch fuer Specter (HTML -> PDF).

Erzeugt ein eigenstaendiges, druckoptimiertes HTML-Handbuch im Specter-Branding,
das die Bedienerin/den Bediener Schritt fuer Schritt durch die Software fuehrt -
in einfacher Sprache, ohne Vorwissen. Im Browser laesst es sich ueber
"Drucken -> Als PDF speichern" in ein schoenes PDF ueberfuehren, ganz ohne
zusaetzliche Abhaengigkeit.

Bewusst getrennt vom Kundenbericht (`report_export.py`): dieses Dokument richtet
sich an das eigene Team, nicht an den Kunden.
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

# Die zehn Offline-Analyzer in einfacher Sprache (Name, was er findet, warum wichtig).
ANALYZERS: list[tuple[str, str, str]] = [
    ("analyze_ad", "Active Directory: schwache Passwort-Regeln, zu viele Admins, "
     "veraltete Konten, Kerberoasting/Golden-Ticket-Risiken.",
     "Das Windows-Herz fast jeder Firma - hier haengt alles dran."),
    ("analyze_exchange", "Exchange/Outlook: veraltete Server-Version, extern "
     "erreichbares ECP, schwache TLS-Einstellungen.",
     "Mail-Server sind ein beliebtes Einfallstor (ProxyShell & Co.)."),
    ("analyze_entra", "Microsoft 365 / Entra ID: fehlende MFA, Legacy-Anmeldung, "
     "zu viele globale Admins, offene Freigaben.",
     "Cloud-Identitaeten sind das neue Passwort zur ganzen Firma."),
    ("analyze_aws", "AWS: Root ohne MFA, offene S3-Buckets, zu weite Rechte, "
     "offene Security-Groups.",
     "Ein offener Bucket = Datenleck in Sekunden."),
    ("analyze_azure", "Azure: oeffentliche Speicher, offene Ports, VMs mit alter "
     "Software, Key Vaults ohne Schutz.",
     "Cloud-Fehlkonfiguration ist die haeufigste Cloud-Luecke."),
    ("analyze_email_security", "E-Mail-Schutz (SPF/DKIM/DMARC): kann jemand in "
     "eurem Namen Mails faelschen?",
     "Schuetzt vor CEO-Fraud - der teuerste Betrug im Mittelstand."),
    ("analyze_dependencies", "Software-Bibliotheken: bekannte Luecken (Log4Shell-"
     "Klasse), veraltete oder ungepinnte Pakete.",
     "Fremd-Code steckt ueberall - und altert schnell."),
    ("analyze_firewall", "Firewall/VPN: Any-Any-Regeln, offenes RDP/SSH aus dem "
     "Internet, VPN ohne MFA.",
     "Offenes RDP ist die Ransomware-Tuer Nummer eins."),
    ("analyze_tls", "TLS/Zertifikate: abgelaufen, schwache Verschluesselung, "
     "alte Protokolle.",
     "Fuer jeden von aussen sichtbar - ein schneller Vertrauensverlust."),
    ("analyze_backup", "Backup/Ransomware-Resilienz: 3-2-1-Regel, offline/"
     "unveraenderbare Kopien, getestete Wiederherstellung.",
     "Entscheidet, ob ihr eine Ransomware ueberlebt - Versicherer-Pruefpunkt Nr. 1."),
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
.meta { color: #6B7280; font-size: 13px; margin: 8px 0 28px; }
h1.title { color: var(--navy); font-size: 30px; margin: 22px 0 4px; letter-spacing: -0.5px; }
h1.title + p { font-size: 15px; color: #6B7280; margin: 0 0 18px; }
h2 { color: var(--navy); font-size: 21px; margin: 34px 0 12px; border-left: 4px solid var(--teal); padding-left: 10px; }
h3 { color: var(--navy); font-size: 15px; margin: 18px 0 6px; }
p { margin: 8px 0; }
table { border-collapse: collapse; width: 100%; font-size: 13px; margin: 10px 0; }
th, td { border: 1px solid var(--border); padding: 8px 10px; text-align: left; vertical-align: top; }
th { background: var(--light); color: var(--navy); font-weight: 600; }
code, .cmd { background: #0D1B2A; color: #E5E7EB; padding: 2px 6px; border-radius: 5px; font-family: ui-monospace, monospace; font-size: 12.5px; }
pre.cmd { display: block; padding: 12px 14px; white-space: pre-wrap; word-break: break-word; margin: 8px 0; }
.callout { border-left: 4px solid var(--teal); background: var(--light); padding: 10px 14px; border-radius: 0 6px 6px 0; margin: 12px 0; }
.warn { border-left: 4px solid #B45309; background: #FEF3C7; padding: 10px 14px; border-radius: 0 6px 6px 0; margin: 12px 0; }
.ok { border-left: 4px solid #14B8A6; background: #ECFDF5; padding: 10px 14px; border-radius: 0 6px 6px 0; margin: 12px 0; }
ul, ol { margin: 6px 0; padding-left: 22px; } li { margin: 4px 0; }
.step { font-weight: 700; color: var(--teal); }
.toc { columns: 2; font-size: 13px; }
footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid var(--border); color: #6B7280; font-size: 12px; }
@media print {
  .wrap { max-width: none; padding: 0 12mm; }
  h2 { page-break-after: avoid; }
  table, .callout, .warn, .ok, pre.cmd { page-break-inside: avoid; }
  a { color: inherit; text-decoration: none; }
}
"""


def _e(text: Any) -> str:
    return html.escape(str(text))


def _now_iso() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d")


def build_handbook_html(company_name: str = "Ihr Unternehmen",
                        generated_at: str | None = None) -> str:
    """Erzeugt das vollstaendige HTML-Handbuch als String."""
    ts = generated_at or _now_iso()
    p: list[str] = []

    p.append("<!doctype html><html lang='de'><head><meta charset='utf-8'>")
    p.append("<title>Specter - Handbuch</title>")
    p.append(f"<style>{_CSS}</style></head><body><div class='wrap'>")

    p.append("<header class='brand'>" + _MARK_IMG +
             "<div><div class='name'>Specter</div>"
             "<div class='sub'>Defensive Security Intelligence</div></div></header>")
    p.append(f"<div class='meta'>Handbuch fuer {_e(company_name)} &middot; "
             f"Stand: {_e(ts)} &middot; internes Dokument</div>")

    p.append("<h1 class='title'>Dein Specter-Handbuch</h1>")
    p.append("<p>So bedienst du deine Sicherheits-Software - Schritt fuer Schritt, "
             "ohne Vorwissen.</p>")

    # Inhalt
    p.append("<h2>Inhalt</h2><div class='toc'><ol>"
             "<li>Was ist Specter?</li>"
             "<li>Die goldene Regel: defensiv &amp; im Rahmen</li>"
             "<li>Was Specter alles prueft</li>"
             "<li>Erste Einrichtung</li>"
             "<li>Welche Daten du beim Kunden brauchst</li>"
             "<li>Ein Auftrag Schritt fuer Schritt</li>"
             "<li>So fuehrst du ein Kundengespraech</li>"
             "<li>Was du sagen darfst - und was nicht</li>"
             "<li>Haeufige Fragen</li>"
             "<li>Spickzettel</li>"
             "</ol></div>")

    # 1
    p.append("<h2>1. Was ist Specter?</h2>")
    p.append("<p>Specter ist dein <strong>automatischer, defensiver "
             "Sicherheits-Pruefer</strong>. Er schaut sich die IT einer Firma an, "
             "findet Schwachstellen und schreibt einen verstaendlichen Bericht mit "
             "konkreten Empfehlungen - so wie es grosse Sicherheitsfirmen tun, nur "
             "guenstiger und schneller.</p>")
    p.append("<div class='callout'>Merksatz: Specter ist wie ein <strong>TueV fuer "
             "die IT</strong>. Er repariert nichts selbst und bricht nirgends ein - "
             "er prueft, dokumentiert und empfiehlt.</div>")
    p.append("<p>Das Besondere: Specter arbeitet <strong>offline</strong>. Er wertet "
             "Export-Dateien aus, die der Kunde bereitstellt. Er verbindet sich nicht "
             "heimlich mit fremden Systemen. Das macht ihn sicher - und rechtlich sauber.</p>")

    # 2
    p.append("<h2>2. Die goldene Regel: defensiv &amp; im Rahmen</h2>")
    p.append("<div class='warn'><strong>Wichtig fuers Vertrauen &amp; fuers Gesetz "
             "(&sect;202a-c StGB, DSGVO):</strong> Specter fuehrt <strong>keine "
             "Angriffe</strong> aus. Keine Passwoerter knacken, keine Daten stehlen, "
             "nichts zerstoeren, keine Systeme lahmlegen. Nur pruefen, nur im "
             "vereinbarten Rahmen (Scope), nur mit schriftlicher Freigabe.</div>")
    p.append("<ul>"
             "<li>Aktive Netzwerk-Scanner sind <strong>standardmaessig aus</strong> "
             "und muessen pro Auftrag freigeschaltet werden.</li>"
             "<li>Alles ausserhalb des Rahmens wird von der Software "
             "<strong>automatisch verweigert</strong> (fail-closed).</li>"
             "<li>Jede Aktion wird protokolliert - du kannst jederzeit belegen, was "
             "gemacht wurde.</li></ul>")
    p.append("<div class='ok'>Genau das ist dein Verkaufsargument: <strong>Firmen "
             "lassen dich an ihre Systeme, weil Specter nachweislich nichts kaputt "
             "macht und nichts abfliesst.</strong></div>")

    # 3
    p.append("<h2>3. Was Specter alles prueft</h2>")
    p.append("<p>Zehn Pruef-Module (&bdquo;Analyzer&ldquo;) decken die Bereiche ab, "
             "die im Mittelstand wirklich zu Schaeden fuehren:</p>")
    p.append("<table><tr><th>Modul</th><th>Was es findet</th><th>Warum es zaehlt</th></tr>")
    for name, what, why in ANALYZERS:
        p.append(f"<tr><td><code>{_e(name)}</code></td><td>{_e(what)}</td>"
                 f"<td>{_e(why)}</td></tr>")
    p.append("</table>")
    p.append("<p>Zusaetzlich: automatische <strong>Angriffspfad-Analyse</strong> "
             "(welche kleinen Luecken zusammen gefaehrlich werden), ein "
             "<strong>CVSS-Score</strong> je Fund, <strong>BSI-IT-Grundschutz</strong>-"
             "Zuordnung und ein <strong>Nachtest</strong> (was wurde behoben?).</p>")

    # 4
    p.append("<h2>4. Erste Einrichtung</h2>")
    p.append("<p>Einmalig auf deinem Rechner (oder Server):</p>")
    p.append("<pre class='cmd'>git clone &lt;repo&gt;\n"
             "cd Specter-\n"
             "pip install -r requirements.txt</pre>")
    p.append("<p>Zum Ausprobieren ohne echte Kundendaten gibt es eine fertige Demo:</p>")
    p.append("<pre class='cmd'>python examples/run_demo.py</pre>")
    p.append("<div class='callout'>Die Demo startet einen kleinen Test-Server auf "
             "deinem eigenen Rechner (127.0.0.1) und zeigt den kompletten Ablauf - "
             "voellig gefahrlos.</div>")

    # 5
    p.append("<h2>5. Welche Daten du beim Kunden brauchst</h2>")
    p.append("<p>Du brauchst <strong>keinen</strong> Vollzugriff. Du bittest den "
             "Kunden um <strong>Export-Dateien</strong> (JSON) - lesend, harmlos, "
             "schnell erstellt:</p>")
    p.append("<table><tr><th>Bereich</th><th>Beispiel-Export</th></tr>"
             "<tr><td>Active Directory</td><td>Benutzer-/Richtlinien-Export bzw. "
             "BloodHound-Daten</td></tr>"
             "<tr><td>Microsoft 365 / Entra</td><td>MFA-/Conditional-Access-Report</td></tr>"
             "<tr><td>AWS / Azure</td><td>IAM-/Storage-/Netzwerk-Export</td></tr>"
             "<tr><td>E-Mail</td><td>DNS-Eintraege (SPF/DKIM/DMARC)</td></tr>"
             "<tr><td>Software</td><td>requirements.txt / package.json / SBOM</td></tr>"
             "<tr><td>Firewall / VPN</td><td>Regelwerk-Export</td></tr>"
             "<tr><td>TLS</td><td>Zertifikats-/Protokoll-Uebersicht</td></tr>"
             "<tr><td>Backup</td><td>Kurzer Fragebogen zur Backup-Strategie</td></tr>"
             "</table>")
    p.append("<div class='ok'>Tipp: In <code>examples/data/</code> liegt fuer jeden "
             "Bereich eine Beispiel-Datei. Zeig sie dem Kunden - dann weiss die "
             "IT-Abteilung sofort, was du brauchst.</div>")

    # 6
    p.append("<h2>6. Ein Auftrag Schritt fuer Schritt</h2>")
    p.append("<ol>"
             "<li><span class='step'>Rahmen festlegen:</span> Trage die erlaubten "
             "Ziele und Pfade in eine <code>scope.yaml</code> ein "
             "(Vorlage: <code>scope.example.yaml</code>). Nur was hier steht, wird "
             "geprueft.</li>"
             "<li><span class='step'>Daten sammeln:</span> Lege die Export-Dateien "
             "des Kunden in einen Ordner im Rahmen.</li>"
             "<li><span class='step'>Pruefen:</span> Starte Specter mit dem Ziel des "
             "Auftrags. Ohne KI-Schluessel laufen die Analyzer direkt; mit "
             "Schluessel steuert das KI-Modell den Ablauf.</li>"
             "<li><span class='step'>Bericht erzeugen:</span> Specter schreibt einen "
             "Markdown- und einen schoenen HTML-Bericht.</li>"
             "<li><span class='step'>PDF &amp; Uebergabe:</span> HTML im Browser "
             "oeffnen &rarr; &bdquo;Drucken &rarr; Als PDF speichern&ldquo; &rarr; "
             "fertiges Kunden-PDF.</li>"
             "<li><span class='step'>Nachtest:</span> Nach der Behebung erneut "
             "pruefen - der Bericht zeigt, was jetzt behoben ist.</li></ol>")
    p.append("<pre class='cmd'>python main.py --scope scope.yaml \\\n"
             "    --objective \"Pruefe die bereitgestellten Exporte in ./kundendaten\"</pre>")

    # 7
    p.append("<h2>7. So fuehrst du ein Kundengespraech</h2>")
    p.append("<p>Ein einfacher Ablauf, den du auswendig koennen kannst:</p>")
    p.append("<ol>"
             "<li><strong>Sorge ansprechen:</strong> &bdquo;Die meisten Schaeden im "
             "Mittelstand kommen ueber E-Mail-Betrug, offenes RDP und fehlende "
             "Backups. Genau das pruefe ich.&ldquo;</li>"
             "<li><strong>Sicherheit betonen:</strong> &bdquo;Ich greife nichts an "
             "und nehme nichts mit. Ich werte nur Export-Dateien aus, die Sie mir "
             "geben.&ldquo;</li>"
             "<li><strong>Nutzen zeigen:</strong> &bdquo;Sie bekommen einen "
             "verstaendlichen Bericht mit Prioritaeten - und einen Nachweis fuer Ihre "
             "Cyber-Versicherung.&ldquo;</li>"
             "<li><strong>Kleiner Einstieg:</strong> Biete einen guenstigen "
             "Erst-Check (z. B. E-Mail-Schutz + Backup) als Tueroeffner an.</li></ol>")
    p.append("<div class='callout'>Versicherungs-Argument: Viele Cyber-Policen "
             "verlangen MFA, getestete Backups und Patch-Management. Specter prueft "
             "genau diese Punkte - dein Bericht hilft dem Kunden, versicherbar zu "
             "bleiben.</div>")

    # 8
    p.append("<h2>8. Was du sagen darfst - und was nicht</h2>")
    p.append("<table><tr><th>So sagst du es (ehrlich)</th><th>So bitte nicht</th></tr>"
             "<tr><td>&bdquo;Ich pruefe defensiv und dokumentiere.&ldquo;</td>"
             "<td>&bdquo;Ich hacke Ihre Firma.&ldquo;</td></tr>"
             "<tr><td>&bdquo;Ich werte Ihre Export-Daten aus.&ldquo;</td>"
             "<td>&bdquo;Ich brauche Admin-Zugang zu allem.&ldquo;</td></tr>"
             "<tr><td>&bdquo;Der Bericht ist eine fachkundige Orientierung.&ldquo;</td>"
             "<td>&bdquo;Das ist ein zertifiziertes Testat.&ldquo;</td></tr>"
             "<tr><td>&bdquo;Ich halte mich strikt an den vereinbarten Rahmen.&ldquo;</td>"
             "<td>&bdquo;Ich schau mal ueberall rein.&ldquo;</td></tr>"
             "</table>")
    p.append("<div class='warn'>Immer schriftliche Freigabe einholen, bevor du "
             "irgendetwas pruefst. Ohne Auftrag kein Zugriff - das schuetzt dich und "
             "den Kunden.</div>")

    # 9
    p.append("<h2>9. Haeufige Fragen</h2>")
    p.append("<h3>Brauche ich einen KI-Schluessel?</h3>"
             "<p>Nein. Die Analyzer laufen auch ohne. Mit einem Schluessel "
             "(z. B. Fable 5) steuert das KI-Modell den Ablauf und korreliert Funde "
             "zusaetzlich.</p>")
    p.append("<h3>Kann Specter etwas kaputt machen?</h3>"
             "<p>Nein. Es fuehrt keine Angriffe aus und aendert keine Kundensysteme. "
             "Aktive Scanner sind aus, bis du sie bewusst freischaltest.</p>")
    p.append("<h3>Was, wenn ich mich nicht sicher bin?</h3>"
             "<p>Im Zweifel weniger pruefen, nicht mehr. Halte dich an die "
             "<code>scope.yaml</code> und frage beim Kunden nach.</p>")
    p.append("<h3>Wie ueberzeuge ich technische Ansprechpartner?</h3>"
             "<p>Zeig die BSI-IT-Grundschutz-Zuordnung und den CVSS-Score im "
             "Bericht - das ist die Sprache, die IT-Abteilungen kennen.</p>")

    # 10
    p.append("<h2>10. Spickzettel</h2>")
    p.append("<table><tr><th>Aufgabe</th><th>Befehl</th></tr>"
             "<tr><td>Demo ansehen</td><td><code>python examples/run_demo.py</code></td></tr>"
             "<tr><td>Selbst-Check von Specter</td><td><code>python examples/self_audit.py</code></td></tr>"
             "<tr><td>Echter Auftrag</td><td><code>python main.py --scope scope.yaml --objective \"...\"</code></td></tr>"
             "<tr><td>Tests laufen lassen</td><td><code>python -m pytest</code></td></tr>"
             "<tr><td>Dieses Handbuch bauen</td><td><code>python examples/build_handbook.py</code></td></tr>"
             "</table>")
    p.append("<div class='ok'>Du schaffst das. Fang mit der Demo an, dann mit einem "
             "kleinen Erst-Check bei einem Kunden, den du kennst. Jeder Auftrag macht "
             "dich sicherer.</div>")

    p.append("<footer>Internes Lern-/Bedien-Handbuch, erstellt mit Specter "
             "(defensive Sicherheitspruefung). Zur PDF-Ausgabe im Browser oeffnen und "
             "&bdquo;Drucken &rarr; Als PDF speichern&ldquo; waehlen. Personenbezogene "
             "Daten sind gemaess DSGVO zu schuetzen.</footer>")
    p.append("</div></body></html>")
    return "".join(p)


def write_handbook(directory: str | Path = "reports",
                   company_name: str = "Ihr Unternehmen") -> Path:
    """Schreibt das Handbuch als HTML-Datei und gibt den Pfad zurueck."""
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    html_path = out / "specter-handbuch.html"
    html_path.write_text(
        build_handbook_html(company_name, _now_iso()), encoding="utf-8")
    return html_path
