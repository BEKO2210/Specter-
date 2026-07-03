"""Markengerechtes Lern-/Bedien-Handbuch für Specter (HTML -> PDF).

Erzeugt ein eigenständiges, druckoptimiertes HTML-Handbuch im Specter-Branding,
das die Bedienerin/den Bediener Schritt für Schritt durch die Software führt -
in einfacher Sprache, ohne Vorwissen. Im Browser lässt es sich über
"Drucken -> Als PDF speichern" in ein schönes PDF überführen, ganz ohne
zusätzliche Abhängigkeit.

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

# Die vierzehn Offline-Analyzer in einfacher Sprache (Name, was er findet, warum wichtig).
ANALYZERS: list[tuple[str, str, str]] = [
    ("analyze_ad", "Active Directory: schwache Passwort-Regeln, zu viele Admins, "
     "veraltete Konten, Kerberoasting/Golden-Ticket-Risiken.",
     "Das Windows-Herz fast jeder Firma - hier hängt alles dran."),
    ("analyze_exchange", "Exchange/Outlook: veraltete Server-Version, extern "
     "erreichbares ECP, schwache TLS-Einstellungen.",
     "Mail-Server sind ein beliebtes Einfallstor (ProxyShell & Co.)."),
    ("analyze_entra", "Microsoft 365 / Entra ID: fehlende MFA, Legacy-Anmeldung, "
     "zu viele globale Admins, offene Freigaben.",
     "Cloud-Identitäten sind das neue Passwort zur ganzen Firma."),
    ("analyze_aws", "AWS: Root ohne MFA, offene S3-Buckets, zu weite Rechte, "
     "offene Security-Groups.",
     "Ein offener Bucket = Datenleck in Sekunden."),
    ("analyze_azure", "Azure: öffentliche Speicher, offene Ports, VMs mit alter "
     "Software, Key Vaults ohne Schutz.",
     "Cloud-Fehlkonfiguration ist die häufigste Cloud-Lücke."),
    ("analyze_email_security", "E-Mail-Schutz (SPF/DKIM/DMARC): kann jemand in "
     "eurem Namen Mails fälschen?",
     "Schützt vor CEO-Fraud - der teuerste Betrug im Mittelstand."),
    ("analyze_dns", "DNS-Sicherheit: fehlendes DNSSEC, fehlende CAA-Records, "
     "offener Zonentransfer (AXFR), Wildcard, dangling CNAME.",
     "DNS ist das Adressbuch der Firma - manipuliert es jemand, landet Verkehr "
     "beim Angreifer."),
    ("analyze_dependencies", "Software-Bibliotheken: bekannte Lücken (Log4Shell-"
     "Klasse), veraltete oder ungepinnte Pakete.",
     "Fremd-Code steckt überall - und altert schnell."),
    ("analyze_firewall", "Firewall/VPN: Any-Any-Regeln, offenes RDP/SSH aus dem "
     "Internet, VPN ohne MFA.",
     "Offenes RDP ist die Ransomware-Tür Nummer eins."),
    ("analyze_tls", "TLS/Zertifikate: abgelaufen, schwache Verschlüsselung, "
     "alte Protokolle.",
     "Für jeden von außen sichtbar - ein schneller Vertrauensverlust."),
    ("analyze_http_headers", "Web-Sicherheit: fehlende Schutz-Header (HSTS/CSP/"
     "X-Frame-Options), unsichere Cookies, verräterische Server-Banner.",
     "Websites sind das Schaufenster - hier fällt Nachlässigkeit sofort auf."),
    ("analyze_backup", "Backup/Ransomware-Resilienz: 3-2-1-Regel, offline/"
     "unveränderbare Kopien, getestete Wiederherstellung.",
     "Entscheidet, ob ihr eine Ransomware überlebt - Versicherer-Prüfpunkt Nr. 1."),
    ("analyze_database", "Datenbanken: öffentlich erreichbare Ports, fehlende "
     "Authentifizierung (Redis/Mongo), Default-Zugangsdaten, Transport ohne TLS.",
     "In Datenbanken liegen die Kronjuwelen - offen erreichbar sind sie ein "
     "Selbstbedienungsladen."),
    ("analyze_container", "Container/Docker: privilegierte Container, gemountetes "
     "docker.sock, Host-Networking, gefährliche Capabilities, root, :latest.",
     "Ein schlecht konfigurierter Container ist der direkte Weg vom Dienst zum Host."),
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
    """Erzeugt das vollständige HTML-Handbuch als String."""
    ts = generated_at or _now_iso()
    p: list[str] = []

    p.append("<!doctype html><html lang='de'><head><meta charset='utf-8'>")
    p.append("<title>Specter - Handbuch</title>")
    p.append(f"<style>{_CSS}</style></head><body><div class='wrap'>")

    p.append("<header class='brand'>" + _MARK_IMG +
             "<div><div class='name'>Specter</div>"
             "<div class='sub'>Defensive Security Intelligence</div></div></header>")
    p.append(f"<div class='meta'>Handbuch für {_e(company_name)} &middot; "
             f"Stand: {_e(ts)} &middot; internes Dokument</div>")

    p.append("<h1 class='title'>Dein Specter-Handbuch</h1>")
    p.append("<p>So bedienst du deine Sicherheits-Software - Schritt für Schritt, "
             "ohne Vorwissen.</p>")

    # Inhalt
    p.append("<h2>Inhalt</h2><div class='toc'><ol>"
             "<li>Was ist Specter?</li>"
             "<li>Die goldene Regel: defensiv &amp; im Rahmen</li>"
             "<li>Was Specter alles prüft</li>"
             "<li>Erste Einrichtung</li>"
             "<li>Welche Daten du beim Kunden brauchst</li>"
             "<li>Ein Auftrag Schritt für Schritt</li>"
             "<li>So führst du ein Kundengespräch</li>"
             "<li>Was du sagen darfst - und was nicht</li>"
             "<li>Häufige Fragen</li>"
             "<li>Spickzettel</li>"
             "</ol></div>")

    # 1
    p.append("<h2>1. Was ist Specter?</h2>")
    p.append("<p>Specter ist dein <strong>automatischer, defensiver "
             "Sicherheits-Prüfer</strong>. Er schaut sich die IT einer Firma an, "
             "findet Schwachstellen und schreibt einen verständlichen Bericht mit "
             "konkreten Empfehlungen - so wie es große Sicherheitsfirmen tun, nur "
             "günstiger und schneller.</p>")
    p.append("<div class='callout'>Merksatz: Specter ist wie ein <strong>TÜV für "
             "die IT</strong>. Er repariert nichts selbst und bricht nirgends ein - "
             "er prüft, dokumentiert und empfiehlt.</div>")
    p.append("<p>Das Besondere: Specter arbeitet <strong>offline</strong>. Er wertet "
             "Export-Dateien aus, die der Kunde bereitstellt. Er verbindet sich nicht "
             "heimlich mit fremden Systemen. Das macht ihn sicher - und rechtlich sauber.</p>")

    # 2
    p.append("<h2>2. Die goldene Regel: defensiv &amp; im Rahmen</h2>")
    p.append("<div class='warn'><strong>Wichtig fürs Vertrauen &amp; fürs Gesetz "
             "(&sect;202a-c StGB, DSGVO):</strong> Specter führt <strong>keine "
             "Angriffe</strong> aus. Keine Passwörter knacken, keine Daten stehlen, "
             "nichts zerstören, keine Systeme lahmlegen. Nur prüfen, nur im "
             "vereinbarten Rahmen (Scope), nur mit schriftlicher Freigabe.</div>")
    p.append("<ul>"
             "<li>Aktive Netzwerk-Scanner sind <strong>standardmäßig aus</strong> "
             "und müssen pro Auftrag freigeschaltet werden.</li>"
             "<li>Alles außerhalb des Rahmens wird von der Software "
             "<strong>automatisch verweigert</strong> (fail-closed).</li>"
             "<li>Jede Aktion wird protokolliert - du kannst jederzeit belegen, was "
             "gemacht wurde.</li></ul>")
    p.append("<div class='ok'>Genau das ist dein Verkaufsargument: <strong>Firmen "
             "lassen dich an ihre Systeme, weil Specter nachweislich nichts kaputt "
             "macht und nichts abfließt.</strong></div>")

    # 3
    p.append("<h2>3. Was Specter alles prüft</h2>")
    p.append("<p>Vierzehn Prüf-Module (&bdquo;Analyzer&ldquo;) decken die Bereiche ab, "
             "die im Mittelstand wirklich zu Schäden führen:</p>")
    p.append("<table><tr><th>Modul</th><th>Was es findet</th><th>Warum es zählt</th></tr>")
    for name, what, why in ANALYZERS:
        p.append(f"<tr><td><code>{_e(name)}</code></td><td>{_e(what)}</td>"
                 f"<td>{_e(why)}</td></tr>")
    p.append("</table>")
    p.append("<p>Zusätzlich: automatische <strong>Angriffspfad-Analyse</strong> "
             "(welche kleinen Lücken zusammen gefährlich werden), ein "
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
             "völlig gefahrlos.</div>")

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
             "<tr><td>E-Mail / DNS</td><td>DNS-Einträge (SPF/DKIM/DMARC, DNSSEC/CAA)</td></tr>"
             "<tr><td>Software</td><td>requirements.txt / package.json / SBOM</td></tr>"
             "<tr><td>Firewall / VPN</td><td>Regelwerk-Export</td></tr>"
             "<tr><td>TLS / Web</td><td>Zertifikats-/Protokoll-Übersicht, HTTP-Header</td></tr>"
             "<tr><td>Datenbanken</td><td>Port-/Auth-/TLS-Übersicht der DB-Dienste</td></tr>"
             "<tr><td>Container</td><td><code>docker inspect</code>-Ausgabe</td></tr>"
             "<tr><td>Backup</td><td>Kurzer Fragebogen zur Backup-Strategie</td></tr>"
             "</table>")
    p.append("<div class='ok'>Tipp: In <code>examples/data/</code> liegt für jeden "
             "Bereich eine Beispiel-Datei. Zeig sie dem Kunden - dann weiß die "
             "IT-Abteilung sofort, was du brauchst.</div>")

    # 6
    p.append("<h2>6. Ein Auftrag Schritt für Schritt</h2>")
    p.append("<ol>"
             "<li><span class='step'>Rahmen festlegen:</span> Trage die erlaubten "
             "Ziele und Pfade in eine <code>scope.yaml</code> ein "
             "(Vorlage: <code>scope.example.yaml</code>). Nur was hier steht, wird "
             "geprüft.</li>"
             "<li><span class='step'>Daten sammeln:</span> Lege die Export-Dateien "
             "des Kunden in einen Ordner im Rahmen.</li>"
             "<li><span class='step'>Prüfen:</span> Starte Specter mit dem Ziel des "
             "Auftrags. Ohne KI-Schlüssel laufen die Analyzer direkt; mit "
             "Schlüssel steuert das KI-Modell den Ablauf.</li>"
             "<li><span class='step'>Bericht erzeugen:</span> Specter schreibt einen "
             "Markdown- und einen schönen HTML-Bericht.</li>"
             "<li><span class='step'>PDF &amp; Übergabe:</span> HTML im Browser "
             "öffnen &rarr; &bdquo;Drucken &rarr; Als PDF speichern&ldquo; &rarr; "
             "fertiges Kunden-PDF.</li>"
             "<li><span class='step'>Nachtest:</span> Nach der Behebung erneut "
             "prüfen - der Bericht zeigt, was jetzt behoben ist.</li></ol>")
    p.append("<pre class='cmd'>python main.py --scope scope.yaml \\\n"
             "    --objective \"Prüfe die bereitgestellten Exporte in ./kundendaten\"</pre>")

    # 7
    p.append("<h2>7. So führst du ein Kundengespräch</h2>")
    p.append("<p>Ein einfacher Ablauf, den du auswendig können kannst:</p>")
    p.append("<ol>"
             "<li><strong>Sorge ansprechen:</strong> &bdquo;Die meisten Schäden im "
             "Mittelstand kommen über E-Mail-Betrug, offenes RDP und fehlende "
             "Backups. Genau das prüfe ich.&ldquo;</li>"
             "<li><strong>Sicherheit betonen:</strong> &bdquo;Ich greife nichts an "
             "und nehme nichts mit. Ich werte nur Export-Dateien aus, die Sie mir "
             "geben.&ldquo;</li>"
             "<li><strong>Nutzen zeigen:</strong> &bdquo;Sie bekommen einen "
             "verständlichen Bericht mit Prioritäten - und einen Nachweis für Ihre "
             "Cyber-Versicherung.&ldquo;</li>"
             "<li><strong>Kleiner Einstieg:</strong> Biete einen günstigen "
             "Erst-Check (z. B. E-Mail-Schutz + Backup) als Türöffner an.</li></ol>")
    p.append("<div class='callout'>Versicherungs-Argument: Viele Cyber-Policen "
             "verlangen MFA, getestete Backups und Patch-Management. Specter prüft "
             "genau diese Punkte - dein Bericht hilft dem Kunden, versicherbar zu "
             "bleiben.</div>")

    # 8
    p.append("<h2>8. Was du sagen darfst - und was nicht</h2>")
    p.append("<table><tr><th>So sagst du es (ehrlich)</th><th>So bitte nicht</th></tr>"
             "<tr><td>&bdquo;Ich prüfe defensiv und dokumentiere.&ldquo;</td>"
             "<td>&bdquo;Ich hacke Ihre Firma.&ldquo;</td></tr>"
             "<tr><td>&bdquo;Ich werte Ihre Export-Daten aus.&ldquo;</td>"
             "<td>&bdquo;Ich brauche Admin-Zugang zu allem.&ldquo;</td></tr>"
             "<tr><td>&bdquo;Der Bericht ist eine fachkundige Orientierung.&ldquo;</td>"
             "<td>&bdquo;Das ist ein zertifiziertes Testat.&ldquo;</td></tr>"
             "<tr><td>&bdquo;Ich halte mich strikt an den vereinbarten Rahmen.&ldquo;</td>"
             "<td>&bdquo;Ich schau mal überall rein.&ldquo;</td></tr>"
             "</table>")
    p.append("<div class='warn'>Immer schriftliche Freigabe einholen, bevor du "
             "irgendetwas prüfst. Ohne Auftrag kein Zugriff - das schützt dich und "
             "den Kunden.</div>")

    # 9
    p.append("<h2>9. Häufige Fragen</h2>")
    p.append("<h3>Brauche ich einen KI-Schlüssel?</h3>"
             "<p>Nein. Die Analyzer laufen auch ohne. Mit einem Schlüssel "
             "(z. B. Fable 5) steuert das KI-Modell den Ablauf und korreliert Funde "
             "zusätzlich.</p>")
    p.append("<h3>Kann Specter etwas kaputt machen?</h3>"
             "<p>Nein. Es führt keine Angriffe aus und ändert keine Kundensysteme. "
             "Aktive Scanner sind aus, bis du sie bewusst freischaltest.</p>")
    p.append("<h3>Was, wenn ich mich nicht sicher bin?</h3>"
             "<p>Im Zweifel weniger prüfen, nicht mehr. Halte dich an die "
             "<code>scope.yaml</code> und frage beim Kunden nach.</p>")
    p.append("<h3>Wie überzeuge ich technische Ansprechpartner?</h3>"
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
             "(defensive Sicherheitsprüfung). Zur PDF-Ausgabe im Browser öffnen und "
             "&bdquo;Drucken &rarr; Als PDF speichern&ldquo; wählen. Personenbezogene "
             "Daten sind gemäß DSGVO zu schützen.</footer>")
    p.append("</div></body></html>")
    return "".join(p)


def write_handbook(directory: str | Path = "reports",
                   company_name: str = "Ihr Unternehmen") -> Path:
    """Schreibt das Handbuch als HTML-Datei und gibt den Pfad zurück."""
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    html_path = out / "specter-handbuch.html"
    html_path.write_text(
        build_handbook_html(company_name, _now_iso()), encoding="utf-8")
    return html_path
