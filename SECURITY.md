# Sicherheit & Vertrauen (Security Policy)

Specter ist ein **defensiver**, scope-gebundener Sicherheits-Prüfer. Diese Datei
beschreibt die Sicherheits-Grundsätze der Software und den Umgang mit
gemeldeten Schwachstellen.

## Grundsätze (gelten immer)

- **Offline-first & lesend:** Es werden ausschließlich bereitgestellte
  Export-Dateien ausgewertet. Keine Live-Verbindung zu fremden Systemen, kein
  direktes Auslesen von Produktivdaten.
- **Keine Ausnutzung (kein Exploit):** Kein Ausnutzen von Schwachstellen, kein
  Knacken von Zugangsdaten, keine Rechteausweitung, kein Denial-of-Service,
  keine Persistenz, keine Umgehung von Schutzmechanismen.
- **Fail-closed Scope:** Nur was in der `scope.yaml` freigegeben ist, wird
  betrachtet. Aktionen außerhalb des Rahmens werden technisch verweigert.
- **Aktive Scanner standardmäßig aus:** Netzwerk-Scanner (nmap/nikto) sind
  deaktiviert und müssen pro Auftrag ausdrücklich freigeschaltet werden
  (Human-in-the-loop, Vier-Augen-Prinzip).
- **Keine Veränderung von Kundensystemen:** Specter prüft, dokumentiert und
  empfiehlt — es ändert, löscht oder installiert nichts in fremden Umgebungen.
- **Vollständiges Audit-Log:** Jede ausgeführte Aktion wird protokolliert.

## Rechtlicher Rahmen

Jede Prüfung erfolgt ausschließlich auf Basis einer **schriftlichen
Beauftragung** und innerhalb des vereinbarten Rahmens (§202a-c StGB,
„Hackerparagraf"). Ohne Freigabe kein Zugriff.

## Datenschutz (DSGVO)

Datenminimierung, lokale Verarbeitung, keine Weitergabe an unbeteiligte Dritte,
Löschkonzept nach Auftragsende und — auf Wunsch — ein
Auftragsverarbeitungsvertrag (AVV, Art. 28 DSGVO). Besondere Kategorien
(Art. 9 DSGVO) werden gesondert behandelt und nicht im Klartext berichtet.

## Melden einer Schwachstelle

Sicherheitsrelevante Funde bitte **nicht** über öffentliche Issues melden,
sondern vertraulich an die im Repository hinterlegte Kontaktadresse. Wir
bestätigen den Eingang und stimmen einen verantwortungsvollen
Offenlegungszeitplan (Responsible Disclosure) ab.

## Nachweis

Ein kundentauglicher Vertrauens-/Sicherheits-One-Pager lässt sich jederzeit
erzeugen:

```bash
python examples/build_trust_onepager.py   # reports/specter-vertrauen-onepager.html
```
