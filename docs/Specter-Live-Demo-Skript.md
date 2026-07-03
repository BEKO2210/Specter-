# Specter — Live-Demo-Skript (Investoren, ~2 Minuten)

**Ziel:** In zwei Minuten zeigen, dass Specter *echt läuft* — von der Analyse bis
zum fertigen PDF-Bericht — ohne Cloud, ohne API-Key, ohne Angriff auf fremde
Systeme. Alles läuft offline auf dem Laptop.

**Vorbereitung (vor dem Termin, einmalig):**

```bash
cd Specter-
python -m pytest -q          # bestätigt: 626 Tests, 100 % Coverage
```

Ein Terminal offen, Schriftgröße hochgestellt. Den Beispielbericht
(`docs/Specter-Beispielbericht.pdf`) und die Kennzahlen-Folie
(`docs/Specter-Investoren-Onepager.pdf`) vorab schon einmal geöffnet halten —
als Fallback, falls das Live-Rendering im Termin hakt.

---

## Ablauf

### 0:00 — Einordnung (15 Sek., während das Terminal sichtbar ist)

> „Specter prüft die IT eines Mittelständlers **offline** — es bekommt nur
> Export-Dateien, baut **keine** Verbindung zu fremden Systemen auf und nutzt
> **keine** Schwachstelle aus. Ich zeige jetzt einen echten End-to-End-Lauf auf
> meinem Laptop, kein Video, keine Folie."

### 0:15 — End-to-End-Lauf starten (Recon → Scan → Findings → Angriffspfade)

```bash
python examples/run_demo.py
```

Das läuft in Sekunden durch und ist **echt**: es startet einen lokalen
Test-Webserver, ruft die echten Werkzeuge in der Reihenfolge Recon → White-Box-Scan
→ aktiver `curl`-Check → Offline-Analysen (AD, Exchange, M365, AWS, Azure, DNS,
Web, TLS, Firewall, Backup, Datenbanken, Container, Abhängigkeiten) →
Angriffspfad-Korrelation → Bericht.

> **Reden, während es läuft:** „Jede Zeile hier ist ein echtes Werkzeug, das
> gerade arbeitet — kein Mock. Am Ende sehen Sie die Zusammenfassung: Assets,
> Findings nach Schweregrad und die korrelierten Angriffspfade."

**Auf die Schlusszeile zeigen:** `Ergebnis: N Assets · N Findings · N Angriffspfade`.

### 0:50 — Den kundenfertigen Bericht erzeugen

```bash
python examples/build_sample_report.py
```

> „Aus denselben Analysen entsteht der Bericht, den der Kunde bekommt — als HTML,
> direkt PDF-tauglich."

### 1:05 — Den Bericht zeigen (das ist der emotionale Höhepunkt)

`docs/Specter-Beispielbericht.pdf` öffnen. Durchscrollen:

1. **Management-Zusammenfassung** — Ampel, Kernaussage in einem Satz.
2. **Angriffspfade** — die 5 korrelierten Ketten („so wird aus kleinen Lücken
   ein Totalschaden"). Auf **„Domänenübernahme über exponierten Fernzugang"** zeigen.
3. **Ein Einzelbefund** — Titel, **CVSS-Score**, **BSI-Grundschutz-Bezug**,
   **konkrete Maßnahme**. „Jeder Punkt ist belegt und direkt abarbeitbar."

> „127 Einzelbefunde werden zu 5 Angriffspfaden und wenigen Choke-Points
> verdichtet — der Kunde ertrinkt nicht in einer Liste, er weiß, wo er zuerst
> ansetzt."

### 1:40 — Kennzahlen & Schluss

Die Kennzahlen-Folie `docs/Specter-Investoren-Onepager.pdf` zeigen (oder die
Website `beko2210.github.io/Specter-`).

> „14 Prüf-Bereiche in einem Lauf, 17 BSI-Bausteine abgedeckt, höchster
> gefundener CVSS-Wert 9,8. Ein klassischer Pentest kostet den Mittelstand fünf-
> stellig und passiert einmal im Jahr — Specter macht das bezahlbar und
> wiederholbar. **626 automatisierte Tests, 100 % Coverage** — das ist kein
> Prototyp, das ist Substanz."

---

## Fallback-Optionen (falls etwas hakt)

| Problem | Sofort-Lösung |
|---|---|
| `run_demo.py` hängt am Port | Erneut ausführen — der Port ist dann frei; oder direkt zu `build_sample_report.py` springen. |
| PDF-Rendering im Termin nicht möglich | Die **vorab erzeugten** PDFs in `docs/` zeigen — inhaltlich identisch. |
| Kein Netz / Proxy-Probleme | Irrelevant — die gesamte Demo ist **offline**. Genau das ist die Botschaft. |
| Frage „Läuft das wirklich?" | `python -m pytest -q` live starten — 626 grüne Tests in ~5 Sekunden. |

## Die drei Sätze, die hängenbleiben sollen

1. **Offline & defensiv** — kein Angriff, kein Datenabfluss, §202-StGB-konform.
2. **Aus Chaos wird Priorität** — 127 Funde → 5 Angriffspfade → wenige Choke-Points.
3. **Bezahlbar statt einmal im Jahr** — Mittelstands-Sicherheit als wiederholbares Produkt.
