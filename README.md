<p align="center">
  <img src="docs/brand/specter-logo.svg" alt="Specter" width="360">
</p>

<p align="center"><strong>Autonomer, defensiver Sicherheits-Agent für autorisiertes Pentesting und Code-Auditing.</strong></p>

---


Specter verbindet ein Sprachmodell (Anthropic Claude, Tool/Function Calling) mit
realen Analyse-Werkzeugen — Dateizugriff, statischer Code-Scan und
Netzwerk-Befehlen — innerhalb eines **strikt durchgesetzten
Autorisierungs-Rahmens**. Der Agent entscheidet in einer Schleife selbst, welches
Werkzeug er als Nächstes einsetzt, bis er Schwachstellen belegt hat oder fertig
ist.

> Inspiriert vom Konzept "Esprit": KI-gestütztes Red Teaming — hier bewusst als
> **defensives**, an einen Scope gebundenes Werkzeug umgesetzt, um Firmen
> abzusichern.

---

## ⚠️ Rechtlicher Hinweis (bitte zuerst lesen)

Aktive Sicherheitsprüfungen (Portscans, Schwachstellen-Tests, Exploits) gegen
Systeme, die dir **nicht** gehören, sind in Deutschland ohne Genehmigung
strafbar (§ 202a–c, § 303a–b StGB — "Hackerparagraf"). Setze Specter nur ein,
wenn du eine **schriftliche Beauftragung** des Systemeigentümers hast.

Specter erzwingt diesen Rahmen technisch:

- Jede aktive Aktion läuft gegen eine **Scope-Datei** (`scope.yaml`). Ziele, die
  dort nicht freigegeben sind, werden **verweigert** (fail-closed).
- Ohne dokumentierte Autorisierung (`engagement.*`) startet der Agent nicht.
- Ein abgelaufenes `valid_until`-Datum stoppt den Agenten.
- Jede Aktion wird revisionssicher in ein **Audit-Log** (`audit/*.jsonl`)
  geschrieben.

Das ersetzt keine Rechtsberatung — es hilft dir, sauber zu arbeiten.

---

## Der Esprit-/Trident-Workflow

Specter bildet den Ablauf einer professionellen Pentest-Plattform in fünf
Phasen ab — der Agent durchläuft sie autonom:

1. **Connect & Recon** — Assets entdecken und im **einheitlichen Asset-Graph**
   erfassen (`register_asset`): Hosts, Dienste, Endpunkte, Datenspeicher,
   Secrets, Code.
2. **Attack & Pentest** — statisch (`scan_code`, `read_file`) und aktiv
   (`run_command`) prüfen, alles scope-gebunden.
3. **Findings-Analyse** — jede Schwachstelle als **strukturiertes Finding**
   (`record_finding`) mit Schweregrad, Kategorie, Asset, Evidenz, CWE, Owner.
   Der Static-Scan erfasst Kandidaten automatisch.
4. **Attack-Path-Korrelation** — Findings werden zu **Angriffspfaden**
   ("toxischen Kombinationen") verkettet (`correlate_paths`), z. B.
   *offengelegtes Secret + exponierter Dienst → Kontoübernahme*.
5. **Fix & Bericht** — deutscher **Bericht** (Markdown + JSON) plus fertige
   **Draft-Pull-Request-Texte** je Finding (`generate_report`).

## Architektur

```
specter/
├── config.py          # lädt & validiert scope.yaml
├── safety.py          # Scope-Durchsetzung (Pfad / Host / Befehl)  ← Herzstück
├── audit.py           # JSONL-Audit-Log
├── llm.py             # Anthropic-Client-Wrapper
├── agent.py           # 5-Phasen-Entscheidungs-Schleife
├── state.py           # geteilter Zustand (Assets + Findings + Pfade)
├── assets.py          # einheitlicher Asset-Graph (Recon)
├── findings.py        # Finding-Modell, Schweregrade, Store
├── attack_paths.py    # regelbasierte Angriffspfad-Korrelation
├── remediation.py     # Gegenmaßnahmen + Draft-PR-Generierung
├── report.py          # produktionsreifer Bericht (Markdown + JSON)
├── bsi.py             # BSI-IT-Grundschutz-Mapping
├── analyzers/         # Offline-Analyse bereitgestellter Exporte
│   ├── active_directory.py   # AD-Risiken (Policy, Gruppen, Kerberos …)
│   └── exchange.py           # Exchange-Risiken (Version, ECP, TLS, Header)
├── scanners/          # sichere Wrapper aktiver Scanner
│   ├── base.py               # Allowlist, Forbidden-Flags, Timeout, Parser
│   ├── nmap.py               # nmap-Wrapper
│   └── nikto.py              # nikto-Wrapper
└── tools/
    ├── register_asset.py   ├── read_file.py       ├── code_scan.py
    ├── analyze_ad.py       ├── analyze_exchange.py
    ├── run_command.py      ├── run_scanner.py
    ├── record_finding.py   ├── correlate_paths.py └── generate_report.py
```

### Die zehn Werkzeuge

| Tool | Phase | Zweck |
|---|---|---|
| `register_asset` | Recon | Asset im Graph erfassen (+ Kanten) |
| `read_file` | Prüfen | Datei lesen (nur im Datei-Scope) |
| `scan_code` | Prüfen | Muster-Scan, erfasst Findings automatisch |
| `analyze_ad` | Prüfen | Active-Directory-Export offline analysieren |
| `analyze_exchange` | Prüfen | Exchange-Daten offline/passiv analysieren |
| `run_command` | Prüfen | Ein erlaubtes Programm gegen ein Scope-Ziel |
| `run_scanner` | Prüfen | Freigegebenen Scanner (nmap/nikto) sicher ausführen |
| `record_finding` | Findings | Schwachstelle strukturiert festhalten |
| `correlate_paths` | Korrelation | Findings → Angriffspfade |
| `generate_report` | Fix & Bericht | Report (MD/JSON) + Draft-PR-Texte |

---

## Windows-Umgebungen: AD- & Exchange-Analyse (offline, defensiv)

Für den Mittelstand besonders relevant. Beide Analyzer werten **ausschließlich
bereitgestellte lokale Exportdateien** aus — **keine** Live-Verbindung, keine
Credential-Nutzung, keine Ausnutzung.

- **`analyze_ad`** (`analyzers/active_directory.py`) — erkennt schwache Passwort-/
  Lockout-Policy, zu große privilegierte Gruppen, veraltete/deaktivierte Konten,
  Service-Accounts mit SPN (Kerberoasting-Exposition), AS-REP-Roasting, altes
  krbtgt-Passwort (Golden-Ticket-Risiko), AdminSDHolder-Reste. Akzeptiert die
  dokumentierte JSON-Struktur oder einen **BloodHound-`users`-Export**.
- **`analyze_exchange`** (`analyzers/exchange.py`) — veraltete Version
  (ProxyLogon/ProxyShell-Ära anhand der Build-Nummer), extern erreichbares **ECP**,
  OWA/Autodiscover, schwache TLS-Protokolle, fehlende Sicherheits-Header.

Beispiel-Exporte: `examples/data/ad_export.example.json`,
`examples/data/exchange.example.json`.

## Aktive Scanner (nmap/nikto) — sicher gekapselt

`run_scanner` führt nur freigegebene Scanner aus. Jeder Lauf ist mehrfach
abgesichert:

- **Freigabe-Pflicht:** deaktiviert, bis `scanners.<name>.enabled: true` in
  `scope.yaml` (fail-closed).
- **Ziel im Scope:** Host muss im Netzwerk-Scope liegen.
- **Strikte Argument-Allowlist:** gefährliche Flags (Evasion, Spoofing, DoS,
  Dateiausgabe) sind **immer** blockiert; aggressive Flags nur mit
  `allow_aggressive: true`; sonst nur explizit freigegebene Flags.
- **Kein `shell=True`**, hartes Timeout, begrenzte Ausgabe, saubere
  Fehlerbehandlung. Ergebnisse werden als Findings übernommen.

## Bericht & BSI-IT-Grundschutz

`generate_report` erzeugt einen **produktionsreifen** Bericht (Markdown + JSON) mit:
Executive Summary, Risiko-Einstufung, Angriffspfaden, **Quick Wins**,
langfristigen Maßnahmen, technischen Findings mit Evidenz,
**BSI-IT-Grundschutz-Mapping** (Finding-ID, Risiko, Bereich, Maßnahme, BSI-Bezug,
Priorität, Evidenz, Einschränkungen), Scanner-Ergebnissen, Scope-Hinweisen,
Limitierungen und nächsten Schritten.

---

## Installation

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...
```

Für aktive Netzwerk-Scans zusätzlich die Tools installieren, die du in der
Allowlist führst, z. B.:

```bash
sudo apt install nmap        # Debian/Ubuntu
```

## Nutzung

```bash
# 1. Scope-Datei aus der Vorlage erstellen und anpassen
cp scope.example.yaml scope.yaml
$EDITOR scope.yaml           # Autorisierung, Ziele, erlaubte Tools eintragen

# 2. Code-Audit (White-Box, keine aktiven Scans)
python main.py --scope scope.yaml \
  --objective "Prüfe den Code in ./targets auf Sicherheitslücken und fasse die Funde mit Schweregrad und Gegenmaßnahmen zusammen."

# 3. Aktiver Scan gegen ein FREIGEGEBENES Test-Ziel
python main.py --scope scope.yaml \
  --objective "Scanne 127.0.0.1 auf offene Ports und Dienste und bewerte die Ergebnisse."
```

Bei `runtime.require_approval: true` (Standard) fragt Specter vor **jedem**
aktiven Befehl im Terminal nach Bestätigung (Human-in-the-loop). Mit `--yes`
lässt sich das für **isolierte Testlabore** überspringen.

## Sofort ausprobieren (Demo, ohne API-Key)

Ein vollständiger End-to-End-Lauf gegen einen mitgelieferten lokalen
Test-Webserver und eine absichtlich verwundbare Beispiel-App — beweist, dass
die ganze Pipeline real funktioniert:

```bash
python examples/run_demo.py
```

Der Lauf durchläuft alle fünf Phasen (Recon → Scan → aktives `curl` → Findings →
Angriffspfade → Bericht) und schreibt einen echten Report nach `reports/`.
Ideal als Vorlage für ein echtes Engagement: `examples/demo_scope.yaml`
kopieren, Autorisierung und Ziele eintragen, mit `main.py` autonom laufen lassen.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest
```

**255 Tests, 100 % Code-Coverage** (per `pytest.ini` als Gate erzwungen,
`--cov-fail-under=100`). Abgedeckt sind u. a.:

- Scope-Durchsetzung (Pfad-Traversal, CIDR, Sperrliste, Allowlist, Metazeichen)
- Findings-Modell, Asset-Graph, Angriffspfad-Korrelation, Report-Generierung
- alle zehn Werkzeuge (Erfolgs- und Fehlerpfade)
- AD-/Exchange-Analyzer (jede Regel + Fehlerfälle, BloodHound-Normalisierung)
- Scanner-Wrapper: Argument-Allowlist, blockierte Gefahren-Flags, Timeout,
  Truncation, Parser (mit gemocktem Subprozess)
- BSI-IT-Grundschutz-Mapping und alle Report-Abschnitte
- die vollständige Agenten-Schleife mit simuliertem LLM (kein API-Key nötig)
- ein **Integrationstest** mit echtem `curl` gegen einen lokalen Server

### Mittelstand-Testszenario „Mustermann GmbH"

Eine realistische Fixture (`tests/fixtures/mittelstand/`) bildet die typische
Angriffsfläche eines deutschen Mittelständlers ab — Webshop (PHP), Kunden-API
(Python), ERP/DATEV-Anbindung (Java), Infrastruktur (RDP/DB offen, alte Images),
personenbezogene Daten (DSGVO) und veraltete Komponenten. Darauf laufen:

- **Szenario-Tests** (`test_mittelstand_scenario.py`) — volles Engagement mit den
  echten Mittelstands-Angriffspfaden: **Domänenübernahme über offenen RDP-Zugang**,
  **DSGVO-meldepflichtiger Datenabfluss (Art. 33/34)**, **Ausnutzung veralteter
  Komponenten**, Webshop-SQLi → Kundendaten.
- **Harte/adversariale Tests** (`test_hard_adversarial.py`) — Scope-Ausbruchsversuche:
  Symlink-Traversal, Dezimal-/Oktal-IP-Umgehung, Homoglyph-Hosts, IPv6-Klammern,
  Command-Chaining, URL-Userinfo-Bypass, Prefix-Verwechslung.
- **Stress-/Performance-Tests** (`test_stress_performance.py`) — 300-Dateien-Scan,
  Korrelation über hunderte Findings, ReDoS-Schutz.
- **Muster-Präzisionstests** (`test_scan_patterns.py`) — je Schwachstellenklasse
  ein positiver Fall plus Falsch-Positiv-Kontrolle.

CI (GitHub Actions, `.github/workflows/ci.yml`) führt die Suite auf Python 3.11
und 3.12 aus.

---

## Nächste Schritte (Ausbau)

- Weitere Scanner als Tools ergänzen (z. B. `nikto`, `whatweb`, `dig`) — einfach
  in `commands.allowed_binaries` freigeben.
- Eigene Code-Muster in `specter/tools/code_scan.py` hinzufügen.
- Echte GitHub-Integration: Draft-PRs automatisch aus Findings öffnen.
- Exploit-Verifikation nur gegen **eigene, lokale Test-Server** (z. B. DVWA,
  Juice Shop) in einer isolierten VM.

## Verantwortung

Dieses Werkzeug dient dazu, Systeme **mit Erlaubnis** sicherer zu machen. Nutze
es nicht gegen fremde Infrastruktur. Der Scope-Mechanismus ist eine Leitplanke,
kein Freibrief.