# Specter

**Autonomer Sicherheits-Agent für autorisiertes Pentesting und Code-Auditing.**

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
├── report.py          # Bericht (Markdown + JSON), DE / BSI / DSGVO
└── tools/
    ├── register_asset.py   # Recon: Asset erfassen
    ├── read_file.py        # White-Box: Datei lesen
    ├── code_scan.py        # statische Muster + Auto-Findings ("scan_code")
    ├── run_command.py      # Terminal-Befehle (Allowlist + Scope + Timeout)
    ├── record_finding.py   # Finding strukturiert erfassen
    ├── correlate_paths.py  # Angriffspfade korrelieren
    └── generate_report.py  # Bericht + Draft-PRs erzeugen
```

### Die sieben Werkzeuge

| Tool | Phase | Zweck |
|---|---|---|
| `register_asset` | Recon | Asset im Graph erfassen (+ Kanten) |
| `read_file` | Prüfen | Datei lesen (nur im Datei-Scope) |
| `scan_code` | Prüfen | Muster-Scan, erfasst Findings automatisch |
| `run_command` | Prüfen | Ein erlaubtes Programm gegen ein Scope-Ziel |
| `record_finding` | Findings | Schwachstelle strukturiert festhalten |
| `correlate_paths` | Korrelation | Findings → Angriffspfade |
| `generate_report` | Fix & Bericht | Report (MD/JSON) + Draft-PR-Texte |

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

**102 Tests, 100 % Code-Coverage** (per `pytest.ini` als Gate erzwungen,
`--cov-fail-under=100`). Abgedeckt sind u. a.:

- Scope-Durchsetzung (Pfad-Traversal, CIDR, Sperrliste, Allowlist, Metazeichen)
- Findings-Modell, Asset-Graph, Angriffspfad-Korrelation, Report-Generierung
- alle sieben Werkzeuge (Erfolgs- und Fehlerpfade)
- die vollständige Agenten-Schleife mit simuliertem LLM (kein API-Key nötig)
- ein **Integrationstest** mit echtem `curl` gegen einen lokalen Server

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