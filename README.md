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

## Architektur

Drei Kernbereiche, wie bei jedem autonomen Agenten:

| Bereich | Rolle | Umsetzung in Specter |
|---|---|---|
| **Augen** (Scanner) | Daten sammeln | `read_file`, `scan_code` |
| **Gehirn** (KI) | Bewerten & entscheiden | `specter/agent.py` (Anthropic Tool Calling) |
| **Hände** (Aktor) | Aktiv prüfen | `run_command` (nmap etc., abgesichert) |

```
specter/
├── config.py          # lädt & validiert scope.yaml
├── safety.py          # Scope-Durchsetzung (Pfad / Host / Befehl)  ← Herzstück
├── audit.py           # JSONL-Audit-Log
├── llm.py             # Anthropic-Client-Wrapper
├── agent.py           # die Entscheidungs-Schleife
└── tools/
    ├── read_file.py   # White-Box: Datei lesen
    ├── code_scan.py   # statische Sicherheitsmuster (Tool "scan_code")
    └── run_command.py # Terminal-Befehle (Allowlist + Scope + Timeout)
```

### Die drei Werkzeuge

1. **`read_file`** — liest eine Datei, aber nur innerhalb von
   `filesystem.allowed_paths` (Schutz vor Directory-Traversal).
2. **`scan_code`** — durchsucht Code rekursiv nach typischen Mustern:
   fest kodierte Secrets, `eval`/`exec`, `shell=True`, mögliche SQL-Injection,
   schwache Hashes (MD5/SHA1), deaktivierte TLS-Prüfung u. a.
3. **`run_command`** — führt **ein** erlaubtes Programm aus (kein `shell=True`,
   keine Pipes/Verkettung, Ziel muss im Netzwerk-Scope liegen, hartes Timeout,
   optional manuelle Freigabe).

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

## Tests

```bash
python -m pytest -q
```

Die Tests decken den kritischsten Teil ab — die Scope-Durchsetzung
(Pfad-Traversal, CIDR-Zugehörigkeit, Sperrliste, Befehls-Allowlist,
Shell-Metazeichen).

---

## Nächste Schritte (Ausbau)

- Weitere Scanner als Tools ergänzen (z. B. `nikto`, `whatweb`, `dig`) — einfach
  in `commands.allowed_binaries` freigeben.
- Eigene Code-Muster in `specter/tools/code_scan.py` hinzufügen.
- Findings automatisch zu einem Markdown-Report (`reports/`) zusammenfassen.
- Exploit-Verifikation nur gegen **eigene, lokale Test-Server** (z. B. DVWA,
  Juice Shop) in einer isolierten VM.

## Verantwortung

Dieses Werkzeug dient dazu, Systeme **mit Erlaubnis** sicherer zu machen. Nutze
es nicht gegen fremde Infrastruktur. Der Scope-Mechanismus ist eine Leitplanke,
kein Freibrief.