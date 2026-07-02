<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/brand/specter-logo-white-transparent.png">
    <img src="docs/brand/specter-logo-transparent.png" alt="Specter" width="380">
  </picture>
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
├── bsi.py             # BSI-IT-Grundschutz-Mapping
├── cvss.py            # CVSS-Lite-Score (numerisch) je Finding
├── analyzers/         # Offline-Analyse bereitgestellter Exporte
│   ├── active_directory.py   # AD-Risiken (Policy, Gruppen, Kerberos …)
│   ├── exchange.py           # Exchange-Risiken (Version, ECP, TLS, Header)
│   ├── entra_id.py           # Entra-ID/M365-Risiken (MFA, CA, Legacy-Auth …)
│   ├── aws.py                # AWS-Risiken (IAM, S3, Security-Groups, Root)
│   ├── azure.py              # Azure-Risiken (Storage, NSG, VM, Key-Vault, SQL, RBAC)
│   ├── email_security.py     # E-Mail-Spoofing/Phishing (SPF, DKIM, DMARC)
│   ├── dependency.py         # SCA: verwundbare/veraltete Abhängigkeiten (CVE)
│   └── firewall.py           # Firewall-/VPN-Config (Any-Any, RDP/SSH, MFA)
├── scanners/          # sichere Wrapper aktiver Scanner
│   ├── base.py               # Allowlist, Forbidden-Flags, Timeout, Parser
│   ├── nmap.py               # nmap-Wrapper
│   └── nikto.py              # nikto-Wrapper
├── choke_points.py    # engste Behebungsstellen (Greedy-Hitting-Set)
├── retest.py          # Re-Test/Delta gegen früheren Bericht
├── report.py          # produktionsreifer Bericht (Markdown + JSON)
├── report_export.py   # markengerechter HTML-Report (PDF via Browser-Druck)
├── integrations/      # opt-in ausgehende Aktionen
│   └── github_pr.py          # Draft-PRs (offline-Dateien + opt-in GitHub-API)
└── tools/
    ├── register_asset.py   ├── read_file.py        ├── code_scan.py
    ├── analyze_ad.py       ├── analyze_exchange.py  ├── analyze_entra.py
    ├── analyze_aws.py      ├── analyze_azure.py     ├── analyze_email_security.py
    ├── analyze_dependencies.py  ├── analyze_firewall.py  ├── run_command.py
    ├── run_scanner.py      ├── record_finding.py    ├── correlate_paths.py
    ├── retest.py           ├── generate_report.py   └── open_pull_requests.py
```

### Die achtzehn Werkzeuge

| Tool | Phase | Zweck |
|---|---|---|
| `register_asset` | Recon | Asset im Graph erfassen (+ Kanten) |
| `read_file` | Prüfen | Datei lesen (nur im Datei-Scope) |
| `scan_code` | Prüfen | Muster-Scan, erfasst Findings automatisch |
| `analyze_ad` | Prüfen | Active-Directory-Export offline analysieren |
| `analyze_exchange` | Prüfen | Exchange-Daten offline/passiv analysieren |
| `analyze_entra` | Prüfen | Entra-ID/M365-Export offline analysieren |
| `analyze_aws` | Prüfen | AWS-Export (IAM/S3/Security-Groups) offline analysieren |
| `analyze_azure` | Prüfen | Azure-Export (Storage/NSG/VM/Key-Vault/SQL/RBAC) offline analysieren |
| `analyze_email_security` | Prüfen | DNS-Export (SPF/DKIM/DMARC) gegen Spoofing/Phishing offline analysieren |
| `analyze_dependencies` | Prüfen | Abhängigkeits-/SBOM-Export gegen lokale Advisory-/CVE-Liste offline analysieren (SCA) |
| `analyze_firewall` | Prüfen | Firewall-/VPN-Konfig-Export offline analysieren (Any-Any, offenes RDP/SSH, VPN ohne MFA) |
| `run_command` | Prüfen | Ein erlaubtes Programm gegen ein Scope-Ziel |
| `run_scanner` | Prüfen | Freigegebenen Scanner (nmap/nikto) sicher ausführen |
| `record_finding` | Findings | Schwachstelle strukturiert festhalten |
| `correlate_paths` | Korrelation | Findings → Angriffspfade (aggregiert) |
| `retest` | Korrelation | Gegen früheren Bericht vergleichen (behoben/neu/offen) |
| `generate_report` | Fix & Bericht | Report (Markdown/JSON/HTML) + Draft-PR-Texte |
| `open_pull_requests` | Fix & Bericht | PR-Texte offline schreiben; opt-in echte GitHub-Draft-PRs |

---

## Windows, Cloud, E-Mail, Abhängigkeiten & Perimeter: AD-, Exchange-, Entra-ID/M365-, AWS-, Azure-, E-Mail-Security-, SCA- & Firewall-Analyse (offline, defensiv)

Für den Mittelstand besonders relevant. Alle acht Analyzer werten **ausschließlich
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
- **`analyze_entra`** (`analyzers/entra_id.py`) — fehlende MFA-Erzwingung/Conditional
  Access, aktive **Legacy-Authentifizierung**, zu viele Global Admins, privilegierte
  Konten **ohne MFA**, überprivilegierte App-Registrierungen (Admin-Consent),
  inaktive Gastkonten, anonyme SharePoint-/OneDrive-Freigaben (DSGVO).
- **`analyze_aws`** (`analyzers/aws.py`) — **Root ohne MFA / mit Access-Keys**,
  schwache IAM-Passwort-Policy, überprivilegierte IAM-User/Rollen (Admin,
  `trust='*'`), alte/ungenutzte Access-Keys, **öffentliche/unverschlüsselte
  S3-Buckets**, Security-Groups mit `0.0.0.0/0` auf sensiblen Ports.
- **`analyze_azure`** (`analyzers/azure.py`) — **öffentliche/unverschlüsselte
  Storage-Accounts**, schwache TLS-Mindestversion, NSGs mit `0.0.0.0/0` auf
  sensiblen Ports, VMs mit **Public IP** oder **veraltetem Betriebssystem**,
  öffentlich erreichbare **Key Vaults**, Azure-SQL ohne **TDE**, zu viele
  **Subscription-Owner**. Identitäts-/M365-Themen deckt `analyze_entra` ab.
- **`analyze_email_security`** (`analyzers/email_security.py`) — prüft aus einem
  DNS-Export die drei Anti-Spoofing-Mechanismen: **fehlendes/weiches SPF**
  (`+all`/`?all`), **fehlendes DKIM** oder zu **schwachen DKIM-Schlüssel**,
  **fehlendes DMARC** oder nur `p=none` sowie fehlende `rua`-Reportadresse.
  Schützt vor **CEO-Fraud/BEC** — im Mittelstand und bei Versicherern ein
  Haupteinfallstor.
- **`analyze_dependencies`** (`analyzers/dependency.py`) — **Software Composition
  Analysis**: gleicht einen Abhängigkeits-/SBOM-Export (requirements.txt,
  `pip freeze`, package.json, npm ls) gegen eine **lokal bereitgestellte
  Advisory-/CVE-Liste** ab und erkennt **bekannte verwundbare Paketversionen**
  (Log4Shell-Klasse, OWASP A06:2021), **nicht mehr gepflegte** (`deprecated`)
  Pakete sowie **ungepinnte** Versionen. Ein transparenter Versionsvergleich
  (`<`, `<=`, `>`, `>=`, `==`, `!=`, Bereiche) entscheidet den Treffer — ohne
  Abfrage von Paket-Registries oder CVE-Feeds.
- **`analyze_firewall`** (`analyzers/firewall.py`) — prüft aus einem Firewall-/VPN-
  Konfig-Export das **Perimeter-Regelwerk**: **Any-Any-Freigaben**, aus dem Internet
  offene **RDP-/SSH-Ports** (Fernzugang) und sensible Dienste (SMB/MSSQL/MySQL/…),
  **VPN ohne MFA**, schwache VPN-Kryptographie (3DES/DES/RC4) oder **IKEv1**,
  veraltete/abgekündigte **VPN-Gateways** sowie öffentlich erreichbare
  **Management-Interfaces**. Offenes RDP ist im Mittelstand der häufigste
  Ransomware-Einstieg.

Jedes Finding erhält zusätzlich einen numerischen **CVSS-Lite-Score** (0–10,
`cvss.py`) mit CVSS-v3.1-Qualitätsstufe — transparent im Bericht ausgewiesen.

Beispiel-Exporte: `examples/data/ad_export.example.json`,
`exchange.example.json`, `entra_export.example.json`, `aws_export.example.json`,
`azure_export.example.json`, `email_security.example.json`,
`dependencies.example.json`, `firewall.example.json`.

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

`generate_report` erzeugt einen **produktionsreifen** Bericht in drei Formaten
(**Markdown, JSON, HTML**) mit: Executive Summary, Risiko-Einstufung,
Angriffspfaden, **Quick Wins**, langfristigen Maßnahmen, technischen Findings mit
Evidenz, **BSI-IT-Grundschutz-Mapping** (Finding-ID, Risiko, Bereich, Maßnahme,
BSI-Bezug, Priorität, Evidenz, Einschränkungen), Scanner-Ergebnissen,
Scope-Hinweisen, Limitierungen und nächsten Schritten.

- **HTML für die Kundenübergabe:** Der HTML-Bericht (`report_export.py`) ist im
  Specter-Branding gestaltet und druckoptimiert (`@media print`) — im Browser
  öffnen und **„Drucken → Als PDF speichern"** ergibt ein sauberes PDF, ganz ohne
  zusätzliche Abhängigkeit.
- **Kompakte Angriffspfade:** Gleichartige Pfade werden zu Sammelpfaden
  verdichtet (mit Anzahl der Kombinationen) — kürzere, lesbarere Berichte.
- **Choke Points (engste Behebungsstellen):** Der Bericht nennt die Findings,
  deren Behebung die meisten Angriffspfade auf einmal bricht (Greedy-Hitting-Set,
  `choke_points.py`) — „behebe zuerst X, das schließt N Pfade".
- **Re-Test / Delta:** Bei einer Folgeprüfung vergleicht `retest` die aktuellen
  Findings mit einem früheren JSON-Bericht und weist **behoben / neu / weiterhin
  offen** samt Alter aus (`retest.py`) — komplett offline, Abgleich über die
  stabile Finding-ID.

```bash
# Folgeprüfung mit Vergleich gegen den letzten Bericht
python main.py --scope scope.yaml \
  --objective "Prüfe ./targets erneut und vergleiche mit reports/specter-report-ALT.json (retest)."
```

## GitHub-Draft-PRs (opt-in, kein Auto-Apply)

`open_pull_requests` erzeugt aus den Findings fertige Pull-Request-Texte.

- **Standard (offline, sicher):** schreibt je Finding eine Markdown-Datei nach
  `reports/pull-requests/` — **nichts verlässt das Haus**.
- **Opt-in (online):** ist `integrations.github` in `scope.yaml` aktiviert und
  liegt ein Token in der konfigurierten Umgebungsvariable, öffnet Specter je
  Finding einen echten **Draft-PR** (neuer Branch + Remediation-Trackingdokument).
  **Kein Auto-Merge, kein Auto-Apply** — ein Mensch prüft; vor dem Online-Schritt
  wird eine Freigabe eingeholt.

```yaml
integrations:
  github:
    enabled: true
    repo: "owner/repo"        # nur eigenes/autorisiertes Repository
    base_branch: "main"
    token_env: "GITHUB_TOKEN"
```

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

### KI-Modell wählen (z. B. Fable 5)

Welches Modell den Agenten steuert, legt **ein Schalter** in der Scope-Datei fest:

```yaml
runtime:
  model: "claude-fable-5"      # stärkste Analyse-/Korrelationstiefe
  # model: "claude-sonnet-5"   # schneller/günstiger
```

Voraussetzung ist die Umgebungsvariable `ANTHROPIC_API_KEY`. Wichtig zur
**Arbeitsteilung**: Die Analyzer und Scanner finden die Schwachstellen
**deterministisch** (reproduzierbar, ohne Halluzination); das Modell
**orchestriert** — es entscheidet, welches Werkzeug als Nächstes läuft,
**verifiziert** die Kandidaten (und verwirft False Positives des statischen
Scans), **korreliert** die Einzelbefunde zu Angriffspfaden und schreibt den
Bericht. Ein stärkeres Modell wie Fable 5 hebt vor allem die Qualität von
Verifikation, Korrelation und Berichtstext.

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

### Self-Audit: Specter prüft sich selbst

Specter lässt sich auf den **eigenen Quellcode** ansetzen — ein Reifenachweis
fürs Kundengespräch:

```bash
python examples/self_audit.py                    # statischer Selbst-Scan (ohne API-Key)

export ANTHROPIC_API_KEY=sk-ant-...              # zusätzlich der autonome
python examples/self_audit.py                    # KI-Lauf mit Fable 5
```

Der Datei-Scope (`examples/self_audit_scope.yaml`) zeigt ausschließlich auf
`specter/`; es werden keine fremden Systeme berührt. Der statische Scan liefert
bewusst nur **Kandidaten** (heuristische Treffer, darunter erwartbar die
Muster-Definitionen des Scanners selbst) — die KI-Schicht mit Fable 5
verifiziert sie und trennt echte Befunde vom Rauschen. Genau diese
Verifikationsstufe unterscheidet Specter von einem reinen Signatur-Scanner.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest
```

**433 Tests, 100 % Code-Coverage** (per `pytest.ini` als Gate erzwungen,
`--cov-fail-under=100`). Abgedeckt sind u. a.:

- Scope-Durchsetzung (Pfad-Traversal, CIDR, Sperrliste, Allowlist, Metazeichen)
- Findings-Modell, Asset-Graph, Angriffspfad-Korrelation + Aggregation
- **Choke-Point-Analyse** (Greedy-Hitting-Set) und **Re-Test/Delta** (behoben/neu/offen)
- alle achtzehn Werkzeuge (Erfolgs- und Fehlerpfade)
- AD-/Exchange-/Entra-ID-/AWS-/Azure-/E-Mail-Security-/SCA-/Firewall-Analyzer (jede Regel + Fehlerfälle, BloodHound, Versionsvergleich), CVSS-Lite
- Scanner-Wrapper: Argument-Allowlist, blockierte Gefahren-Flags, Timeout,
  Truncation, Parser (mit gemocktem Subprozess)
- BSI-IT-Grundschutz-Mapping sowie Markdown- und HTML-Report (alle Abschnitte,
  HTML-Escaping)
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