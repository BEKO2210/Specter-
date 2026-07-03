# Specter-Benchmark — Methodik

> **Kurzfassung:** Gegen einen offengelegten, reproduzierbaren
> **Regressionskorpus** aus **71 markierten Szenarien** über **alle 14 Analyzer**
> (plus zwei Roh-Format-Routen) erkennt Specter **197 von 197** gepflanzten
> Schwachstellen (**Recall 100 %**) und erzeugt dabei **null Fehlalarme**
> (**Präzision 100 %**), auch auf 27 gehärteten und Täuschungs-Szenarien. Jeder
> Schweregrad stimmt (100 %). Nachrechnen: `python examples/benchmark/run.py`.
>
> **Was diese Zahl ist — und was nicht:** Korpus und Erkennungsregeln stammen
> vom selben Autor; die 100 % sind eine **korpus-relative Regressions-Garantie**
> („keine bekannte Fehlerklasse geht je wieder verloren, kein bekannter
> Täuschungsfall wird je zum Fehlalarm"), **keine Real-World-Erkennungsrate**.
> Eine solche Rate kann seriös niemand angeben, dessen Grundgesamtheit unbekannt
> ist — deshalb veröffentlichen wir stattdessen die Messlatte selbst.

Dieses Dokument erklärt, **was** gemessen wird, **wie** und **wo die Grenzen
liegen**. Es ist bewusst nüchtern gehalten: keine Marketing-Quote, sondern eine
Zahl, die jeder auf dem eigenen Rechner in Millisekunden reproduziert.

---

## Warum diese Benchmark existiert

Sicherheitssoftware wird gern mit unüberprüfbaren „Erkennungsraten" beworben
(„99,9 % aller Angriffe"). Solche Zahlen sind wertlos, weil die Grundgesamtheit
niemand kennt. Specter geht den umgekehrten Weg: Wir veröffentlichen **die
Wahrheit, gegen die gemessen wird** — einen konkreten, lesbaren Korpus mit
bekanntem Soll-Ergebnis — und messen ausschließlich dagegen. Die Zahl ist damit
nicht beeindruckend *weil sie groß ist*, sondern *weil sie nachprüfbar ist*.

Dazu gehört auch die Kehrseite offen benannt: Wer die Regeln schreibt **und**
den Korpus, misst zwangsläufig gegen die eigene Erwartung. Der Wert des
Verfahrens liegt deshalb nicht im Erreichen der 100 % (die sind per Gate
erzwungen), sondern darin, dass (a) jede jemals gefundene Fehlerklasse als
Szenario **festgeschrieben** wird und nie wieder unbemerkt kaputtgehen kann,
und (b) jeder den Korpus lesen, kritisieren und um eigene Fälle erweitern kann.

Zwei Kennzahlen zählen gleichermaßen:

- **Erkennung (Recall):** Wird jede vorhandene Lücke gefunden? Ein Werkzeug, das
  nichts übersieht, aber ständig Fehlalarme wirft, ist im Alltag unbrauchbar.
- **Präzision (1 − Falsch-Positiv-Rate):** Wird *nur* gemeldet, was wirklich ein
  Problem ist? Genau hier scheitern viele Scanner — und genau hier prüft die
  Benchmark am härtesten.

---

## Der Korpus

| Kennzahl | Wert |
|---|---|
| Szenarien | **71** |
| Abgedeckte Analyzer | **14 / 14** (+ 2 Roh-Format-Routen) |
| Markierte Soll-Funde (Ground Truth) | **197** |
| Gehärtete/negative Szenarien (Soll: 0 Funde) | **27** |

Jedes Szenario ist ein realistischer, aber synthetischer Export (E-Mail-DNS,
`docker inspect`, AD-Struktur, Firewall-Regelwerk, …) mit **exakt bekanntem**
Soll-Ergebnis. Es gibt vier Arten:

| Art | Anzahl | Zweck |
|---|---|---|
| **Gepflanzte Lücke** (`vuln`) | 18 | Bekannte Schwachstellen, die gefunden werden **müssen**. |
| **Gehärtet** (`hardened`) | 16 | Sauberer Soll-Zustand — es darf **kein** Fund entstehen. |
| **Schwellenwert** (`boundary`) | 11 | Werte exakt auf der Entscheidungsgrenze. |
| **Täuschung** (`confuser`) | 26 | Sieht gefährlich aus, ist es nicht — oder umgekehrt (inkl. „schmutziger" Exporte mit String-Werten). |

### Roh-Formate: echte Vendor-Ausgaben statt vorgeformter Exporte

Ein berechtigter Einwand gegen synthetische Korpora lautet: *„Die Eingaben sind
auf das Schema des Werkzeugs zugeschnitten — die Antwort steckt schon in der
Frage."* Deshalb enthält der Korpus eine eigene Dimension mit **unveränderten
Roh-Formaten**, wie die Werkzeuge sie wirklich ausgeben:

- **`container_raw`** — die echte, verschachtelte `docker inspect`-JSON-Ausgabe
  (PascalCase, `HostConfig`/`Binds`/`NetworkSettings`), inklusive eines
  Täuschungsfalls (`/var/run/docker.sock.backup` ist *nicht* das Docker-Socket).
- **`aws_raw`** — ein Bündel echter AWS-CLI-Antworten (`get-account-summary`,
  `describe-security-groups`, `get-bucket-policy-status`, …). Weltoffene Ports
  werden aus `IpPermissions`/`CidrIp` abgeleitet, die Vertrauensweite aus dem
  echten `AssumeRolePolicyDocument`, das Schlüssel-Alter aus `CreateDate` gegen
  ein festes Referenzdatum — die Bewertung steckt hier **nicht** in der Eingabe.

Beide Routen laufen durch **dieselben Normalisierer wie die Kundenanalyse**
(`specter/container_live.py`, `specter/aws_raw.py`) — gemessen wird also der
Produktiv-Codepfad, nicht eine Benchmark-Sonderlocke.

### Was die Benchmark „schwer" macht

Ein oberflächlicher Test pflanzt nur offensichtliche Lücken und freut sich über
100 %. Dieser Korpus ist **adversarial** gebaut — er greift genau die Stellen an,
an denen reale Werkzeuge scheitern:

- **Grenzwerte exakt auf der Kante.** DKIM mit **1024** Bit (grenzwertig) neben
  **1023** (zu schwach) und **2048** (sauber). Passwort-Mindestlänge **12** (ok)
  gegen **11**. Zertifikat mit **30** Tagen Restlaufzeit (Warnung) gegen **31**
  (still). krbtgt mit **180** Tagen (ok) gegen **181**. Access-Key mit exakt
  **180** Tagen. Ein Off-by-One in einer Regel fällt hier sofort auf.

- **Numerischer statt alphabetischer Versionsvergleich.** `internal-lib 2.9.0`
  unter dem Constraint `< 2.10.0` **muss** als verwundbar gelten. Ein naiver
  String-Vergleich (`"2.9.0" > "2.10.0"`, weil `'9' > '1'`) würde die Lücke
  übersehen — ein klassischer, gefährlicher SCA-Bug.

- **Semantische Täuschungen.** Ein öffentlich erreichbarer Webserver auf Port
  **443/80** ist legitim und darf **nicht** als „offener Port" gemeldet werden;
  ein interner RDP-Zugang ebenso wenig. Ein **EC-Schlüssel mit 256 Bit** ist
  stark und darf nicht mit einem 1024-Bit-RSA verwechselt werden. Ein M365-Tenant
  ohne Security Defaults, aber mit passender **Conditional-Access-Richtlinie** ist
  abgesichert — eine **deaktivierte** Richtlinie dagegen schützt nicht und muss
  weiterhin als Lücke gelten.

- **Fehlende Felder ≠ unsicher.** Ein Datenbank-Datensatz, der nur `engine` und
  `port` angibt, darf keinen Fund erzeugen — Specter bewertet nur, was explizit
  als unsicher belegt ist.

- **Schmutzige Exporte.** Reale Exporte aus CSV, YAML oder PowerShell liefern
  `"false"` statt `false` und `"8"` statt `8`. Der Korpus erzwingt beides:
  `min_length: "8"` **muss** als schwache Policy erkannt werden (kein stiller
  Skip), und ein String `"false"` darf **niemals** als „wahr" fehlgedeutet
  werden (`zone_transfer: "false"` → kein Fehlalarm). Werkzeug-Schreibweisen
  wie **`TLSv1`** (so nennt OpenSSL TLS 1.0 — genau das liefert der eigene
  Live-Kollektor) müssen ebenso erkannt werden wie zu kurze **EC-Schlüssel**
  (192 Bit zu kurz, 224 exakt sauber).

---

## Wie gemessen wird

Für jedes Szenario ruft die Benchmark den echten Analyzer auf und gleicht seine
Funde mit der Ground Truth ab. Weil das Datenmodell **keine** stabilen
Fund-Codes kennt (die Finding-`id` ist ein Hash aus Kategorie/Asset/Ort/Titel),
wird — wie schon in den Labor-Harnessen — über **(Kategorie, Titel-Teilstring,
Schweregrad)** gematcht.

Die Erwartungsliste eines Szenarios ist **vollständig**: Jeder tatsächliche Fund,
der zu keiner Erwartung passt, zählt als **Fehlalarm (False Positive)**. Bei
gehärteten Szenarien ist die Erwartung leer — dort ist **jeder** Fund ein
Fehlalarm. Daraus ergeben sich:

```
Recall      = erkannte Soll-Funde / alle Soll-Funde          (Ziel: 100 %)
Präzision   = korrekte Funde / (korrekte Funde + Fehlalarme)  (Ziel: 100 %)
Spezifität  = gehärtete Szenarien ohne Fehlalarm / alle davon (Ziel: 100 %)
Schweregrad = korrekte Schweregrade / getroffene Erwartungen  (Ziel: 100 %)
```

---

## Ausführen

```bash
# Farbige Scorecard (Konsole)
python examples/benchmark/run.py

# Maschinenlesbar (für Skripte/CI)
python examples/benchmark/run.py --json

# Jede Zeile einzeln
python examples/benchmark/run.py --details
```

Der Läufer endet mit **Exit-Code 1**, sobald die Erkennung unter 100 % fällt, ein
Fehlalarm auftritt oder ein Schweregrad nicht stimmt — er ist damit zugleich ein
Gate.

## Als Regressionswächter in der CI

Die Benchmark läuft bei **jedem Commit** über `tests/test_benchmark.py` in der
regulären Testsuite mit (auf Python 3.11 und 3.12). Sie schlägt fehl, sobald

- eine gepflanzte Lücke nicht mehr erkannt wird,
- ein gehärtetes/Schwellen-/Täuschungs-Szenario plötzlich einen Fehlalarm wirft,
- oder sich ein Schweregrad verschiebt.

So kann niemand versehentlich eine Erkennungsregel lockern und dabei die
Falsch-Positiv-Rate hochziehen, ohne dass die CI es meldet.

---

## Grenzen (ehrlich benannt)

- **Korpus und Regeln haben denselben Autor.** Die Benchmark ist damit ein
  Regressions-Gate, kein unabhängiger Test: Sie beweist, dass keine dokumentierte
  Fehlerklasse jemals still kaputtgeht — nicht, dass Specter in fremden,
  ungesehenen Umgebungen dieselbe Quote erreicht. Die 100 % sind per Gate
  erzwungen (`MIN_RECALL = 1.0`) und daher **konstruktionsbedingt**, solange die
  CI grün ist.
- Der Korpus misst die **Analyzer-Logik** gegen bekannte Fehlerklassen, nicht die
  Vollständigkeit gegenüber *allen* denkbaren Angriffen. Er beweist Korrektheit
  und Präzision auf einem definierten, offengelegten Umfang — nicht „Sicherheit"
  im absoluten Sinn.
- Die Szenarien sind synthetisch (dafür deterministisch und reproduzierbar). Die
  **Roh-Format-Dimension** (`container_raw`, `aws_raw`) verringert die Distanz
  zur Realität, ersetzt sie aber nicht; die **Labor-Harnesse**
  (`examples/live_lab/`) ergänzen das um Läufe gegen *echte*, selbst gestartete
  Server, Datenbanken und Container.
- Erweiterungen sind erwünscht: Neue Fehlerklassen werden als weitere Szenarien
  in `examples/benchmark/corpus.py` aufgenommen — jede Regel bekommt so ihren
  festen Platz in der Wahrheit, gegen die gemessen wird. Extern beigesteuerte
  Szenarien (die der Autor **nicht** kennt, bevor sie laufen) sind der beste
  Weg, die Selbstreferenz dieses Korpus aufzubrechen.
