"""Angriffspfad-Korrelation ("toxische Kombinationen").

Kernidee: Einzelne Findings sind nur so gefährlich wie ihre Verkettung. Dieses
Modul verdichtet die Findings eines Auftrags regelbasiert zu Angriffspfaden -
erreichbarer Einstieg + ausnutzbare Schwachstelle + Weg zu sensiblen Daten.

Die Regeln arbeiten bewusst konservativ auf Kategorie-Ebene: treten die
Bausteine eines bekannten Musters gemeinsam im Auftrag auf (z. B. exponierter
Fernzugang *und* schwache Zugangsdaten), wird der Pfad ausgewiesen. Das ist eine
Heuristik für *plausible* Ketten, kein Nachweis einer technisch verifizierten
Route zwischen den beteiligten Systemen - der Bericht formuliert Pfade daher als
Kombinations-Risiko, das manuell zu bestätigen ist. Rein regelbasiert und
deterministisch (nachvollziehbar, keine Halluzination).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .assets import AssetGraph
from .findings import Finding, FindingsStore, Severity


@dataclass
class AttackPath:
    title: str
    severity: Severity
    steps: list[str]
    finding_ids: list[str] = field(default_factory=list)
    rationale: str = ""
    # Anzahl gleichartiger Einzelpfade, die hier zusammengefasst sind (>=1).
    instances: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity.label,
            "severity_rank": int(self.severity),
            "steps": self.steps,
            "finding_ids": self.finding_ids,
            "rationale": self.rationale,
            "instances": self.instances,
        }


# Eine Korrelationsregel prüft die Findings-Menge und liefert 0..n Pfade.
Rule = Callable[[list[Finding], AssetGraph], list[AttackPath]]


def _has(findings: list[Finding], category: str) -> list[Finding]:
    return [f for f in findings if f.category == category]


def _rule_secret_to_service(
    findings: list[Finding], graph: AssetGraph
) -> list[AttackPath]:
    """Offengelegtes Secret + exponierter Dienst -> Übernahme."""
    secrets = _has(findings, "secret_exposure")
    services = _has(findings, "exposed_service")
    if not secrets or not services:
        return []
    paths: list[AttackPath] = []
    for sec in secrets:
        for svc in services:
            paths.append(
                AttackPath(
                    title="Kontoübernahme über offengelegtes Secret",
                    severity=Severity.KRITISCH,
                    steps=[
                        f"Secret erlangen: {sec.location or sec.asset} ({sec.title})",
                        f"Am exponierten Dienst anmelden: {svc.location or svc.asset}",
                        "Authentifizierten Zugriff auf das System erlangen",
                    ],
                    finding_ids=[sec.id, svc.id],
                    rationale=(
                        "Ein im Klartext auffindbares Secret lässt sich direkt "
                        "gegen einen von außen erreichbaren Dienst verwenden."
                    ),
                )
            )
    return paths


def _rule_injection_to_data(
    findings: list[Finding], graph: AssetGraph
) -> list[AttackPath]:
    """Injection auf einem Endpunkt + erreichbare sensible Daten -> Datenabfluss."""
    injections = _has(findings, "injection")
    data = _has(findings, "sensitive_data") + _has(findings, "cloud_storage")
    paths: list[AttackPath] = []
    for inj in injections:
        target = data[0] if data else None
        steps = [
            f"Injection ausnutzen: {inj.location or inj.asset} ({inj.title})",
            "Datenbank-/Systembefehle über die Schwachstelle ausführen",
        ]
        if target:
            steps.append(f"Sensible Daten exfiltrieren: {target.asset}")
        paths.append(
            AttackPath(
                title="Datenabfluss über Injection",
                severity=Severity.KRITISCH if data else Severity.HOCH,
                steps=steps,
                finding_ids=[inj.id] + ([data[0].id] if data else []),
                rationale=(
                    "Injection-Schwachstellen erlauben direkten Zugriff auf "
                    "dahinterliegende Daten oder Betriebssystembefehle."
                ),
            )
        )
    return paths


def _rule_auth_to_access(
    findings: list[Finding], graph: AssetGraph
) -> list[AttackPath]:
    """Schwache Auth + fehlerhafte Zugriffskontrolle -> Rechteausweitung."""
    auth = _has(findings, "auth_weakness")
    access = _has(findings, "access_control")
    if not (auth and access):
        return []
    return [
        AttackPath(
            title="Rechteausweitung über schwache Auth und Zugriffskontrolle",
            severity=Severity.HOCH,
            steps=[
                f"Schwache Authentifizierung überwinden: {auth[0].title}",
                f"Fehlerhafte Zugriffskontrolle ausnutzen: {access[0].title}",
                "Auf Ressourcen fremder Nutzer/Rollen zugreifen",
            ],
            finding_ids=[auth[0].id, access[0].id],
            rationale=(
                "Schwache Anmeldung senkt die Einstiegshürde; fehlende "
                "Objekt-Zugriffskontrolle erlaubt danach horizontale/vertikale "
                "Rechteausweitung."
            ),
        )
    ]


def _rule_cloud_public_data(
    findings: list[Finding], graph: AssetGraph
) -> list[AttackPath]:
    """Öffentlicher Cloud-Speicher -> direkter Datenzugriff (Einzelbefund als Pfad)."""
    paths: list[AttackPath] = []
    for f in _has(findings, "cloud_storage"):
        paths.append(
            AttackPath(
                title="Direkter Datenzugriff über offenen Cloud-Speicher",
                severity=max(f.severity, Severity.HOCH),
                steps=[
                    f"Öffentlich erreichbaren Speicher identifizieren: {f.asset}",
                    "Ohne Authentifizierung auf abgelegte Daten zugreifen",
                ],
                finding_ids=[f.id],
                rationale="Fehlkonfigurierter Speicher gibt Daten ohne Zugangskontrolle preis.",
            )
        )
    return paths


def _rule_remote_access_domain(
    findings: list[Finding], graph: AssetGraph
) -> list[AttackPath]:
    """Exponierter Fernzugang (RDP/VPN) + Credential -> interner Zugriff / Domäne.

    Der klassische Ransomware-Einstieg im Mittelstand: ein offener RDP-/VPN-Zugang
    plus ein geleaktes oder Default-Credential führt zur Domänenübernahme.
    """
    remote = _has(findings, "remote_access")
    creds = (
        _has(findings, "secret_exposure")
        + _has(findings, "default_credentials")
        + _has(findings, "auth_weakness")
    )
    if not remote or not creds:
        return []
    paths: list[AttackPath] = []
    for rem in remote:
        cred = creds[0]
        paths.append(
            AttackPath(
                title="Domänenübernahme über exponierten Fernzugang",
                severity=Severity.KRITISCH,
                steps=[
                    f"Fernzugang identifizieren: {rem.location or rem.asset} ({rem.title})",
                    f"Zugangsdaten verwenden: {cred.title}",
                    "Im internen Netz Fuß fassen und Rechte ausweiten (Domain Admin)",
                    "Netzwerkweite Kompromittierung / Ransomware-Ausbringung möglich",
                ],
                finding_ids=[rem.id, cred.id],
                rationale=(
                    "Offene RDP-/VPN-Zugänge sind der häufigste Ransomware-"
                    "Einstieg im Mittelstand; zusammen mit schwachen oder "
                    "geleakten Zugangsdaten führt das direkt ins interne Netz."
                ),
            )
        )
    return paths


def _rule_dsgvo_breach(
    findings: list[Finding], graph: AssetGraph
) -> list[AttackPath]:
    """Personenbezogene Daten + Injection/Zugriffsfehler/Fehlkonfig -> DSGVO-Meldung."""
    pii = _has(findings, "personal_data") + _has(findings, "sensitive_data")
    vectors = (
        _has(findings, "injection")
        + _has(findings, "access_control")
        + _has(findings, "cloud_storage")
        + _has(findings, "misconfiguration")
    )
    if not pii or not vectors:
        return []
    vec = vectors[0]
    data = pii[0]
    return [
        AttackPath(
            title="DSGVO-meldepflichtiger Datenabfluss (Art. 33/34)",
            severity=Severity.KRITISCH,
            steps=[
                f"Schwachstelle ausnutzen: {vec.title} ({vec.location or vec.asset})",
                f"Zugriff auf personenbezogene Daten: {data.asset}",
                "Datenabfluss -> Meldepflicht binnen 72 h an die Aufsichtsbehörde",
            ],
            finding_ids=[vec.id, data.id],
            rationale=(
                "Ein Abfluss personenbezogener Daten löst nach Art. 33/34 DSGVO "
                "eine Melde- und ggf. Benachrichtigungspflicht aus (Bußgeldrisiko "
                "bis 4 % des Jahresumsatzes)."
            ),
        )
    ]


def _rule_outdated_exploit(
    findings: list[Finding], graph: AssetGraph
) -> list[AttackPath]:
    """Veraltete Komponente + erreichbar von außen -> Ausnutzung bekannter CVE."""
    outdated = _has(findings, "outdated_component")
    reachable = _has(findings, "exposed_service") + _has(findings, "remote_access")
    if not outdated:
        return []
    paths: list[AttackPath] = []
    for comp in outdated:
        target = reachable[0] if reachable else None
        steps = [
            f"Veraltete Komponente erkennen: {comp.title} ({comp.location or comp.asset})",
            "Öffentlich bekannte Schwachstelle (CVE/Exploit) recherchieren",
        ]
        ids = [comp.id]
        if target:
            steps.append(f"Gegen erreichbaren Dienst ausnutzen: {target.location or target.asset}")
            ids.append(target.id)
        else:
            steps.append("Bei Erreichbarkeit ausnutzen (Foothold)")
        paths.append(
            AttackPath(
                title="Ausnutzung bekannter Schwachstelle in veralteter Komponente",
                severity=Severity.KRITISCH if reachable else Severity.HOCH,
                steps=steps,
                finding_ids=ids,
                rationale=(
                    "Veraltete, von außen erreichbare Komponenten (z. B. altes "
                    "Exchange, Log4j, alte VPN-Gateways) haben oft öffentlich "
                    "verfügbare Exploits."
                ),
            )
        )
    return paths


DEFAULT_RULES: list[Rule] = [
    _rule_secret_to_service,
    _rule_injection_to_data,
    _rule_auth_to_access,
    _rule_cloud_public_data,
    _rule_remote_access_domain,
    _rule_dsgvo_breach,
    _rule_outdated_exploit,
]


def aggregate_paths(paths: list[AttackPath]) -> list[AttackPath]:
    """Verdichtet gleichartige Pfade (gleicher Titel) zu je einem Sammelpfad.

    Reduziert Rauschen im Bericht: statt N nahezu identischer Pfade (z. B. je
    ein offengelegtes Secret) entsteht ein Sammelpfad mit höchstem Schweregrad,
    vereinigten Findings und der Anzahl betroffener Kombinationen. Die Schritte
    des schwersten Vertreters bleiben als Beispiel erhalten.
    """
    groups: dict[str, list[AttackPath]] = {}
    order: list[str] = []
    for p in paths:
        if p.title not in groups:
            groups[p.title] = []
            order.append(p.title)
        groups[p.title].append(p)

    result: list[AttackPath] = []
    for title in order:
        members = groups[title]
        if len(members) == 1:
            result.append(members[0])
            continue
        strongest = max(members, key=lambda x: int(x.severity))
        finding_ids: list[str] = []
        for m in members:
            for fid in m.finding_ids:
                if fid not in finding_ids:
                    finding_ids.append(fid)
        rationale = strongest.rationale
        if rationale:
            rationale += (
                f" Zusammengefasst aus {len(members)} gleichartigen Kombinationen."
            )
        result.append(AttackPath(
            title=title,
            severity=strongest.severity,
            steps=strongest.steps,
            finding_ids=finding_ids,
            rationale=rationale,
            instances=len(members),
        ))
    return sorted(result, key=lambda x: -int(x.severity))


def correlate(
    findings_store: FindingsStore,
    graph: AssetGraph,
    rules: list[Rule] | None = None,
    min_severity: Severity = Severity.MITTEL,
    aggregate: bool = True,
) -> list[AttackPath]:
    """Wendet alle Regeln an und liefert die Angriffspfade, nach Schwere sortiert.

    Mit ``aggregate=True`` (Standard) werden gleichartige Pfade zu Sammelpfaden
    verdichtet - kompakter und kundentauglicher. ``aggregate=False`` liefert die
    einzelnen Pfade (z. B. für eine detaillierte technische Analyse).
    """
    active = rules if rules is not None else DEFAULT_RULES
    relevant = findings_store.by_severity(min_severity)
    paths: list[AttackPath] = []
    for rule in active:
        paths.extend(rule(relevant, graph))
    # Deduplizieren über (title, finding_ids) und nach Schwere sortieren.
    seen: set[tuple[str, tuple[str, ...]]] = set()
    unique: list[AttackPath] = []
    for p in sorted(paths, key=lambda x: -int(x.severity)):
        sig = (p.title, tuple(sorted(p.finding_ids)))
        if sig in seen:
            continue
        seen.add(sig)
        unique.append(p)
    if aggregate:
        return aggregate_paths(unique)
    return unique
