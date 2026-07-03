"""Defensive Analyse der Container-/Docker-Konfiguration aus einem Export.

Wertet einen normalisierten `docker inspect`-Export aus und erkennt die klassischen
Container-Fehlkonfigurationen, über die ein Angreifer aus einem Container auf den
Host ausbricht oder die Isolation aushebelt: privilegierte Container, gemountetes
Docker-Socket, Host-Networking, gefährliche Capabilities, Lauf als root und
ungepinnte `:latest`-Images - rein offline, ohne Live-Zugriff, ohne Ausnutzung.
Der Labor-Kollektor (`examples/live_lab/run_container_lab.py`) kann einen echten,
selbst gestarteten Container per `docker inspect` abgreifen und über
`specter.container_live.normalize_inspect` in die hier erwartete Struktur bringen.

Erwartete Struktur (alle Felder optional):

    {
      "containers": [
        {
          "name": "web", "image": "nginx:latest",
          "privileged": true, "host_network": true,
          "cap_add": ["SYS_ADMIN"], "user": "root",
          "docker_socket_mounted": true,
          "ports": ["0.0.0.0:8080->80/tcp"]
        }
      ]
    }
"""

from __future__ import annotations

from typing import Any

from ..findings import Finding, Severity

# Capabilities, die praktisch einen Host-Ausbruch ermöglichen.
DANGEROUS_CAPS = {
    "ALL", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH",
    "NET_ADMIN", "NET_RAW", "SYS_BOOT", "BPF",
}
# Als root laufend, wenn User leer/root/0.
_ROOT_USERS = {"", "root", "0", "0:0"}


def _mk(title, severity, asset, evidence, *, category="container_security",
        cwe="", owner="Container-/DevOps-Team") -> Finding:
    return Finding(
        title=title, category=category, severity=severity, asset=asset,
        location=asset, evidence=evidence, cwe=cwe, owner=owner,
        source="container_analyzer", status="offen",
    )


def _analyze_container(c: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    name = str(c.get("name") or "Container")

    if c.get("privileged"):
        out.append(_mk(
            f"Privilegierter Container: {name}", Severity.KRITISCH, name,
            "--privileged hebt nahezu alle Isolation auf - faktisch Root-Zugriff "
            "auf den Host", cwe="CWE-250"))

    if c.get("docker_socket_mounted"):
        out.append(_mk(
            f"Docker-Socket im Container gemountet: {name}", Severity.KRITISCH, name,
            "/var/run/docker.sock im Container = vollständige Kontrolle über den "
            "Docker-Daemon und damit den Host", cwe="CWE-250"))

    caps = [str(x).upper().replace("CAP_", "") for x in (c.get("cap_add") or [])
            if str(x).strip()]
    dangerous = sorted({x for x in caps if x in DANGEROUS_CAPS})
    if dangerous:
        out.append(_mk(
            f"Gefährliche Capabilities: {name} ({', '.join(dangerous)})",
            Severity.HOCH, name,
            f"cap_add={dangerous} - ermöglicht Ausbruch/Host-Zugriff", cwe="CWE-250"))

    if c.get("host_network"):
        out.append(_mk(
            f"Host-Networking aktiv: {name}", Severity.MITTEL, name,
            "network=host hebt die Netzwerk-Isolation auf - der Container sieht "
            "alle Host-Interfaces", cwe="CWE-668"))

    user = str(c.get("user", "")).strip().lower()
    if user in _ROOT_USERS:
        out.append(_mk(
            f"Container läuft als root: {name}", Severity.MITTEL, name,
            f"user={c.get('user') or '(leer=root)'} - nach Ausbruch direkt Host-"
            "root; besser als unprivilegierter Benutzer laufen", cwe="CWE-250"))

    image = str(c.get("image", "")).strip()
    if image and (":" not in image.rsplit("/", 1)[-1] or image.endswith(":latest")):
        out.append(_mk(
            f"Ungepinntes Image (:latest): {name}", Severity.NIEDRIG, name,
            f"image={image} - kein fester Tag/Digest; Builds sind nicht "
            "reproduzierbar und können ungeprüft wechseln", cwe="CWE-1104"))

    for p in (c.get("ports") or []):
        if "0.0.0.0" in str(p) or "[::]:" in str(p):
            out.append(_mk(
                f"Container-Port auf allen Interfaces veröffentlicht: {name} ({p})",
                Severity.MITTEL, name, f"Port-Bindung {p} - auf benötigte Quell-IP/"
                "127.0.0.1 einschränken", category="exposed_service", cwe="CWE-668"))
    return out


def analyze_container(data: dict[str, Any]) -> list[Finding]:
    """Führt alle Container-Konfigurationsprüfungen aus und liefert die Findings."""
    if not isinstance(data, dict):
        return []
    containers = data.get("containers")
    if not isinstance(containers, list):
        return []
    findings: list[Finding] = []
    for c in containers:
        if isinstance(c, dict):
            findings += _analyze_container(c)
    return findings
