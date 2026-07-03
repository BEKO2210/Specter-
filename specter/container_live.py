"""Reiner Parser für echte `docker inspect`-Ausgabe -> Analyzer-Export.

Der eigentliche `docker inspect`-Aufruf lebt im Labor-Runner
(`examples/live_lab/run_container_lab.py`); hier steht nur die deterministische,
testbare Normalisierung: die (verschachtelte) echte `docker inspect`-JSON-Struktur
in die flache Form bringen, die der Offline-Analyzer `analyze_container` erwartet.

So bleibt die Kernlogik offline testbar (100 % Coverage) und identisch zur
Kundenanalyse - der Live-Check fuettert nur echte, selbst erhobene Daten ein.
"""

from __future__ import annotations

from typing import Any

_DOCKER_SOCK = "/var/run/docker.sock"


def _socket_mounted(host_config: dict[str, Any], mounts: Any) -> bool:
    """Prüft, ob das Docker-Socket in den Container gemountet ist."""
    for bind in host_config.get("Binds") or []:
        if str(bind).split(":", 1)[0] == _DOCKER_SOCK:
            return True
    if isinstance(mounts, list):
        for m in mounts:
            if isinstance(m, dict) and m.get("Source") == _DOCKER_SOCK:
                return True
    return False


def _published_ports(network_settings: dict[str, Any]) -> list[str]:
    """Baut lesbare Port-Bindungen 'hostip:hostport->containerport/proto'."""
    out: list[str] = []
    ports = network_settings.get("Ports")
    if not isinstance(ports, dict):
        return out
    for container_port, bindings in ports.items():
        if not bindings:
            continue
        for b in bindings:
            if isinstance(b, dict):
                host_ip = b.get("HostIp", "") or "0.0.0.0"
                out.append(f"{host_ip}:{b.get('HostPort', '')}->{container_port}")
    return out


def normalize_container(obj: dict[str, Any]) -> dict[str, Any]:
    """Normalisiert ein einzelnes `docker inspect`-Objekt in die flache Form."""
    host_config = obj.get("HostConfig") if isinstance(obj.get("HostConfig"), dict) else {}
    config = obj.get("Config") if isinstance(obj.get("Config"), dict) else {}
    net = obj.get("NetworkSettings") if isinstance(obj.get("NetworkSettings"), dict) else {}
    return {
        "name": str(obj.get("Name", "")).lstrip("/") or "Container",
        "image": str(config.get("Image", "")),
        "privileged": bool(host_config.get("Privileged", False)),
        "host_network": host_config.get("NetworkMode") == "host",
        "cap_add": list(host_config.get("CapAdd") or []),
        "user": str(config.get("User", "")),
        "docker_socket_mounted": _socket_mounted(host_config, obj.get("Mounts")),
        "ports": _published_ports(net),
    }


def normalize_inspect(inspect_json: Any) -> dict[str, Any]:
    """Wandelt eine echte `docker inspect`-Ausgabe (Liste) in den Analyzer-Export."""
    items = inspect_json if isinstance(inspect_json, list) else [inspect_json]
    containers = [normalize_container(o) for o in items if isinstance(o, dict)]
    return {"containers": containers}
