"""Tests fuer den reinen docker-inspect-Normalisierer (offline, deterministisch)."""

from __future__ import annotations

from specter.analyzers.container import analyze_container
from specter.container_live import normalize_container, normalize_inspect

# Echte (verkuerzte) `docker inspect`-Ausgabe eines absichtlich unsicheren Containers.
_INSPECT = [{
    "Id": "9f3a1c7e2b4d",
    "Name": "/legacy-web",
    "Config": {"Image": "nginx:latest", "User": ""},
    "HostConfig": {
        "Privileged": True,
        "NetworkMode": "host",
        "CapAdd": ["SYS_ADMIN"],
        "Binds": ["/var/run/docker.sock:/var/run/docker.sock:ro"],
    },
    "Mounts": [{"Source": "/var/run/docker.sock",
                "Destination": "/var/run/docker.sock"}],
    "NetworkSettings": {"Ports": {
        "80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}],
        "9000/tcp": None,
    }},
}]


def test_normalize_inspect_flattens_real_docker_inspect():
    export = normalize_inspect(_INSPECT)
    c = export["containers"][0]
    assert c["name"] == "legacy-web"
    assert c["image"] == "nginx:latest"
    assert c["privileged"] is True
    assert c["host_network"] is True
    assert c["cap_add"] == ["SYS_ADMIN"]
    assert c["user"] == ""
    assert c["docker_socket_mounted"] is True
    assert c["ports"] == ["0.0.0.0:8080->80/tcp"]
    # Der echte Analyzer meldet die realen Fehlkonfigurationen.
    titles = " ".join(f.title for f in analyze_container(export))
    assert "Privilegiert" in titles and "Docker-Socket" in titles


def test_normalize_socket_via_binds_only():
    obj = {"Name": "x", "Config": {"Image": "a:1"},
           "HostConfig": {"Binds": ["/var/run/docker.sock:/sock"]}}
    assert normalize_container(obj)["docker_socket_mounted"] is True


def test_normalize_socket_via_mounts_only():
    # Kein passender Bind, aber das Socket taucht in Mounts auf.
    obj = {"Name": "y", "Config": {"Image": "a:1"},
           "HostConfig": {"Binds": ["/data:/data"]},
           "Mounts": [{"Source": "/etc", "Destination": "/etc"},
                      {"Source": "/var/run/docker.sock",
                       "Destination": "/var/run/docker.sock"}]}
    assert normalize_container(obj)["docker_socket_mounted"] is True


def test_normalize_no_socket_and_no_ports():
    obj = {"Name": "/app", "Config": {"Image": "app:1.0", "User": "1000"},
           "HostConfig": {"NetworkMode": "bridge", "Binds": ["/data:/data"]},
           "NetworkSettings": {"Ports": {"80/tcp": None}}}
    c = normalize_container(obj)
    assert c["docker_socket_mounted"] is False
    assert c["ports"] == [] and c["host_network"] is False
    assert analyze_container({"containers": [c]}) == []


def test_normalize_missing_sections_defaults():
    # Voellig leeres Objekt -> robuste Defaults, kein Absturz.
    c = normalize_container({})
    assert c["name"] == "Container" and c["image"] == ""
    assert c["privileged"] is False and c["ports"] == []


def test_normalize_inspect_accepts_single_object_and_skips_junk():
    export = normalize_inspect({"Name": "solo", "Config": {"Image": "a:1"}})
    assert export["containers"][0]["name"] == "solo"
    assert normalize_inspect(["nope", 5]) == {"containers": []}


def test_normalize_ports_default_hostip():
    obj = {"Name": "p", "Config": {"Image": "a:1"},
           "NetworkSettings": {"Ports": {"5432/tcp": [{"HostPort": "5432"}]}}}
    # Fehlendes HostIp -> 0.0.0.0 (alle Interfaces).
    assert normalize_container(obj)["ports"] == ["0.0.0.0:5432->5432/tcp"]
