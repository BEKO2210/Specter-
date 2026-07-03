"""Einheitlicher Asset-Graph (Recon).

Entspricht dem "Unified Asset Graph" von Esprit/Trident: waehrend der Aufklärung
(Recon) entdeckte Bausteine - Code-Repositories, Hosts, Dienste, Endpunkte,
Datenspeicher, Secrets - werden als Knoten erfasst und über Kanten verbunden
(z. B. "Host betreibt Dienst", "Dienst liest Datenspeicher"). Findings und
Angriffspfade referenzieren diese Assets.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Erlaubte Asset-Typen mit deutscher Anzeige.
ASSET_TYPES: dict[str, str] = {
    "code": "Code-Repository/Quelltext",
    "host": "Host/IP",
    "service": "Netzwerkdienst/Port",
    "endpoint": "Web-/API-Endpunkt",
    "datastore": "Datenspeicher (DB/Bucket)",
    "identity": "Identität/Konto",
    "secret": "Geheimnis (Credential/Token)",
}


@dataclass
class Asset:
    key: str                       # eindeutiger Schlüssel, z. B. "host:127.0.0.1"
    type: str
    name: str
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def type_label(self) -> str:
        return ASSET_TYPES.get(self.type, self.type)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "type": self.type,
            "type_label": self.type_label,
            "name": self.name,
            "metadata": self.metadata,
        }


@dataclass
class Edge:
    src: str                       # Asset-Key
    dst: str                       # Asset-Key
    relation: str                  # z. B. "betreibt", "liest", "authentifiziert_an"

    def to_dict(self) -> dict[str, str]:
        return {"src": self.src, "dst": self.dst, "relation": self.relation}


class AssetGraph:
    def __init__(self) -> None:
        self._assets: dict[str, Asset] = {}
        self._edges: list[Edge] = []

    @staticmethod
    def make_key(asset_type: str, name: str) -> str:
        return f"{asset_type}:{name}".lower()

    def add_asset(
        self, asset_type: str, name: str, **metadata: Any
    ) -> tuple[Asset, bool]:
        """Registriert ein Asset. Rückgabe: (Asset, is_new)."""
        if asset_type not in ASSET_TYPES:
            asset_type = "host"
        key = self.make_key(asset_type, name)
        if key in self._assets:
            # Metadaten zusammenführen.
            self._assets[key].metadata.update(metadata)
            return self._assets[key], False
        asset = Asset(key=key, type=asset_type, name=name, metadata=dict(metadata))
        self._assets[key] = asset
        return asset, True

    def add_edge(self, src_key: str, dst_key: str, relation: str) -> bool:
        if src_key not in self._assets or dst_key not in self._assets:
            return False
        for e in self._edges:
            if e.src == src_key and e.dst == dst_key and e.relation == relation:
                return False
        self._edges.append(Edge(src_key, dst_key, relation))
        return True

    def get(self, key: str) -> Asset | None:
        return self._assets.get(key)

    def assets(self) -> list[Asset]:
        return sorted(self._assets.values(), key=lambda a: (a.type, a.name))

    def edges(self) -> list[Edge]:
        return list(self._edges)

    def neighbors(self, key: str) -> list[tuple[str, str]]:
        """Nachbarn eines Assets als (nachbar_key, relation)."""
        out: list[tuple[str, str]] = []
        for e in self._edges:
            if e.src == key:
                out.append((e.dst, e.relation))
            elif e.dst == key:
                out.append((e.src, e.relation))
        return out

    def counts_by_type(self) -> dict[str, int]:
        result: dict[str, int] = {}
        for a in self._assets.values():
            result[a.type_label] = result.get(a.type_label, 0) + 1
        return result

    def __len__(self) -> int:
        return len(self._assets)
