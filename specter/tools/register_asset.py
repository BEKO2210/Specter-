"""Tool: Asset im Graph erfassen (Recon-Phase)."""

from __future__ import annotations

from typing import Any

from ..assets import ASSET_TYPES
from ..audit import AuditLog
from ..state import EngagementState
from .base import ToolResult


class RegisterAssetTool:
    name = "register_asset"
    active = False

    def __init__(self, state: EngagementState, audit: AuditLog) -> None:
        self.state = state
        self.audit = audit

    @property
    def spec(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": (
                "Erfasst ein entdecktes Asset im einheitlichen Asset-Graph "
                "(Recon). Optional kann eine Verbindung zu einem bereits "
                "erfassten Asset angegeben werden (relation + related_to als "
                "Asset-Key 'typ:name'). Nutze dies, um Hosts, Dienste, "
                "Endpunkte, Datenspeicher und Secrets zu strukturieren."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "type": {
                        "type": "string",
                        "enum": list(ASSET_TYPES.keys()),
                        "description": "Asset-Typ.",
                    },
                    "name": {"type": "string", "description": "Bezeichner (Host, Pfad, URL...)."},
                    "note": {"type": "string", "description": "Optionaler Hinweis (Metadaten)."},
                    "relation": {
                        "type": "string",
                        "description": "Optionale Kantenbeziehung, z. B. 'betreibt'.",
                    },
                    "related_to": {
                        "type": "string",
                        "description": "Asset-Key des Nachbarn ('typ:name').",
                    },
                },
                "required": ["type", "name"],
            },
        }

    def run(self, arguments: dict[str, Any]) -> ToolResult:
        asset_type = str(arguments.get("type", "")).strip()
        name = str(arguments.get("name", "")).strip()
        if not name:
            return ToolResult("Kein Asset-Name angegeben.", is_error=True)

        metadata = {}
        note = str(arguments.get("note", "")).strip()
        if note:
            metadata["note"] = note

        asset, is_new = self.state.assets.add_asset(asset_type, name, **metadata)

        edge_info = ""
        relation = str(arguments.get("relation", "")).strip()
        related_to = str(arguments.get("related_to", "")).strip().lower()
        if relation and related_to:
            ok = self.state.assets.add_edge(asset.key, related_to, relation)
            edge_info = (
                f" Kante '{relation}' -> {related_to} hinzugefügt."
                if ok
                else f" (Kante zu {related_to} nicht möglich - Nachbar unbekannt.)"
            )

        self.audit.record(
            "register_asset", key=asset.key, is_new=is_new, relation=relation or None
        )
        state = "neu erfasst" if is_new else "aktualisiert"
        return ToolResult(
            f"Asset {state}: {asset.key} ({asset.type_label}).{edge_info} "
            f"Assets gesamt: {len(self.state.assets)}."
        )
