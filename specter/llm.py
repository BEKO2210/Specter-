"""Duenner Wrapper um den Anthropic-Client (Tool/Function Calling)."""

from __future__ import annotations

import os
from typing import Any

class LLMError(Exception):
    pass


class AnthropicLLM:
    def __init__(self, model: str, max_tokens: int = 4096) -> None:
        try:
            import anthropic
        except ImportError as exc:
            raise LLMError(
                "Das Paket 'anthropic' fehlt. Installiere die Abhaengigkeiten mit "
                "`pip install -r requirements.txt`."
            ) from exc
        self._anthropic = anthropic

        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise LLMError(
                "Umgebungsvariable ANTHROPIC_API_KEY ist nicht gesetzt. "
                "Setze sie mit `export ANTHROPIC_API_KEY=sk-ant-...`."
            )
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model
        self.max_tokens = max_tokens

    def create(
        self,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> Any:
        try:
            return self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                system=system,
                messages=messages,
                tools=tools,
            )
        except self._anthropic.APIError as exc:  # pragma: no cover - Netzabhaengig
            raise LLMError(f"Anthropic-API-Fehler: {exc}") from exc
