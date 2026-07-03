"""Werkzeuge, die dem Agenten "Augen und Hände" geben.

Jedes Tool liefert ein Anthropic-Tool-Schema (`spec`) und eine `run`-Methode.
Alle aktiven Aktionen laufen zwingend durch die SafetyPolicy.
"""

from .base import Tool, ToolResult, build_registry

__all__ = ["Tool", "ToolResult", "build_registry"]
