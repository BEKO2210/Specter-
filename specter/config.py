"""Laedt und validiert die Scope-/Autorisierungsdatei (scope.yaml)."""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


class ScopeError(Exception):
    """Wird ausgeloest, wenn die Scope-Datei fehlt oder ungueltig ist."""


@dataclass
class Engagement:
    name: str
    authorized_by: str
    authorization_ref: str
    valid_until: str | None = None


@dataclass
class ScannerPolicy:
    """Freigabe- und Sicherheitsregeln fuer einen aktiven Scanner (z. B. nmap)."""

    enabled: bool = False
    allow_aggressive: bool = False
    extra_allowed_flags: list[str] = field(default_factory=list)
    timeout_seconds: int = 300
    max_output_bytes: int = 200_000

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "ScannerPolicy":
        data = data or {}
        return cls(
            enabled=bool(data.get("enabled", False)),
            allow_aggressive=bool(data.get("allow_aggressive", False)),
            extra_allowed_flags=[str(f) for f in (data.get("extra_allowed_flags") or [])],
            timeout_seconds=int(data.get("timeout_seconds", 300)),
            max_output_bytes=int(data.get("max_output_bytes", 200_000)),
        )


@dataclass
class GitHubIntegration:
    """Opt-in-Integration zum Erstellen von Draft-Pull-Requests aus Findings."""

    enabled: bool = False
    repo: str = ""                       # "owner/name"
    base_branch: str = "main"
    branch_prefix: str = "specter/fix-"
    token_env: str = "GITHUB_TOKEN"

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "GitHubIntegration":
        data = data or {}
        return cls(
            enabled=bool(data.get("enabled", False)),
            repo=str(data.get("repo", "")),
            base_branch=str(data.get("base_branch", "main")),
            branch_prefix=str(data.get("branch_prefix", "specter/fix-")),
            token_env=str(data.get("token_env", "GITHUB_TOKEN")),
        )


@dataclass
class Config:
    """Aufbereitete, validierte Konfiguration des Agenten."""

    engagement: Engagement
    allowed_targets: list[str]
    forbidden_targets: list[str]
    allowed_paths: list[Path]
    max_file_bytes: int
    allowed_binaries: list[str]
    command_timeout: int
    require_approval: bool
    max_iterations: int
    model: str
    scanners: dict[str, ScannerPolicy] = field(default_factory=dict)
    github: GitHubIntegration = field(default_factory=GitHubIntegration)
    raw: dict[str, Any] = field(default_factory=dict)

    def scanner_policy(self, name: str) -> ScannerPolicy:
        """Policy fuer einen Scanner; Default = deaktiviert (fail-closed)."""
        return self.scanners.get(name, ScannerPolicy())

    @classmethod
    def load(cls, path: str | Path) -> "Config":
        p = Path(path)
        if not p.exists():
            raise ScopeError(
                f"Scope-Datei nicht gefunden: {p}. "
                "Kopiere scope.example.yaml nach scope.yaml und passe sie an."
            )
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ScopeError(f"Scope-Datei ist kein gueltiges YAML: {exc}") from exc

        eng_raw = data.get("engagement") or {}
        for required in ("name", "authorized_by", "authorization_ref"):
            if not eng_raw.get(required):
                raise ScopeError(
                    f"engagement.{required} fehlt in der Scope-Datei. "
                    "Ohne dokumentierte Autorisierung startet Specter nicht."
                )
        engagement = Engagement(
            name=str(eng_raw["name"]),
            authorized_by=str(eng_raw["authorized_by"]),
            authorization_ref=str(eng_raw["authorization_ref"]),
            valid_until=eng_raw.get("valid_until"),
        )

        cls._check_valid_until(engagement.valid_until)

        network = data.get("network") or {}
        filesystem = data.get("filesystem") or {}
        commands = data.get("commands") or {}
        runtime = data.get("runtime") or {}
        scanners_raw = data.get("scanners") or {}
        integrations = data.get("integrations") or {}

        allowed_paths = [
            Path(pth).expanduser().resolve()
            for pth in (filesystem.get("allowed_paths") or [])
        ]
        scanners = {
            str(name): ScannerPolicy.from_dict(cfg)
            for name, cfg in scanners_raw.items()
        }
        github = GitHubIntegration.from_dict(integrations.get("github"))

        return cls(
            engagement=engagement,
            allowed_targets=[str(t) for t in (network.get("allowed_targets") or [])],
            forbidden_targets=[str(t) for t in (network.get("forbidden_targets") or [])],
            allowed_paths=allowed_paths,
            max_file_bytes=int(filesystem.get("max_file_bytes", 1_000_000)),
            allowed_binaries=[str(b) for b in (commands.get("allowed_binaries") or [])],
            command_timeout=int(commands.get("timeout_seconds", 300)),
            require_approval=bool(runtime.get("require_approval", True)),
            max_iterations=int(runtime.get("max_iterations", 25)),
            model=str(runtime.get("model", "claude-sonnet-5")),
            scanners=scanners,
            github=github,
            raw=data,
        )

    @staticmethod
    def _check_valid_until(valid_until: str | None) -> None:
        if not valid_until:
            return
        try:
            deadline = _dt.date.fromisoformat(str(valid_until))
        except ValueError as exc:
            raise ScopeError(
                f"engagement.valid_until ist kein gueltiges Datum (YYYY-MM-DD): {valid_until}"
            ) from exc
        if _dt.date.today() > deadline:
            raise ScopeError(
                f"Autorisierung ist am {deadline.isoformat()} abgelaufen. "
                "Erneuere die Beauftragung, bevor du fortfaehrst."
            )
