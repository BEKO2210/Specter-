"""Gemeinsame Test-Fixtures und Helfer."""

from __future__ import annotations

from pathlib import Path

import pytest

from specter.config import Config, Engagement


def make_config(tmp_path: Path, **overrides) -> Config:
    """Erzeugt eine Test-Config mit einem freigegebenen targets-Verzeichnis."""
    allowed = tmp_path / "targets"
    allowed.mkdir(exist_ok=True)
    defaults = dict(
        engagement=Engagement("Test-Engagement", "Tester", "REF-1"),
        allowed_targets=["127.0.0.1", "192.168.56.0/24", "scanme.nmap.org"],
        forbidden_targets=["169.254.169.254"],
        allowed_paths=[allowed.resolve()],
        max_file_bytes=100_000,
        allowed_binaries=["echo", "nmap", "curl"],
        command_timeout=10,
        require_approval=False,
        max_iterations=5,
        model="claude-sonnet-5",
    )
    defaults.update(overrides)
    return Config(**defaults)


@pytest.fixture
def config(tmp_path) -> Config:
    return make_config(tmp_path)


@pytest.fixture
def targets_dir(config) -> Path:
    return config.allowed_paths[0]
