"""Tests für den Anthropic-LLM-Wrapper (Fehlerpfade ohne echten Netzzugriff)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from specter.llm import AnthropicLLM, LLMError


def test_missing_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(LLMError, match="ANTHROPIC_API_KEY"):
        AnthropicLLM(model="claude-sonnet-5")


def test_missing_package(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "anthropic":
            raise ImportError("kein anthropic")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(LLMError, match="anthropic"):
        AnthropicLLM(model="claude-sonnet-5")


def test_create_success(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    llm = AnthropicLLM(model="claude-sonnet-5")
    sentinel = SimpleNamespace(content=[], stop_reason="end_turn")
    llm.client = SimpleNamespace(
        messages=SimpleNamespace(create=lambda **kw: sentinel)
    )
    out = llm.create("sys", [{"role": "user", "content": "hi"}], [])
    assert out is sentinel


def test_create_wraps_api_error(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    llm = AnthropicLLM(model="claude-sonnet-5")

    class Boom(llm._anthropic.APIError):
        def __init__(self):
            pass

    def raise_boom(**kw):
        raise Boom()

    llm.client = SimpleNamespace(messages=SimpleNamespace(create=raise_boom))
    with pytest.raises(LLMError, match="Anthropic-API-Fehler"):
        llm.create("sys", [], [])
