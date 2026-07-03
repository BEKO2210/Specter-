"""Tests für die reinen Live-Datenbank-Parser (offline, deterministisch)."""

from __future__ import annotations

from specter.analyzers.database import analyze_database
from specter.db_live import build_database_export, redis_requires_auth


def test_redis_requires_auth_pong_means_no_auth():
    assert redis_requires_auth("+PONG\r\n") is False
    assert redis_requires_auth("+pong") is False


def test_redis_requires_auth_error_means_auth():
    assert redis_requires_auth("-NOAUTH Authentication required.") is True
    assert redis_requires_auth("-ERR Client sent AUTH, but no password is set") is True


def test_redis_requires_auth_unknown_defaults_to_auth():
    # Leere/unbekannte Antwort -> vorsichtshalber "Auth nötig" (kein Fehlalarm).
    assert redis_requires_auth("") is True
    assert redis_requires_auth("irgendwas") is True


def test_build_database_export_no_auth_feeds_analyzer():
    # Echte +PONG-Antwort eines offenen Redis -> Analyzer meldet fehlende Auth.
    export = build_database_export(
        "redis", "127.0.0.1", 6379, public=True, ping_response="+PONG\r\n")
    db = export["databases"][0]
    assert db["auth_required"] is False and db["public"] is True
    cats = {f.category for f in analyze_database(export)}
    assert "exposed_service" in cats and "auth_weakness" in cats


def test_build_database_export_authed_is_clean():
    export = build_database_export(
        "redis", "10.0.0.5", 6379, public=False,
        ping_response="-NOAUTH Authentication required.", tls=True)
    db = export["databases"][0]
    assert db["auth_required"] is True
    assert analyze_database(export) == []
