"""Tests fuer die reinen Live-DNS-Parser (offline, deterministisch)."""

from __future__ import annotations

from specter.analyzers.dns_security import analyze_dns
from specter.dns_live import build_dns_export, extract_ad_flag, extract_caa

# Echte dns.google-Antwort (SOA, do=1) mit gesetztem AD-Flag (DNSSEC validiert).
_SOA_SIGNED = {"Status": 0, "AD": True, "Answer": [
    {"name": "a.de.", "type": 6, "data": "ns.a.de. hostmaster.a.de. 1 2 3 4 5"}]}
_SOA_UNSIGNED = {"Status": 0, "AD": False, "Answer": []}

# Echte dns.google-Antwort (CAA, type 257).
_CAA = {"Status": 0, "Answer": [
    {"name": "a.de.", "type": 257, "data": "0 issue \"letsencrypt.org\""},
    {"name": "a.de.", "type": 257, "data": ""},
]}


def test_extract_ad_flag():
    assert extract_ad_flag(_SOA_SIGNED) is True
    assert extract_ad_flag(_SOA_UNSIGNED) is False
    assert extract_ad_flag("nope") is False
    assert extract_ad_flag({}) is False


def test_extract_caa_only_type_257_and_nonblank():
    assert extract_caa(_CAA) == ["0 issue \"letsencrypt.org\""]
    assert extract_caa("nope") == []
    assert extract_caa({"Answer": [{"type": 16, "data": "v=spf1"}]}) == []


def test_build_dns_export_signed_feeds_analyzer():
    export = build_dns_export("a.de", _SOA_SIGNED, _CAA)
    assert export == {"domain": "a.de", "dnssec": True,
                      "caa": ["0 issue \"letsencrypt.org\""]}
    # Signiert + CAA vorhanden -> der echte Analyzer meldet nichts.
    assert analyze_dns(export) == []


def test_build_dns_export_unsigned_feeds_analyzer():
    export = build_dns_export("a.de", _SOA_UNSIGNED, {})
    assert export["dnssec"] is False and export["caa"] == []
    titles = " ".join(f.title for f in analyze_dns(export))
    assert "DNSSEC nicht aktiv" in titles
    assert "Keine CAA-Records" in titles
