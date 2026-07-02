"""Tests für die reinen Live-Web/TLS-Parser (offline, deterministisch)."""

from __future__ import annotations

from specter.analyzers.http_headers import analyze_http_headers
from specter.analyzers.tls_certificates import analyze_tls
from specter.web_live import (
    build_headers_export, build_tls_export, days_until, parse_cookie,
    parse_header_lines, parse_s_client, parse_x509,
)

# Echte curl -sSI Beispielausgabe (verkürzt).
_CURL = (
    "HTTP/1.1 200 OK\r\n"
    "Server: Apache/2.4.29 (Ubuntu)\r\n"
    "Content-Type: text/html\r\n"
    "Set-Cookie: SID=abc123; Path=/\r\n"
    "Set-Cookie: theme=dark; Path=/; Secure; HttpOnly; SameSite=Lax\r\n"
    "\r\n"
)

# Echte openssl s_client Beispielausgabe (verkürzt).
_SCLIENT = (
    "---\n"
    "New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384\n"
    "SSL-Session:\n"
    "    Protocol  : TLSv1.2\n"
    "    Cipher    : ECDHE-RSA-AES256-GCM-SHA384\n"
)

# Echte openssl x509 -text -enddate -subject -issuer Beispielausgabe (verkürzt).
_X509_EXPIRED_RSA1024 = (
    "notAfter=Jun  1 12:00:00 2020 GMT\n"
    "Subject: CN=lab.local\n"
    "Issuer: CN=lab.local\n"
    "        Public Key Algorithm: rsaEncryption\n"
    "            Public-Key: (1024 bit)\n"
    "    Signature Algorithm: sha256WithRSAEncryption\n"
)


# -- Header ----------------------------------------------------------------

def test_parse_header_lines_splits_headers_and_cookies():
    headers, cookies = parse_header_lines(_CURL)
    assert headers["Server"] == "Apache/2.4.29 (Ubuntu)"
    assert "Set-Cookie" not in headers
    assert len(cookies) == 2


def test_parse_header_lines_skips_status_and_junk():
    headers, cookies = parse_header_lines("HTTP/2 200\nGarbageOhneDoppelpunkt\n\nX-Test: 1")
    assert headers == {"X-Test": "1"} and cookies == []


def test_parse_cookie_flags():
    insecure = parse_cookie("SID=abc; Path=/")
    assert insecure == {"name": "SID", "secure": False, "httponly": False, "samesite": ""}
    secure = parse_cookie("theme=dark; Secure; HttpOnly; SameSite=Lax")
    assert secure["secure"] and secure["httponly"] and secure["samesite"] == "Lax"


def test_parse_cookie_empty_defaults_name():
    assert parse_cookie("")["name"] == "cookie"


def test_build_headers_export_feeds_analyzer():
    export = build_headers_export("https://a.de", _CURL)
    assert export["url"] == "https://a.de"
    assert export["headers"]["Server"].startswith("Apache")
    assert [c["name"] for c in export["cookies"]] == ["SID", "theme"]
    # Der echte Analyzer erkennt Banner + unsicheres SID-Cookie.
    findings = analyze_http_headers(export)
    titles = " ".join(f.title for f in findings)
    assert "Server-Banner" in titles
    assert "Cookie ohne Secure-Flag: SID" in titles


# -- TLS -------------------------------------------------------------------

def test_parse_s_client():
    assert parse_s_client(_SCLIENT) == ("TLSv1.2", "ECDHE-RSA-AES256-GCM-SHA384")


def test_parse_s_client_empty():
    assert parse_s_client("nichts hier") == ("", "")


def test_parse_x509_fields():
    x = parse_x509(_X509_EXPIRED_RSA1024)
    assert x["not_after"] == "Jun  1 12:00:00 2020 GMT"
    assert x["key_type"] == "RSA" and x["key_bits"] == 1024
    assert x["signature_algorithm"] == "sha256WithRSAEncryption"
    assert x["self_signed"] is True


def test_parse_x509_ec_and_not_selfsigned():
    x = parse_x509("Subject: CN=a\nIssuer: CN=CA\n    Public Key Algorithm: id-ecPublicKey\n")
    assert x["key_type"] == "EC" and x["self_signed"] is False


def test_parse_x509_empty():
    x = parse_x509("leer")
    assert x == {"not_after": "", "signature_algorithm": "", "key_type": "",
                 "key_bits": 0, "self_signed": False}


def test_days_until_past_and_future():
    assert days_until("Jun  1 12:00:00 2020 GMT", "2026-07-02") < 0
    assert days_until("Jun  1 12:00:00 2030 GMT", "2026-07-02") > 0


def test_days_until_invalid():
    assert days_until("kein datum", "2026-07-02") is None
    assert days_until("Xxx  1 12:00:00 2020 GMT", "2026-07-02") is None


def test_build_tls_export_feeds_analyzer():
    export = build_tls_export("lab.local:443", _SCLIENT, _X509_EXPIRED_RSA1024, "2026-07-02")
    ep = export["endpoints"][0]
    assert ep["host"] == "lab.local:443"
    assert ep["certificate"]["days_until_expiry"] < 0
    assert ep["protocols"] == ["TLSv1.2"] and ep["ciphers"][0].startswith("ECDHE")
    # Der echte Analyzer erkennt abgelaufenes Zertifikat + zu kurzen Schlüssel + self-signed.
    findings = analyze_tls(export)
    titles = " ".join(f.title for f in findings)
    assert "abgelaufen" in titles
    assert "zu kurzem Schluessel" in titles
    assert "Selbstsigniert" in titles


def test_build_tls_export_no_protocol_no_expiry():
    # Kein s_client-Text, kein Datum -> leere Protokoll-/Cipher-Listen, kein days-Feld.
    export = build_tls_export("h", "", "leer", "2026-07-02")
    ep = export["endpoints"][0]
    assert ep["protocols"] == [] and ep["ciphers"] == []
    assert "days_until_expiry" not in ep["certificate"]
