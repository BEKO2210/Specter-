"""Tests für die reinen Live-E-Mail-Check-Bausteine (offline, deterministisch)."""

from __future__ import annotations

from specter.analyzers.email_security import analyze_email_security
from specter.email_live import (
    build_email_export, dkim_entry, extract_txt, rsa_bits_from_der,
    select_record,
)


def _der_len(length: int) -> bytes:
    """DER-Längenkodierung (kurz oder lang)."""
    if length < 0x80:
        return bytes([length])
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _integer(nbytes: int) -> bytes:
    return b"\x02" + _der_len(nbytes) + b"\xff" * nbytes


# -- extract_txt -----------------------------------------------------------

def test_extract_txt_filters_and_strips():
    resp = {"Answer": [
        {"type": 16, "data": '"v=spf1 -all"'},
        {"type": 1, "data": "1.2.3.4"},        # kein TXT -> ignoriert
        "kaputt",                                # kein dict -> ignoriert
        {"type": 16, "data": "plain"},
    ]}
    assert extract_txt(resp) == ["v=spf1 -all", "plain"]


def test_extract_txt_non_dict():
    assert extract_txt("nope") == []
    assert extract_txt({}) == []


# -- select_record ---------------------------------------------------------

def test_select_record_case_insensitive_and_miss():
    txts = ["google-site-verification=x", "V=SPF1 include:_spf -all"]
    assert select_record("v=spf1", txts) == "V=SPF1 include:_spf -all"
    assert select_record("v=dmarc1", txts) == ""


# -- rsa_bits_from_der -----------------------------------------------------

def test_rsa_bits_rounds_to_2048():
    # SEQUENCE { BITSTRING { SEQUENCE { INTEGER(256B), INTEGER(3B exp) } } }
    inner = _integer(256) + _integer(3)
    seq_inner = b"\x30" + _der_len(len(inner)) + inner
    bitstr = b"\x03" + _der_len(len(seq_inner) + 1) + b"\x00" + seq_inner
    outer = b"\x30" + _der_len(len(bitstr)) + bitstr
    import base64
    assert rsa_bits_from_der(base64.b64encode(outer).decode()) == 2048


def test_rsa_bits_non_standard_and_other_tag():
    import base64
    # NULL (0x05) -> else-Zweig; INTEGER 100 Bytes -> 800 Bit (nicht gerundet).
    der = b"\x05\x00" + _integer(100)
    assert rsa_bits_from_der(base64.b64encode(der).decode()) == 800


def test_rsa_bits_invalid_base64():
    assert rsa_bits_from_der("!!!nicht base64!!!") == 0


def test_rsa_bits_truncated_after_tag():
    import base64
    # Nur ein Tag-Byte -> Schleife bricht sauber ab (kein Crash).
    assert rsa_bits_from_der(base64.b64encode(b"\x30").decode()) == 0


# -- dkim_entry ------------------------------------------------------------

def test_dkim_entry_without_p_is_none():
    assert dkim_entry("s1", ["v=DKIM1; k=rsa"]) is None


def test_dkim_entry_present_without_bits():
    # p= vorhanden aber leer/ungültig -> present ohne key_bits.
    entry = dkim_entry("s1", ["v=DKIM1; k=rsa; p="])
    assert entry == {"selector": "s1", "present": True}


def test_dkim_entry_with_bits():
    import base64
    # Echter DER mit 2048-Bit-Modulus als p=.
    inner = _integer(256) + _integer(3)
    seq_inner = b"\x30" + _der_len(len(inner)) + inner
    bitstr = b"\x03" + _der_len(len(seq_inner) + 1) + b"\x00" + seq_inner
    outer = b"\x30" + _der_len(len(bitstr)) + bitstr
    p = base64.b64encode(outer).decode()
    entry = dkim_entry("s1", [f"v=DKIM1; k=rsa; p={p}"])
    assert entry == {"selector": "s1", "present": True, "key_bits": 2048}


# -- build_email_export + End-to-End mit dem echten Analyzer ---------------

def test_build_export_and_analyze_weak_domain():
    export = build_email_export(
        "kunde.de",
        apex_txts=["v=spf1 include:_spf -all"],
        dmarc_txts=["v=DMARC1; p=none"],
        dkim_by_selector={"s1": ["v=DKIM1; k=rsa; p="], "leer": ["kein key hier"]})
    assert export["domain"] == "kunde.de"
    assert export["spf"] == "v=spf1 include:_spf -all"
    assert export["dmarc"] == "v=DMARC1; p=none"
    # Nur der Selector mit p= wird übernommen.
    assert [d["selector"] for d in export["dkim"]] == ["s1"]
    # Der echte Analyzer erkennt p=none.
    findings = analyze_email_security(export)
    assert any("p=none" in f.title for f in findings)


def test_build_export_empty_domain_all_missing():
    export = build_email_export("leer.de", [], [], {})
    assert export == {"domain": "leer.de", "spf": "", "dmarc": "", "dkim": []}
    # Alles fehlt -> SPF/DMARC/DKIM je ein Befund.
    assert len(analyze_email_security(export)) == 3
