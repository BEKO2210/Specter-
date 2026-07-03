"""Sicherheit des Report-Generators gegen Injection aus dem geprüften System.

Bedrohungsmodell: Ein bösartiger geprüfter Server (oder eine manipulierte
Export-Datei) kann Werte in Findings schmuggeln, die aus *seinem* Einflussbereich
stammen — Server-Banner, HTML-Kommentare, Zertifikatsfelder. Diese Werte landen
als Titel, Asset, Fundstelle und **Beleg** im Bericht.

Der HTML-Bericht wird im Browser geöffnet, der Markdown-Bericht in Viewern
(GitHub, VS Code, Obsidian) oder Markdown->PDF-Konvertern gerendert — beide
rendern eingebettetes HTML. Ohne Schutz wäre ein ``<script>`` im Banner ein
**Stored-XSS gegen den Prüfer**. Diese Tests sichern, dass keine
angreiferkontrollierte Zeichenkette ausführbar in den Bericht gelangt.
"""

from __future__ import annotations

import re

from specter.assets import AssetGraph
from specter.attack_paths import AttackPath
from specter.config import Config, Engagement
from specter.container_live import normalize_container, normalize_inspect
from specter.findings import Finding, FindingsStore, Severity
from specter.report import (
    _md_cell, _md_fence, _md_inline, build_markdown,
)
from specter.report_export import build_html

XSS = "<script>alert('xss')</script>"
IMG = "<img src=x onerror=alert(1)>"


def _cfg() -> Config:
    return Config(
        engagement=Engagement("Kunde", "Chef", "REF-1"),
        allowed_targets=["127.0.0.1"], forbidden_targets=[], allowed_paths=[],
        max_file_bytes=1000, allowed_binaries=["curl"], command_timeout=5,
        require_approval=False, max_iterations=3, model="claude-sonnet-5",
    )


def _evil_store() -> FindingsStore:
    store = FindingsStore()
    store.add(Finding(
        title=f"Banner {XSS}", category="web_security", severity=Severity.HOCH,
        asset=f"host {IMG}", evidence=f"Server: Apache {XSS}\n<!-- {IMG} -->",
        location=f"loc {XSS}", cwe="CWE-79", owner=f"team {XSS}",
        remediation=f"fix {XSS}",
    ))
    return store


# ------------------------------- HTML-Bericht -------------------------------

def test_html_report_escapes_all_attacker_fields():
    store = _evil_store()
    path = AttackPath(title=f"Pfad {XSS}", severity=Severity.KRITISCH,
                      steps=[f"Schritt {XSS}"], finding_ids=list(store.all()[0].id and [store.all()[0].id]),
                      rationale=f"Grund {IMG}")
    html = build_html(_cfg(), AssetGraph(), store, [path])
    # Keine ausführbaren Roh-Payloads.
    assert "<script>alert" not in html
    assert "<img src=x onerror" not in html
    # Sie sind als Entities enthalten (also gerendert, aber inert).
    assert "&lt;script&gt;" in html


def test_html_report_has_no_unescaped_angle_tag_from_evidence():
    """Kein <tag>, das nicht Teil des eigenen HTML-Gerüsts ist."""
    store = _evil_store()
    html = build_html(_cfg(), AssetGraph(), store, [])
    # Der Payload-Kern darf nur escaped vorkommen.
    assert "alert('xss')" not in html or "&lt;script&gt;alert" in html
    assert "<script" not in html.lower().replace("&lt;script", "")


# ----------------------------- Markdown-Bericht -----------------------------

def test_markdown_inline_fields_are_html_neutralized():
    store = _evil_store()
    path = AttackPath(title=f"Pfad {XSS}", severity=Severity.KRITISCH,
                      steps=[f"Schritt {XSS}"], finding_ids=[store.all()[0].id],
                      rationale=f"Grund {IMG}")
    md = build_markdown(_cfg(), AssetGraph(), store, [path])
    # Kein ausführbares <script>/<img> AUSSERHALB von Codeblöcken.
    outside = _strip_code_fences(md)
    assert "<script>" not in outside
    assert "<img src=x onerror" not in outside
    # Escaped-Form ist vorhanden.
    assert "&lt;script&gt;" in md


def test_markdown_evidence_fence_is_breakout_proof():
    """Beleg mit eigenem ```-Fence darf den Codeblock nicht schließen."""
    store = FindingsStore()
    store.add(Finding(
        title="x", category="web_security", severity=Severity.HOCH, asset="a",
        evidence="Zeile1\n```\n## Gefälschte Überschrift\n<script>alert(1)</script>\n```\ndanach",
    ))
    md = build_markdown(_cfg(), AssetGraph(), store, [])
    # Der umschließende Fence ist länger als der innere ```-Lauf.
    assert "````" in md
    # Nach dem Entfernen der Codeblöcke ist der Payload weg (also war er drin).
    outside = _strip_code_fences(md)
    assert "<script>" not in outside
    assert "## Gefälschte Überschrift" not in outside


def test_markdown_table_cells_pipe_safe():
    store = FindingsStore()
    store.add(Finding(title="A | B", category="injection", severity=Severity.HOCH,
                      asset="x | y"))
    md = build_markdown(_cfg(), AssetGraph(), store, [])
    row = next(ln for ln in md.splitlines() if ln.startswith("| SPEC-"))
    # Escaped-Pipes in der Zelle, Spaltenzahl bleibt korrekt.
    assert "\\|" in row
    assert row.count(" | ") >= 4


def test_benign_markdown_unchanged_by_hardening():
    """Regressionsanker: gutartige Inhalte bleiben unverändert lesbar."""
    assert _md_inline("SPF erlaubt beliebige Absender (+all/?all)") == \
        "SPF erlaubt beliebige Absender (+all/?all)"
    assert _md_inline("portal.musterversicherung.de:443") == \
        "portal.musterversicherung.de:443"
    assert _md_fence("Server: Apache/2.4.29") == "```\nServer: Apache/2.4.29\n```"
    assert _md_cell("MySQL") == "MySQL"


# ------------------------------ Helfer-Units ------------------------------

def test_md_inline_neutralizes_html_and_newlines():
    assert _md_inline("<b>x</b>") == "&lt;b&gt;x&lt;/b&gt;"
    assert _md_inline("a\n## fake") == "a ## fake"
    assert _md_inline("a\r\nb") == "a b"


def test_md_fence_grows_with_backtick_runs():
    assert _md_fence("no ticks") == "```\nno ticks\n```"
    assert _md_fence("has ``` fence").startswith("````")
    assert _md_fence("has ````` five").startswith("``````")


def test_md_cell_escapes_pipe():
    assert _md_cell("a|b") == "a\\|b"
    assert _md_cell("<x>|y") == "&lt;x&gt;\\|y"


# --------------------- Container-Kollektor Defense-in-Depth ---------------------

def test_normalize_container_survives_junk():
    for junk in [None, 5, "string", [], {"HostConfig": {"CapAdd": 5}},
                 {"Config": {"Image": ["x"]}}, {"HostConfig": "x"}]:
        result = normalize_container(junk)
        assert isinstance(result, dict)
        assert isinstance(result["cap_add"], list)


def test_normalize_container_capadd_string_becomes_list():
    result = normalize_container({"HostConfig": {"CapAdd": "SYS_ADMIN"}})
    assert result["cap_add"] == ["SYS_ADMIN"]


def test_normalize_inspect_ignores_non_dict_entries():
    out = normalize_inspect([{"Name": "/ok"}, 5, "x", None])
    assert len(out["containers"]) == 1
    assert out["containers"][0]["name"] == "ok"


# ------------------------------ Helfer ------------------------------

def _strip_code_fences(md: str) -> str:
    """Entfernt fenced Codeblöcke (``` bis ``````), damit nur der außerhalb
    gerenderte Markdown-Text übrig bleibt — dort darf kein HTML durchrutschen."""
    return re.sub(r"(?ms)^(`{3,})\n.*?^\1\s*$", "", md)
