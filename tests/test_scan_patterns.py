"""Praezisionstests je Erkennungsmuster: richtige Kategorie/CWE, keine Fehlalarme.

Sichert die Scan-Heuristik gegen Regressionen ab - fuer jede Schwachstellen-
klasse ein positives Beispiel und am Ende eine Falsch-Positiv-Kontrolle.
"""

from __future__ import annotations

import pytest

from specter.audit import AuditLog
from specter.config import Config, Engagement
from specter.safety import SafetyPolicy
from specter.state import EngagementState
from specter.tools.code_scan import CodeScanTool


def _scan(tmp_path, filename: str, content: str) -> EngagementState:
    allowed = tmp_path / "targets"
    allowed.mkdir(exist_ok=True)
    (allowed / filename).write_text(content, encoding="utf-8")
    cfg = Config(
        engagement=Engagement("X", "Y", "R"),
        allowed_targets=["127.0.0.1"], forbidden_targets=[],
        allowed_paths=[allowed.resolve()], max_file_bytes=100_000,
        allowed_binaries=["curl"], command_timeout=5,
        require_approval=False, max_iterations=5, model="claude-sonnet-5",
    )
    state = EngagementState()
    CodeScanTool(cfg, SafetyPolicy(cfg), AuditLog(tmp_path / "a"), state).run(
        {"path": str(allowed)}
    )
    return state


# (Dateiname, Codezeile, erwartete Kategorie, erwartete CWE)
CASES = [
    ("s.py", 'API_KEY = "sk-live-abcdef123"', "secret_exposure", "CWE-798"),
    ("s.env", "JWT_SECRET=supergeheimwert123456", "secret_exposure", "CWE-798"),
    ("aws.yml", "aws_secret_access_key: AKIA1234567890", "secret_exposure", "CWE-798"),
    ("e.py", "result = eval(user_input)", "injection", "CWE-95"),
    ("sh.py", "subprocess.run(cmd, shell=True)", "injection", "CWE-78"),
    ("q.py", 'sql = "SELECT * FROM t WHERE id=" + uid', "injection", "CWE-89"),
    ("h.py", "hashlib.md5(pw.encode())", "crypto_weakness", "CWE-327"),
    ("t.py", "requests.get(url, verify=False)", "transport_security", "CWE-295"),
    ("d.py", "obj = pickle.loads(data)", "deserialization", "CWE-502"),
    ("cfg.py", "DEBUG = True", "misconfiguration", "CWE-489"),
    ("dc.ini", "admin = admin", "default_credentials", "CWE-1392"),
    ("pii.txt", "Feld: Sozialversicherungsnummer", "personal_data", "CWE-359"),
    ("old.txt", "dependency: log4j 2.14.0", "outdated_component", "CWE-1104"),
]


@pytest.mark.parametrize("filename,line,category,cwe", CASES)
def test_pattern_detects_category(tmp_path, filename, line, category, cwe):
    state = _scan(tmp_path, filename, line + "\n")
    cats = {f.category for f in state.findings.all()}
    assert category in cats, f"{category} nicht erkannt in: {line}"
    match = [f for f in state.findings.all() if f.category == category][0]
    assert match.cwe == cwe


def test_clean_code_no_false_positives(tmp_path):
    clean = """
import math

def flaeche(radius: float) -> float:
    return math.pi * radius * radius

class Rechnung:
    def __init__(self, betrag: float) -> None:
        self.betrag = betrag

    def mit_mwst(self) -> float:
        return self.betrag * 1.19

WILLKOMMEN = "Guten Tag"
MAX_VERSUCHE = 3
"""
    state = _scan(tmp_path, "sauber.py", clean)
    assert len(state.findings) == 0


def test_pii_special_categories_detected(tmp_path):
    """Besondere Datenkategorien nach Art. 9 DSGVO werden als PII erfasst."""
    state = _scan(tmp_path, "art9.txt",
                  "Verarbeitung: Gesundheitsdaten, Geburtsdatum, IBAN\n")
    pii = [f for f in state.findings.all() if f.category == "personal_data"]
    assert len(pii) >= 1


def test_severity_mapping_is_correct(tmp_path):
    """Kritische Muster sind mind. 'hoch', informelle niedriger eingestuft."""
    from specter.findings import Severity
    state = _scan(tmp_path, "mix.py",
                  'API_KEY = "sk-live-xxxxxx"\nDEBUG = True\n')
    by_cat = {f.category: f.severity for f in state.findings.all()}
    assert by_cat["secret_exposure"] >= Severity.HOCH
    assert by_cat["misconfiguration"] <= Severity.NIEDRIG
