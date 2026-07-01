"""ABSICHTLICH VERWUNDBARE Beispiel-App - nur fuer Specter-Demos/Tests.

NICHT in Produktion verwenden. Enthaelt bewusst typische Schwachstellen,
damit Specter sie im White-Box-Scan findet.
"""

import hashlib
import subprocess

# Schwachstelle: fest kodiertes Secret (CWE-798)
API_KEY = "sk-live-DEMO-1234567890abcdef"
DB_PASSWORD = "P@ssw0rt123"

# Schwachstelle: Debug-Modus in Produktion (CWE-489)
DEBUG = True


def get_user(uid):
    # Schwachstelle: SQL-Injection durch String-Verkettung (CWE-89)
    query = "SELECT * FROM users WHERE id = " + uid
    return db.execute(query)  # noqa: F821 (db ist nur Platzhalter)


def run_ping(host):
    # Schwachstelle: Command-Injection durch shell=True (CWE-78)
    return subprocess.run("ping -c1 " + host, shell=True)


def hash_password(pw):
    # Schwachstelle: schwacher Hash (CWE-327)
    return hashlib.md5(pw.encode()).hexdigest()
