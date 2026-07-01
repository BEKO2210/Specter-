"""ABSICHTLICH VERWUNDBAR - Test-Fixture (Mustermann GmbH Kunden-API).

Nicht in Produktion verwenden.
"""

import hashlib
import subprocess

# Fest kodierter API-Schluessel
API_KEY = "sk-live-mustermann-9f8e7d6c5b4a"

# Debug-Modus in Produktion
DEBUG = True


def authenticate(user_input):
    # Dynamische Codeausfuehrung
    return eval(user_input)  # noqa: S307


def query_customer(customer_id):
    # SQL-Injection
    return db.execute("SELECT * FROM kunden WHERE id = " + customer_id)  # noqa: F821


def backup(host):
    # Command-Injection durch shell=True
    subprocess.run("rsync -a /data " + host, shell=True)


def hash_pw(pw):
    # Schwacher Hash
    return hashlib.md5(pw.encode()).hexdigest()
