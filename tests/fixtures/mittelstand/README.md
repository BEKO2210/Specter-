# Test-Fixture: Mustermann GmbH (bewusst verwundbar)

Simuliert die typische Angriffsfläche eines **deutschen Mittelständlers** und
dient ausschließlich den Specter-Tests. **Nicht in Produktion verwenden.**

Enthaltene, absichtlich eingebaute Schwachstellen:

| Bereich | Datei | Schwachstellen |
|---|---|---|
| Webshop (PHP) | `webshop/checkout.php` | SQL-Injection, DB-Secret, PII im Log |
| Kunden-API (Python) | `api/service.py` | API-Key, `eval`, `shell=True`, SQLi, MD5, DEBUG |
| ERP/DATEV (Java) | `erp/DatevConnector.java` | Buchhaltungs-Credentials, PII (Lohn) |
| Infrastruktur | `infra/docker-compose.yml` | RDP/DB offen (0.0.0.0), Default-Creds, alte Images |
| Infrastruktur | `infra/.env` | Secrets im Klartext (JWT, AWS, SMTP, Stripe) |
| Infrastruktur | `infra/nginx.conf` | SSLv3/TLS1.0, `proxy_ssl_verify off` |
| Infrastruktur | `infra/Dockerfile` | veraltetes Basis-Image (python:2.7, django 1.8) |
| Konfiguration | `config/application.properties` | Default-Admin, PII-Felder, log4j 2.14 |
| Datenbank | `db/schema.sql` | Klartext-Passwörter, besondere Daten (Art. 9 DSGVO) |
| — | `api/utils_clean.py` | **keine** — Kontrolle gegen Falsch-Positive |
