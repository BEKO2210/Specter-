"""Der Benchmark-Korpus: markierte Szenarien mit vollständiger Ground Truth.

Jedes Szenario ist ein realistischer, aber synthetischer Export, dessen Soll-
Ergebnis exakt bekannt ist. Der Korpus ist bewusst **adversarial** aufgebaut:

* **Schwellenwerte** liegen genau auf der Kante (Passwortlänge 12, DKIM 1024 Bit,
  Zertifikat 30 Tage Restlaufzeit, krbtgt 180 Tage, 8 Domänen-Admins …) — sowohl
  knapp darüber (muss finden) als auch exakt auf/unter der Grenze (darf nicht).
* **Täuschungen** sehen gefährlich aus, sind es aber nicht (öffentlicher Port 443
  auf einem Webserver, interner RDP-Zugang, EC-Schlüssel mit 256 Bit, ein per
  Conditional Access vollständig abgesichertes M365-Tenant) — oder umgekehrt
  (eine *deaktivierte* CA-Richtlinie schützt nicht; ein Access-Key ohne
  `last_used`-Feld gilt als ungenutzt).
* **Numerischer Versionsvergleich**: `internal-lib 2.9.0` unter `< 2.10.0` MUSS
  als verwundbar erkannt werden — ein naiver String-Vergleich (`"2.9.0" > "2.10.0"`)
  würde die Lücke übersehen. Genau solche Fallen trennen ein gutes von einem
  oberflächlichen Werkzeug.

Die gehärteten Szenarien (`kind="hardened"`) sind die Basis für die
Falsch-Positiv-Rate: Sie beschreiben den sauberen Soll-Zustand und dürfen
**null** Funde erzeugen.
"""

from __future__ import annotations

from specter.findings import Severity

from .model import Expect, Scenario

# Kürzel für die Schweregrade — hält die Erwartungslisten lesbar.
K, H, M, N = Severity.KRITISCH, Severity.HOCH, Severity.MITTEL, Severity.NIEDRIG


def _members(prefix: str, n: int) -> list[str]:
    return [f"{prefix}{i}" for i in range(n)]


SCENARIOS: list[Scenario] = [
    # ================================ E-MAIL ================================
    Scenario(
        "email-missing", "email", "vuln",
        "Domain ohne SPF/DKIM/DMARC",
        {"domain": "kmu-ohne-schutz.de"},
        (
            Expect("email_security", "Kein SPF-Eintrag", H),
            Expect("email_security", "Kein DMARC-Eintrag", H),
            Expect("email_security", "Kein DKIM-Schlüssel", M),
        ),
        "Der häufigste Mittelstands-Befund: gar kein Spoofing-Schutz.",
    ),
    Scenario(
        "email-weak", "email", "vuln",
        "SPF +all, DMARC p=none, DKIM 1024 Bit",
        {
            "domain": "kmu-schwach.de",
            "spf": "v=spf1 include:_spf.google.com +all",
            "dmarc": "v=DMARC1; p=none",
            "dkim": [
                {"selector": "google", "key_bits": 1024, "present": True},
                {"selector": "legacy", "present": False},
            ],
        },
        (
            Expect("email_security", "SPF erlaubt beliebige Absender", H),
            Expect("email_security", "DMARC nur im Monitoring-Modus", M),
            Expect("email_security", "DMARC ohne Auswertungs-Reports", N),
            Expect("crypto_weakness", "nicht mehr zeitgemäß", N),
        ),
        "+all hebt SPF auf, p=none erzwingt nichts, 1024-Bit-DKIM ist veraltet.",
    ),
    Scenario(
        "email-hardened", "email", "hardened",
        "SPF -all, DMARC p=reject, DKIM 2048 Bit",
        {
            "domain": "kmu-sauber.de",
            "spf": "v=spf1 include:_spf.google.com -all",
            "dmarc": "v=DMARC1; p=reject; rua=mailto:dmarc@kmu-sauber.de",
            "dkim": [{"selector": "s2024", "key_bits": 2048, "present": True}],
        },
        (),
        "Vollständig gehärtet — es darf kein Fund entstehen.",
    ),
    Scenario(
        "email-dkim-bits", "email", "boundary",
        "DKIM 1024/2048/1023 Bit nebeneinander",
        {
            "domain": "kmu-dkim.de",
            "spf": "v=spf1 -all",
            "dmarc": "v=DMARC1; p=reject; rua=mailto:d@kmu-dkim.de",
            "dkim": [
                {"selector": "a", "key_bits": 1024, "present": True},
                {"selector": "b", "key_bits": 2048, "present": True},
                {"selector": "c", "key_bits": 1023, "present": True},
            ],
        },
        (
            Expect("crypto_weakness", "1024 Bit", N),
            Expect("crypto_weakness", "1023 Bit", H),
        ),
        "2048 ist sauber, 1024 ist grenzwertig (niedrig), <1024 ist zu schwach (hoch).",
    ),
    Scenario(
        "email-spf-noall", "email", "confuser",
        "SPF ohne all-Mechanismus, sonst sauber",
        {
            "domain": "kmu-spf.de",
            "spf": "v=spf1 ip4:198.51.100.0/24",
            "dmarc": "v=DMARC1; p=quarantine; rua=mailto:d@kmu-spf.de",
            "dkim": [{"selector": "a", "key_bits": 2048, "present": True}],
        },
        (Expect("email_security", "SPF ohne abschließenden all-Mechanismus", M),),
        "p=quarantine darf NICHT als p=none gewertet werden; nur das fehlende all zählt.",
    ),

    # ================================= DNS =================================
    Scenario(
        "dns-vuln", "dns", "vuln",
        "Kein DNSSEC/CAA, offener AXFR, Wildcard, dangling CNAME",
        {
            "domain": "kmu-dns.de", "dnssec": False, "caa": [],
            "wildcard": True, "zone_transfer": True,
            "dangling_cnames": ["alt.kmu-dns.de -> gone.azurewebsites.net"],
        },
        (
            Expect("dns_security", "DNSSEC nicht aktiv", M),
            Expect("dns_security", "Keine CAA-Records", N),
            Expect("dns_security", "Offener Zonentransfer (AXFR)", H),
            Expect("dns_security", "Wildcard-DNS-Eintrag", N),
            Expect("dns_security", "Dangling CNAME", H),
        ),
        "Alle fünf DNS-Prüfungen schlagen an.",
    ),
    Scenario(
        "dns-hardened", "dns", "hardened",
        "DNSSEC + CAA aktiv, kein AXFR/Wildcard",
        {
            "domain": "kmu-dns-ok.de", "dnssec": True,
            "caa": ["0 issue \"letsencrypt.org\""],
            "wildcard": False, "zone_transfer": False, "dangling_cnames": [],
        },
        (),
        "Sauberer Soll-Zustand — null Funde.",
    ),
    Scenario(
        "dns-blank-caa", "dns", "confuser",
        "CAA-Liste vorhanden, aber nur Leerstrings",
        {
            "domain": "kmu-caa.de", "dnssec": True,
            "caa": ["", "   "], "wildcard": False, "zone_transfer": False,
        },
        (Expect("dns_security", "Keine CAA-Records", N),),
        "Eine mit Leerstrings gefüllte CAA-Liste zählt korrekt als 'keine CAA'.",
    ),

    # ================================= HTTP =================================
    Scenario(
        "http-vuln", "http", "vuln",
        "Portal ohne Header, unsichere Cookies",
        {
            "url": "https://portal.kmu-web.de",
            "headers": {
                "Server": "Apache/2.4.29 (Ubuntu)",
                "X-Powered-By": "PHP/7.2.24",
                "Content-Type": "text/html; charset=UTF-8",
            },
            "cookies": [
                {"name": "SESSIONID", "secure": False, "httponly": False,
                 "samesite": "None"},
            ],
        },
        (
            Expect("transport_security", "Kein HSTS", H),
            Expect("web_security", "Keine Content-Security-Policy", M),
            Expect("web_security", "Clickjacking-Schutz fehlt", M),
            Expect("web_security", "X-Content-Type-Options nicht 'nosniff'", N),
            Expect("web_security", "Keine Referrer-Policy", N),
            Expect("web_security", "Keine Permissions-Policy", N),
            Expect("web_security", "Server-Banner verrät Software", N),
            Expect("web_security", "X-Powered-By verrät Software", N),
            Expect("web_security", "Cookie ohne Secure-Flag", M),
            Expect("web_security", "Cookie ohne HttpOnly-Flag", M),
            Expect("web_security", "Cookie ohne SameSite-Schutz", N),
        ),
        "Elf klassische Web-Härtungslücken auf einem Endpunkt.",
    ),
    Scenario(
        "http-hardened", "http", "hardened",
        "Alle Header gesetzt, Cookie sicher",
        {
            "url": "https://www.kmu-web.de",
            "headers": {
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "Content-Security-Policy": "default-src 'self'",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "geolocation=()",
            },
            "cookies": [
                {"name": "consent", "secure": True, "httponly": True,
                 "samesite": "Lax"},
            ],
        },
        (),
        "Vollständig gehärteter Endpunkt — null Funde.",
    ),
    Scenario(
        "http-hsts-short", "http", "boundary",
        "HSTS knapp unter 180 Tagen, Cookie SameSite=None",
        {
            "url": "https://kurz.kmu-web.de",
            "headers": {
                "Strict-Transport-Security": "max-age=15551999",
                "Content-Security-Policy": "default-src 'self'",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "geolocation=()",
            },
            "cookies": [
                {"name": "sid", "secure": True, "httponly": True,
                 "samesite": "None"},
            ],
        },
        (
            Expect("transport_security", "HSTS mit zu kurzer Gültigkeit", N),
            Expect("web_security", "Cookie ohne SameSite-Schutz", N),
        ),
        "max-age=15551999 ist eine Sekunde zu kurz; SameSite=None ist kein Schutz.",
    ),
    Scenario(
        "http-hsts-exact", "http", "boundary",
        "HSTS exakt auf der Schwelle, Cookie SameSite=Strict",
        {
            "url": "https://exakt.kmu-web.de",
            "headers": {
                "Strict-Transport-Security": "max-age=15552000",
                "Content-Security-Policy": "default-src 'self'",
                "X-Frame-Options": "SAMEORIGIN",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "geolocation=()",
            },
            "cookies": [
                {"name": "sid", "secure": True, "httponly": True,
                 "samesite": "Strict"},
            ],
        },
        (),
        "Exakt 15552000 Sekunden gilt als ausreichend — kein Fund.",
    ),

    # ================================= TLS =================================
    Scenario(
        "tls-vuln", "tls", "vuln",
        "Abgelaufen, SHA-1, 1024 Bit, SSLv3, RC4/3DES",
        {"endpoints": [{
            "host": "portal.kmu-tls.de:443",
            "certificate": {
                "days_until_expiry": -4,
                "signature_algorithm": "sha1WithRSAEncryption",
                "key_type": "RSA", "key_bits": 1024, "self_signed": False,
            },
            "protocols": ["SSLv3", "TLSv1.0", "TLSv1.2"],
            "ciphers": ["ECDHE-RSA-AES256-GCM-SHA384", "RC4-SHA", "DES-CBC3-SHA"],
        }]},
        (
            Expect("transport_security", "TLS-Zertifikat abgelaufen", H),
            Expect("crypto_weakness", "schwacher Signatur", H),
            Expect("crypto_weakness", "zu kurzem Schlüssel (1024 Bit)", H),
            Expect("transport_security", "(SSLv3)", H),
            Expect("transport_security", "(TLSv1.0)", M),
            Expect("crypto_weakness", "(RC4-SHA)", M),
            Expect("crypto_weakness", "(DES-CBC3-SHA)", M),
        ),
        "Ein Lehrbuch-Endpunkt mit sieben unabhängigen TLS-Schwächen.",
    ),
    Scenario(
        "tls-hardened", "tls", "hardened",
        "TLS 1.2/1.3, SHA-256, RSA 2048, gültig",
        {"endpoints": [{
            "host": "mail.kmu-tls.de:443",
            "certificate": {
                "days_until_expiry": 200,
                "signature_algorithm": "sha256WithRSAEncryption",
                "key_type": "RSA", "key_bits": 2048, "self_signed": False,
            },
            "protocols": ["TLSv1.2", "TLSv1.3"],
            "ciphers": ["ECDHE-RSA-AES256-GCM-SHA384",
                        "ECDHE-ECDSA-AES128-GCM-SHA256"],
        }]},
        (),
        "Moderne, saubere TLS-Konfiguration — null Funde.",
    ),
    Scenario(
        "tls-ec-key", "tls", "confuser",
        "EC-Schlüssel 256 Bit, Ablauf in 31 Tagen",
        {"endpoints": [{
            "host": "api.kmu-tls.de:443",
            "certificate": {
                "days_until_expiry": 31,
                "signature_algorithm": "ecdsa-with-SHA256",
                "key_type": "EC", "key_bits": 256, "self_signed": False,
            },
            "protocols": ["TLSv1.2", "TLSv1.3"],
            "ciphers": ["TLS_AES_128_GCM_SHA256"],
        }]},
        (),
        "256-Bit-EC ist stark (nicht mit RSA-1024 verwechseln); 31 Tage sind ok.",
    ),
    Scenario(
        "tls-expiry-warn", "tls", "boundary",
        "Ablauf in exakt 30 Tagen, selbstsigniert",
        {"endpoints": [{
            "host": "warn.kmu-tls.de:443",
            "certificate": {
                "days_until_expiry": 30,
                "signature_algorithm": "sha256WithRSAEncryption",
                "key_type": "RSA", "key_bits": 2048, "self_signed": True,
            },
            "protocols": ["TLSv1.2"],
            "ciphers": ["ECDHE-RSA-AES256-GCM-SHA384"],
        }]},
        (
            Expect("transport_security", "läuft in 30 Tagen ab", M),
            Expect("misconfiguration", "Selbstsigniertes TLS-Zertifikat", M),
        ),
        "30 Tage lösen exakt die Warnung aus; Selbstsignierung ist ein eigener Fund.",
    ),

    # =============================== DATENBANK ===============================
    Scenario(
        "db-redis-open", "database", "vuln",
        "Redis öffentlich, ohne Auth, ohne TLS",
        {"databases": [{"engine": "redis", "port": 6379, "public": True,
                        "auth_required": False, "tls": False,
                        "default_creds": False}]},
        (
            Expect("exposed_service", "Datenbank öffentlich erreichbar", H),
            Expect("auth_weakness", "Datenbank ohne Authentifizierung", H),
            Expect("transport_security", "Unverschlüsselter Datenbank-Transport", M),
        ),
        "Der Klassiker: ein offener, unauthentifizierter Redis.",
    ),
    Scenario(
        "db-default-creds", "database", "vuln",
        "MySQL öffentlich mit Default-Zugangsdaten",
        {"databases": [{"engine": "mysql", "port": 3306, "public": True,
                        "auth_required": True, "tls": False,
                        "default_creds": True}]},
        (
            Expect("exposed_service", "Datenbank öffentlich erreichbar", H),
            Expect("default_credentials", "Standard-/Default-Zugangsdaten", K),
            Expect("transport_security", "Unverschlüsselter Datenbank-Transport", M),
        ),
        "Default-Creds sind kritisch — das erste Angriffsziel.",
    ),
    Scenario(
        "db-hardened", "database", "hardened",
        "PostgreSQL privat, Auth + TLS",
        {"databases": [{"engine": "postgresql", "port": 5432, "public": False,
                        "auth_required": True, "tls": True,
                        "default_creds": False}]},
        (),
        "Nicht öffentlich, authentifiziert, verschlüsselt — null Funde.",
    ),
    Scenario(
        "db-minimal", "database", "confuser",
        "Nur engine/port angegeben, keine Flags",
        {"databases": [{"engine": "postgresql", "port": 5432}]},
        (),
        "Fehlende Flags dürfen NICHT als unsicher gewertet werden (nur explizites False).",
    ),
    Scenario(
        "db-public-only", "database", "confuser",
        "Öffentlich, aber authentifiziert und verschlüsselt",
        {"databases": [{"engine": "mysql", "port": 3306, "public": True,
                        "auth_required": True, "tls": True,
                        "default_creds": False}]},
        (Expect("exposed_service", "Datenbank öffentlich erreichbar", H),),
        "Nur die Exposition zählt — kein Auth-/TLS-Fehlalarm.",
    ),

    # =============================== CONTAINER ===============================
    Scenario(
        "container-vuln", "container", "vuln",
        "Privileged, docker.sock, SYS_ADMIN, host-net, root, :latest",
        {"containers": [{
            "name": "legacy-web", "image": "nginx:latest",
            "privileged": True, "host_network": True, "cap_add": ["SYS_ADMIN"],
            "user": "", "docker_socket_mounted": True,
            "ports": ["0.0.0.0:8080->80/tcp"],
        }]},
        (
            Expect("container_security", "Privilegierter Container", K),
            Expect("container_security", "Docker-Socket im Container gemountet", K),
            Expect("container_security", "Gefährliche Capabilities", H),
            Expect("container_security", "Host-Networking aktiv", M),
            Expect("container_security", "Container läuft als root", M),
            Expect("container_security", "Ungepinntes Image (:latest)", N),
            Expect("exposed_service", "Container-Port auf allen Interfaces", M),
        ),
        "Der maximal fehlkonfigurierte Container — sieben Funde.",
    ),
    Scenario(
        "container-hardened", "container", "hardened",
        "Gepinnt, unprivilegiert, harmlose Caps, 127.0.0.1",
        {"containers": [{
            "name": "web", "image": "nginx:1.25.3",
            "privileged": False, "host_network": False,
            "cap_add": ["NET_BIND_SERVICE"], "user": "1000",
            "docker_socket_mounted": False,
            "ports": ["127.0.0.1:8080->80/tcp"],
        }]},
        (),
        "Best-Practice-Container — null Funde.",
    ),
    Scenario(
        "container-caps-mix", "container", "confuser",
        "Gemischte Caps, User 0:0, Registry-Image mit Tag",
        {"containers": [{
            "name": "svc", "image": "registry.example.io/team/app:2.1",
            "privileged": False, "host_network": False,
            "cap_add": ["CHOWN", "SYS_ADMIN", "NET_RAW"], "user": "0:0",
            "docker_socket_mounted": False,
            "ports": ["127.0.0.1:9000->9000/tcp"],
        }]},
        (
            Expect("container_security", "Gefährliche Capabilities", H),
            Expect("container_security", "Container läuft als root", M),
        ),
        "Nur SYS_ADMIN/NET_RAW sind gefährlich (CHOWN nicht); 0:0 ist root; das getaggte Image ist ok.",
    ),

    # ============================== ABHÄNGIGKEITEN ==============================
    Scenario(
        "dep-vuln", "dependency", "vuln",
        "Log4Shell + numerischer Versionsvergleich (2.9.0 < 2.10.0)",
        {
            "project": "portal-backend",
            "dependencies": [
                {"name": "log4j-core", "version": "2.14.1", "ecosystem": "maven"},
                {"name": "internal-lib", "version": "2.9.0", "ecosystem": "pypi"},
            ],
            "advisories": [
                {"name": "log4j-core", "ecosystem": "maven",
                 "vulnerable": "<2.15.0", "fixed": "2.17.1",
                 "cve": "CVE-2021-44228", "severity": "kritisch",
                 "title": "Log4Shell Remote Code Execution"},
                {"name": "internal-lib", "ecosystem": "pypi",
                 "vulnerable": "<2.10.0", "fixed": "2.10.0",
                 "cve": "CVE-2024-0001", "severity": "hoch",
                 "title": "Auth-Bypass"},
            ],
        },
        (
            Expect("outdated_component", "log4j-core 2.14.1", K),
            Expect("outdated_component", "internal-lib 2.9.0", H),
        ),
        "2.9.0 < 2.10.0 nur bei numerischem Vergleich — String-Vergleich übersähe es.",
    ),
    Scenario(
        "dep-patched", "dependency", "hardened",
        "Gepatchte Versionen, exakt auf der Fix-Grenze",
        {
            "project": "portal-backend",
            "dependencies": [
                {"name": "log4j-core", "version": "2.17.1", "ecosystem": "maven"},
                {"name": "internal-lib", "version": "2.10.0", "ecosystem": "pypi"},
                {"name": "fastapi", "version": "0.110.0", "ecosystem": "pypi"},
            ],
            "advisories": [
                {"name": "log4j-core", "ecosystem": "maven",
                 "vulnerable": "<2.15.0", "fixed": "2.17.1",
                 "cve": "CVE-2021-44228", "severity": "kritisch", "title": "Log4Shell"},
                {"name": "internal-lib", "ecosystem": "pypi",
                 "vulnerable": "<2.10.0", "fixed": "2.10.0",
                 "cve": "CVE-2024-0001", "severity": "hoch", "title": "Auth-Bypass"},
            ],
        },
        (),
        "2.10.0 ist NICHT < 2.10.0 — die obere Grenze ist exklusiv, kein Fehlalarm.",
    ),
    Scenario(
        "dep-confuser", "dependency", "confuser",
        "Deprecated + ungepinnt + Ecosystem-Fehlpaarung",
        {
            "project": "web",
            "dependencies": [
                {"name": "lodash", "version": "4.17.11", "ecosystem": "npm",
                 "deprecated": True},
                {"name": "requests", "version": "*", "ecosystem": "pypi"},
                {"name": "django", "version": "2.2.0", "ecosystem": "npm"},
            ],
            "advisories": [
                {"name": "django", "ecosystem": "pypi",
                 "vulnerable": ">=2.0,<2.2.28", "fixed": "2.2.28",
                 "cve": "CVE-2022-28346", "severity": "hoch", "title": "SQLi"},
            ],
        },
        (
            Expect("outdated_component", "Nicht mehr gepflegte Abhängigkeit: lodash", M),
            Expect("outdated_component", "Ungepinnte Abhängigkeit: requests", N),
        ),
        "Das django-Advisory (pypi) darf NICHT auf das npm-Paket gleichen Namens zutreffen.",
    ),
    Scenario(
        "dep-range", "dependency", "boundary",
        "Bereichs-Constraint >=2.0,<2.2.28 exakt an der Grenze",
        {
            "project": "web",
            "dependencies": [
                {"name": "django", "version": "2.2.27", "ecosystem": "pypi"},
                {"name": "django-lts", "version": "2.2.28", "ecosystem": "pypi"},
            ],
            "advisories": [
                {"name": "django", "ecosystem": "pypi",
                 "vulnerable": ">=2.0,<2.2.28", "fixed": "2.2.28",
                 "cve": "CVE-2022-28346", "severity": "hoch", "title": "SQLi"},
                {"name": "django-lts", "ecosystem": "pypi",
                 "vulnerable": ">=2.0,<2.2.28", "fixed": "2.2.28",
                 "cve": "CVE-2022-28346", "severity": "hoch", "title": "SQLi"},
            ],
        },
        (Expect("outdated_component", "django 2.2.27", H),),
        "2.2.27 liegt im Bereich, 2.2.28 (obere Grenze exklusiv) nicht.",
    ),

    # ================================ BACKUP ================================
    Scenario(
        "backup-vuln", "backup", "vuln",
        "Eine Kopie, kein Offsite/Immutable/Restore/MFA",
        {
            "organization": "Muster AG",
            "backups": [{"name": "fileserver-daily", "copies": 1,
                         "offsite": False, "offline_or_immutable": False,
                         "encrypted": False, "restore_tested": False,
                         "last_restore_test_days": 500, "mfa_on_console": False,
                         "retention_days": 7}],
            "policy": {"documented": False},
        },
        (
            Expect("backup_resilience", "Höchstens eine Backup-Kopie", H),
            Expect("backup_resilience", "Kein offline-/unveränderbares", H),
            Expect("backup_resilience", "Keine Offsite-Kopie", H),
            Expect("backup_resilience", "Wiederherstellung nie getestet", H),
            Expect("backup_resilience", "Backup-Konsole ohne MFA", M),
            Expect("backup_resilience", "Backup nicht verschlüsselt", M),
            Expect("backup_resilience", "Zu kurze Backup-Aufbewahrung", M),
            Expect("backup_resilience", "Kein dokumentiertes", N),
        ),
        "Der ransomware-tödliche Zustand: kein unveränderbares, getestetes Backup.",
    ),
    Scenario(
        "backup-hardened", "backup", "hardened",
        "3 Kopien, offsite, immutable, getestet, MFA",
        {
            "organization": "Muster AG",
            "backups": [{"name": "erp", "copies": 3, "offsite": True,
                         "offline_or_immutable": True, "encrypted": True,
                         "restore_tested": True, "last_restore_test_days": 100,
                         "mfa_on_console": True, "retention_days": 90}],
            "policy": {"documented": True},
        },
        (),
        "3-2-1 erfüllt, immutable, jährlich getestet — null Funde.",
    ),
    Scenario(
        "backup-partial", "backup", "confuser",
        "Zwei Kopien, Restore vor 400 Tagen getestet",
        {
            "organization": "Muster AG",
            "backups": [{"name": "nas", "copies": 2, "offsite": True,
                         "offline_or_immutable": True, "encrypted": True,
                         "restore_tested": True, "last_restore_test_days": 400,
                         "mfa_on_console": True, "retention_days": 30}],
        },
        (
            Expect("backup_resilience", "Zu wenige Backup-Kopien", M),
            Expect("backup_resilience", "Restore-Test überfällig", H),
        ),
        "2 Kopien sind kein SPOF, aber unter der 3-2-1-Regel; Restore vor >365 Tagen ist überfällig.",
    ),
    Scenario(
        "backup-thresholds", "backup", "boundary",
        "3 Kopien, Restore vor exakt 365 Tagen, 30 Tage Retention",
        {
            "organization": "Muster AG",
            "backups": [{"name": "x", "copies": 3, "offsite": True,
                         "offline_or_immutable": True, "encrypted": True,
                         "restore_tested": True, "last_restore_test_days": 365,
                         "mfa_on_console": True, "retention_days": 30}],
            "policy": {"documented": True},
        },
        (),
        "Genau auf allen Schwellen (3 Kopien, 365 Tage, 30 Tage) — noch sauber.",
    ),

    # =============================== FIREWALL ===============================
    Scenario(
        "fw-vuln", "firewall", "vuln",
        "Any-Any, offenes RDP/SSH/MSSQL, Legacy-VPN, offenes Mgmt",
        {
            "device": "fw-hq",
            "rules": [
                {"name": "permit-any-out", "action": "allow", "source": "any",
                 "destination": "any", "service": "any"},
                {"name": "rdp-support", "action": "allow", "source": "0.0.0.0/0",
                 "destination": "10.0.0.20", "service": "RDP", "port": 3389},
                {"name": "ssh-admin", "action": "allow", "source": "0.0.0.0/0",
                 "destination": "10.0.0.5", "service": "ssh"},
                {"name": "db-exposed", "action": "allow", "source": "any",
                 "destination": "10.0.0.30", "service": "MSSQL", "port": 1433},
                {"name": "internal-web", "action": "allow", "source": "10.0.0.0/8",
                 "destination": "10.0.0.40", "service": "https", "port": 443},
                {"name": "deny-telnet", "action": "deny", "source": "any",
                 "destination": "any", "service": "telnet", "port": 23},
            ],
            "vpn": [
                {"name": "site-legacy", "encryption": "3des", "ike_version": 1,
                 "mfa": False, "eol": True},
                {"name": "remote-workers", "encryption": "aes256",
                 "ike_version": 2, "mfa": True},
            ],
            "management": {"public": True, "exposed_interfaces": ["https", "ssh"]},
        },
        (
            Expect("misconfiguration", "Any-Any-Freigabe", H),
            Expect("remote_access", "RDP aus dem Internet erreichbar", H),
            Expect("remote_access", "SSH aus dem Internet erreichbar", H),
            Expect("exposed_service", "Sensibler Dienst offen ins Internet (MSSQL)", H),
            Expect("crypto_weakness", "VPN mit schwacher Kryptographie", H),
            Expect("misconfiguration", "VPN nutzt veraltetes IKEv1", M),
            Expect("remote_access", "VPN-Zugang ohne MFA", H),
            Expect("outdated_component", "Veraltetes/abgekündigtes VPN-Gateway", H),
            Expect("exposed_service", "Management-Interface aus dem Internet erreichbar", H),
            Expect("remote_access", "SSH-Fernzugang der Firewall", H),
        ),
        "Die internen Regeln und die deny-Regel dürfen NICHT zusätzlich anschlagen.",
    ),
    Scenario(
        "fw-hardened", "firewall", "hardened",
        "Öffentlicher Webserver + interner RDP + deny-all",
        {
            "device": "fw-hq",
            "rules": [
                {"name": "web-in", "action": "allow", "source": "0.0.0.0/0",
                 "destination": "10.0.0.10", "service": "https", "port": 443},
                {"name": "web-in-80", "action": "allow", "source": "any",
                 "destination": "10.0.0.10", "service": "http", "port": 80},
                {"name": "internal-rdp", "action": "allow", "source": "10.0.0.0/8",
                 "destination": "10.0.0.5", "service": "RDP", "port": 3389},
                {"name": "block-all", "action": "deny", "source": "any",
                 "destination": "any", "service": "any"},
            ],
            "vpn": [{"name": "vpn-modern", "encryption": "aes256",
                     "ike_version": 2, "mfa": True, "eol": False}],
            "management": {"public": False},
        },
        (),
        "Internet→443/80 auf einen Webserver ist legitim; interner RDP ist ok — null Funde.",
    ),
    Scenario(
        "fw-service-port", "firewall", "confuser",
        "Telnet aus dem Internet über Service-Namen (kein Port-Feld)",
        {
            "device": "fw-edge",
            "rules": [{"name": "telnet-in", "action": "permit", "source": "any",
                       "destination": "10.0.0.9", "service": "telnet"}],
        },
        (Expect("exposed_service", "Sensibler Dienst offen ins Internet (Telnet)", H),),
        "Der Zielport wird korrekt aus dem Service-Namen abgeleitet (telnet→23).",
    ),

    # ================================= AWS =================================
    Scenario(
        "aws-vuln", "aws", "vuln",
        "Root ohne MFA, Admin-Rolle offen, offener S3, offene SG",
        {
            "account_id": "123456789012",
            "root_account": {"mfa_enabled": False, "access_keys": 1},
            "password_policy": {"minimum_length": 8, "require_symbols": False,
                                "max_age_days": 0},
            "users": [{"name": "deploy-bot", "mfa_enabled": False,
                       "console_access": True,
                       "attached_policies": ["AdministratorAccess"],
                       "access_keys": [{"age_days": 430, "last_used_days": 300}]}],
            "roles": [{"name": "ci-deploy", "trust": "*",
                       "attached_policies": ["AdministratorAccess"]}],
            "s3_buckets": [{"name": "kunden-backups", "public": True,
                            "encryption": False}],
            "security_groups": [{"name": "db-sg",
                                 "open_to_world_ports": [3306, 22, 80]}],
        },
        (
            Expect("auth_weakness", "Root-Konto ohne MFA", K),
            Expect("access_control", "Root-Konto besitzt Access-Keys", K),
            Expect("auth_weakness", "Schwache IAM-Passwort-Policy (Mindestlänge 8)", M),
            Expect("auth_weakness", "ohne Sonderzeichen-Pflicht", N),
            Expect("auth_weakness", "IAM-Passwörter laufen nie ab", N),
            Expect("auth_weakness", "IAM-Konsolenzugriff ohne MFA: deploy-bot", H),
            Expect("access_control", "Überprivilegierter IAM-User (Admin): deploy-bot", H),
            Expect("access_control", "Alter Access-Key (430 Tage)", M),
            Expect("access_control", "Ungenutzter Access-Key: deploy-bot", N),
            Expect("access_control", "Admin-Rolle von beliebigem Prinzipal annehmbar", K),
            Expect("cloud_storage", "Öffentlicher S3-Bucket", H),
            Expect("misconfiguration", "S3-Bucket ohne Verschlüsselung", N),
            Expect("exposed_service", "auf Port 3306", H),
            Expect("exposed_service", "auf Port 22", H),
            Expect("exposed_service", "auf Port 80", M),
        ),
        "Fünfzehn AWS-Funde; Port 80 ist mittel, 22/3306 sind hoch (sensibel).",
    ),
    Scenario(
        "aws-hardened", "aws", "hardened",
        "Root mit MFA, ReadOnly-User, private Bucket, leere SG",
        {
            "account_id": "111111111111",
            "root_account": {"mfa_enabled": True, "access_keys": 0},
            "password_policy": {"minimum_length": 14, "require_symbols": True,
                                "max_age_days": 90},
            "users": [{"name": "ops", "mfa_enabled": True, "console_access": True,
                       "attached_policies": ["ReadOnlyAccess"],
                       "access_keys": [{"age_days": 30, "last_used_days": 5}]}],
            "roles": [{"name": "app", "trust": "arn:aws:iam::111:root",
                       "attached_policies": ["ReadOnlyAccess"]}],
            "s3_buckets": [{"name": "logs", "public": False, "encryption": True}],
            "security_groups": [{"name": "web-sg", "open_to_world_ports": []}],
        },
        (),
        "Sauberes Konto — null Funde.",
    ),
    Scenario(
        "aws-thresholds", "aws", "boundary",
        "Mindestlänge 14, Key exakt 180 Tage, User ohne Konsole",
        {
            "account_id": "222222222222",
            "password_policy": {"minimum_length": 14, "require_symbols": True,
                                "max_age_days": 90},
            "users": [{"name": "svc", "console_access": False,
                       "mfa_enabled": False,
                       "attached_policies": ["ReadOnlyAccess"],
                       "access_keys": [{"age_days": 180, "last_used_days": 180}]}],
        },
        (),
        "14 ist nicht <14; 180 Tage sind nicht >180; ohne Konsole zählt fehlende MFA nicht.",
    ),
    Scenario(
        "aws-unused-key", "aws", "confuser",
        "Access-Key ohne last_used-Feld",
        {
            "account_id": "333333333333",
            "users": [{"name": "leftover", "console_access": False,
                       "attached_policies": ["ReadOnlyAccess"],
                       "access_keys": [{"age_days": 10}]}],
        },
        (Expect("access_control", "Ungenutzter Access-Key: leftover", N),),
        "Ein fehlendes last_used-Feld gilt konservativ als 'ungenutzt'.",
    ),

    # ================================= AZURE =================================
    Scenario(
        "azure-vuln", "azure", "vuln",
        "Offener Blob, NSG-Ports, Legacy-VM, offener KV/SQL, zu viele Owner",
        {
            "subscription_id": "sub-1",
            "storage_accounts": [{"name": "sa1", "public_blob_access": True,
                                  "https_only": False, "encryption": False,
                                  "min_tls": "TLS1.0"}],
            "network_security_groups": [{"name": "nsg-db",
                                         "open_to_internet_ports": [3389, 1433, 80]}],
            "virtual_machines": [{"name": "vm-legacy", "public_ip": True,
                                  "disk_encryption": False,
                                  "os": "Windows Server 2012 R2"}],
            "key_vaults": [{"name": "kv1", "public_network_access": True,
                            "purge_protection": False}],
            "sql_servers": [{"name": "sql1", "public_access": True,
                             "tde_enabled": False}],
            "role_assignments": [
                {"principal": "a@x", "role": "Owner", "scope": "subscription"},
                {"principal": "b@x", "role": "Owner", "scope": "subscription"},
                {"principal": "c@x", "role": "Owner", "scope": "subscription"},
                {"principal": "d@x", "role": "Owner", "scope": "subscription"},
            ],
        },
        (
            Expect("cloud_storage", "Öffentlicher Blob-Zugriff", H),
            Expect("transport_security", "erlaubt unverschlüsselten Zugriff", M),
            Expect("transport_security", "schwacher TLS-Mindestversion", M),
            Expect("misconfiguration", "ohne Verschlüsselung im Ruhezustand", N),
            Expect("exposed_service", "auf Port 3389: nsg-db", H),
            Expect("exposed_service", "auf Port 1433: nsg-db", H),
            Expect("exposed_service", "auf Port 80: nsg-db", M),
            Expect("exposed_service", "VM direkt aus dem Internet erreichbar", M),
            Expect("outdated_component", "VM mit veraltetem Betriebssystem", H),
            Expect("misconfiguration", "VM ohne Datenträgerverschlüsselung", N),
            Expect("misconfiguration", "Key Vault öffentlich erreichbar", H),
            Expect("misconfiguration", "Key Vault ohne Purge-Protection", N),
            Expect("exposed_service", "Azure-SQL-Server öffentlich erreichbar", H),
            Expect("crypto_weakness", "Transparent Data Encryption", M),
            Expect("access_control", "Zu viele Subscription-Owner (4)", H),
        ),
        "Fünfzehn Azure-Funde über alle sechs Ressourcentypen.",
    ),
    Scenario(
        "azure-hardened", "azure", "hardened",
        "Alles privat/verschlüsselt, moderne OS, 3 Owner",
        {
            "subscription_id": "sub-2",
            "storage_accounts": [{"name": "sa", "public_blob_access": False,
                                  "https_only": True, "encryption": True,
                                  "min_tls": "TLS1.2"}],
            "network_security_groups": [{"name": "nsg",
                                         "open_to_internet_ports": []}],
            "virtual_machines": [{"name": "vm", "public_ip": False,
                                  "disk_encryption": True,
                                  "os": "Windows Server 2022"}],
            "key_vaults": [{"name": "kv", "public_network_access": False,
                            "purge_protection": True}],
            "sql_servers": [{"name": "sql", "public_access": False,
                             "tde_enabled": True}],
            "role_assignments": [
                {"role": "Owner", "scope": "subscription"},
                {"role": "Owner", "scope": "subscription"},
                {"role": "Owner", "scope": "subscription"},
            ],
        },
        (),
        "Server 2022 enthält nicht '2012'; min_tls 1.2 ist ok; 3 Owner sind erlaubt.",
    ),
    Scenario(
        "azure-rbac-scope", "azure", "confuser",
        "3 Subscription-Owner + weitere Owner auf niedrigerer Ebene",
        {
            "subscription_id": "sub-3",
            "storage_accounts": [{"name": "sa", "public_blob_access": False,
                                  "https_only": True, "encryption": True,
                                  "min_tls": "TLS1.2"}],
            "role_assignments": [
                {"role": "Owner", "scope": "subscription"},
                {"role": "Owner", "scope": "subscription"},
                {"role": "Owner", "scope": "subscription"},
                {"role": "Owner", "scope": "resourcegroup"},
                {"role": "Owner", "scope": "resourcegroup"},
                {"role": "Contributor", "scope": "subscription"},
                {"role": "Contributor", "scope": "subscription"},
            ],
        },
        (),
        "Nur Owner auf Subscription-Ebene zählen — RG-Owner und Contributor nicht.",
    ),

    # ============================ ACTIVE DIRECTORY ============================
    Scenario(
        "ad-vuln", "ad", "vuln",
        "Schwache Policy, altes krbtgt, überfüllte DA, riskante Konten",
        {
            "domain": "corp.kmu.de",
            "password_policy": {"min_length": 8, "complexity": False,
                                "lockout_threshold": 0, "max_age_days": 0,
                                "history_length": 3},
            "krbtgt_password_age_days": 1450,
            "privileged_groups": {"Domain Admins": _members("da", 9)},
            "users": [
                {"name": "svc-mssql", "enabled": True, "privileged": True,
                 "password_never_expires": True,
                 "service_principal_names": ["MSSQL/db01"]},
                {"name": "m.weber", "enabled": True, "privileged": False,
                 "last_logon_days": 410, "kerberos_preauth": False},
                {"name": "ex-admin", "enabled": False, "groups": ["Domain Admins"]},
                {"name": "a.fischer", "enabled": True, "admin_count": 1,
                 "groups": []},
            ],
        },
        (
            Expect("auth_weakness", "Passwort-Mindestlänge zu gering (8 < 12)", H),
            Expect("auth_weakness", "Passwort-Komplexität nicht erzwungen", H),
            Expect("auth_weakness", "Keine Account-Lockout-Policy", H),
            Expect("auth_weakness", "Passwörter laufen nie ab", M),
            Expect("auth_weakness", "Passwort-Historie zu kurz (3)", N),
            Expect("auth_weakness", "krbtgt-Passwort veraltet (1450 Tage)", H),
            Expect("access_control", "Zu viele privilegierte Konten in 'Domain Admins' (9)", H),
            Expect("auth_weakness", "Privilegiertes Konto mit nie ablaufendem Passwort: svc-mssql", H),
            Expect("auth_weakness", "Service-Konto mit SPN (Kerberoasting-Exposition): svc-mssql", M),
            Expect("access_control", "Aktives, aber ungenutztes Konto (seit 410 Tagen): m.weber", M),
            Expect("auth_weakness", "Kerberos-Pre-Auth deaktiviert (AS-REP-Roasting): m.weber", H),
            Expect("access_control", "Deaktiviertes Konto weiterhin in privilegierter Gruppe: ex-admin", M),
            Expect("access_control", "adminCount=1 ohne aktuelle Privilegien (AdminSDHolder-Rest): a.fischer", N),
        ),
        "Dreizehn AD-Funde; m.weber (nicht privilegiert) ergibt ein mittleres Stale-Konto.",
    ),
    Scenario(
        "ad-hardened", "ad", "hardened",
        "Starke Policy, junges krbtgt, schlanke DA, saubere Konten",
        {
            "domain": "corp.kmu.de",
            "password_policy": {"min_length": 14, "complexity": True,
                                "lockout_threshold": 5, "max_age_days": 90,
                                "history_length": 24},
            "krbtgt_password_age_days": 30,
            "privileged_groups": {"Domain Admins": _members("da", 5)},
            "users": [{"name": "j.klein", "enabled": True, "privileged": False,
                       "password_never_expires": False, "last_logon_days": 5,
                       "service_principal_names": [], "kerberos_preauth": True,
                       "admin_count": 0, "groups": ["Domain Users"]}],
        },
        (),
        "Alles über der Schwelle — null Funde.",
    ),
    Scenario(
        "ad-thresholds", "ad", "boundary",
        "Länge 12, Historie 5, krbtgt 180, 8 DA, Stale 90",
        {
            "domain": "corp.kmu.de",
            "password_policy": {"min_length": 12, "complexity": True,
                                "lockout_threshold": 5, "max_age_days": 90,
                                "history_length": 5},
            "krbtgt_password_age_days": 180,
            "privileged_groups": {"Domain Admins": _members("da", 8)},
            "users": [{"name": "p.stale", "enabled": True, "privileged": True,
                       "last_logon_days": 90, "kerberos_preauth": True,
                       "password_never_expires": False}],
        },
        (),
        "Länge 12 (nicht <12), Historie 5 (nicht <5), krbtgt 180 (nicht >180), 8 DA, 90 Tage — sauber.",
    ),

    # ============================== ENTRA-ID / M365 ==============================
    Scenario(
        "entra-vuln", "entra", "vuln",
        "Keine Defaults/CA/MFA, Legacy-Auth, überprivilegierte App",
        {
            "tenant": "kmu.onmicrosoft.com",
            "security_defaults_enabled": False, "legacy_auth_allowed": True,
            "conditional_access_policies": [],
            "roles": {"Global Administrator": _members("ga", 7)},
            "users": [
                {"upn": "admin@kmu.de", "enabled": True, "privileged": True,
                 "mfa_registered": False, "guest": False},
                {"upn": "gast@partner.de", "enabled": True, "privileged": False,
                 "mfa_registered": True, "guest": True, "last_sign_in_days": 240},
            ],
            "app_registrations": [{"name": "Alt-Sync-Tool", "admin_consent": True,
                                   "high_privilege_permissions": ["Directory.ReadWrite.All"]}],
            "sharing": {"anonymous_links_enabled": True},
        },
        (
            Expect("misconfiguration", "Weder Security Defaults noch Conditional Access aktiv", H),
            Expect("auth_weakness", "Keine MFA-Erzwingung", H),
            Expect("auth_weakness", "Legacy-Authentifizierung nicht blockiert", H),
            Expect("access_control", "Zu viele Konten in 'Global Administrator' (7)", H),
            Expect("auth_weakness", "Privilegiertes Konto ohne MFA: admin@kmu.de", K),
            Expect("access_control", "Inaktives Gastkonto (seit 240 Tagen)", M),
            Expect("access_control", "Überprivilegierte App-Registrierung: Alt-Sync-Tool", H),
            Expect("personal_data", "Anonyme Freigabelinks aktiviert", M),
        ),
        "Acht M365-Funde; das privilegierte Konto ohne MFA ist kritisch.",
    ),
    Scenario(
        "entra-hardened", "entra", "hardened",
        "Security Defaults an, kein Legacy, schlanke GA-Rolle",
        {
            "tenant": "kmu.onmicrosoft.com",
            "security_defaults_enabled": True, "legacy_auth_allowed": False,
            "conditional_access_policies": [],
            "roles": {"Global Administrator": _members("ga", 3)},
            "users": [{"upn": "user@kmu.de", "enabled": True,
                       "privileged": False, "mfa_registered": True,
                       "guest": False}],
            "app_registrations": [{"name": "App", "admin_consent": False,
                                   "high_privilege_permissions": []}],
            "sharing": {"anonymous_links_enabled": False},
        },
        (),
        "Security Defaults erzwingen MFA — null Funde.",
    ),
    Scenario(
        "entra-ca-covers", "entra", "confuser",
        "Keine Defaults + Legacy erlaubt, aber CA deckt alles ab",
        {
            "tenant": "kmu.onmicrosoft.com",
            "security_defaults_enabled": False, "legacy_auth_allowed": True,
            "conditional_access_policies": [
                {"name": "Baseline MFA", "state": "enabled",
                 "requires_mfa": True, "blocks_legacy_auth": True}],
            "roles": {"Global Administrator": _members("ga", 2)},
            "users": [{"upn": "u@kmu.de", "enabled": True, "privileged": False,
                       "mfa_registered": True, "guest": False}],
            "sharing": {"anonymous_links_enabled": False},
        },
        (),
        "Eine aktive CA-Richtlinie erzwingt MFA und blockt Legacy — sieht riskant aus, ist es nicht.",
    ),
    Scenario(
        "entra-ca-disabled", "entra", "confuser",
        "CA-Richtlinie vorhanden, aber deaktiviert",
        {
            "tenant": "kmu.onmicrosoft.com",
            "security_defaults_enabled": False, "legacy_auth_allowed": False,
            "conditional_access_policies": [
                {"name": "MFA (deaktiviert)", "state": "disabled",
                 "requires_mfa": True, "blocks_legacy_auth": True}],
            "roles": {}, "users": [], "sharing": {},
        },
        (
            Expect("misconfiguration", "Weder Security Defaults noch Conditional Access aktiv", H),
            Expect("auth_weakness", "Keine MFA-Erzwingung", H),
        ),
        "Eine DEAKTIVIERTE Richtlinie schützt nicht — sie darf keinen Schutz vortäuschen.",
    ),

    # =============================== EXCHANGE ===============================
    Scenario(
        "exchange-vuln", "exchange", "vuln",
        "Ungepatchter Build, ECP/OWA extern, TLS 1.0, fehlende Header",
        {
            "host": "mail.kmu.de", "product": "Exchange 2016",
            "build": "15.1.2044.4",
            "external_services": ["OWA", "ECP", "Autodiscover"],
            "tls": {"protocols": ["TLSv1.0", "TLSv1.2"]},
            "headers": {"Strict-Transport-Security": None,
                        "X-Content-Type-Options": None},
            "server_header": "Microsoft-IIS/10.0",
        },
        (
            Expect("outdated_component", "Veraltete Exchange-Version (Build 15.1.2044.4)", K),
            Expect("misconfiguration", "Exchange-ECP", H),
            Expect("exposed_service", "OWA extern erreichbar", M),
            Expect("misconfiguration", "Autodiscover extern erreichbar", N),
            Expect("transport_security", "Schwache TLS-Protokolle aktiv", H),
            Expect("misconfiguration", "Sicherheits-Header fehlt: HSTS", N),
            Expect("misconfiguration", "Sicherheits-Header fehlt: X-Frame-Options", N),
            Expect("misconfiguration", "Sicherheits-Header fehlt: X-Content-Type-Options", N),
            Expect("misconfiguration", "Server-Header gibt Produkt/Version preis", N),
        ),
        "Build 2044 < Richtwert 2507 (ProxyShell-Ära); ECP gehört nicht ins Internet.",
    ),
    Scenario(
        "exchange-hardened", "exchange", "hardened",
        "Gepatcht, keine externen Dienste, TLS 1.2/1.3, Header gesetzt",
        {
            "host": "mail.kmu.de", "product": "Exchange 2019",
            "build": "15.2.1544.4", "external_services": [],
            "tls": {"protocols": ["TLSv1.2", "TLSv1.3"]},
            "headers": {"Strict-Transport-Security": "max-age=31536000",
                        "X-Frame-Options": "DENY",
                        "X-Content-Type-Options": "nosniff"},
            "server_header": "",
        },
        (),
        "Build genau auf dem Richtwert, keine externen Dienste — null Funde.",
    ),
    Scenario(
        "exchange-eol", "exchange", "confuser",
        "End-of-Life-Version (Exchange 2010)",
        {
            "host": "old.kmu.de", "product": "Exchange 2010",
            "build": "14.3.496.0", "external_services": [],
            "tls": {"protocols": ["TLSv1.2"]},
            "headers": {"Strict-Transport-Security": "max-age=31536000",
                        "X-Frame-Options": "DENY",
                        "X-Content-Type-Options": "nosniff"},
            "server_header": "",
        },
        (Expect("outdated_component", "End-of-Life Exchange erkannt", K),),
        "Major-Version < 15 ist EOL — unabhängig vom dritten Build-Feld.",
    ),
    Scenario(
        "exchange-build-exact", "exchange", "boundary",
        "Build exakt auf dem Sicherheits-Richtwert",
        {
            "host": "mail.kmu.de", "product": "Exchange 2016",
            "build": "15.1.2507.0", "external_services": [],
            "tls": {"protocols": ["TLSv1.2", "TLSv1.3"]},
            "headers": {"Strict-Transport-Security": "max-age=31536000",
                        "X-Frame-Options": "DENY",
                        "X-Content-Type-Options": "nosniff"},
            "server_header": "",
        },
        (),
        "2507 ist nicht < 2507 — der Build gilt als gepatcht.",
    ),

    # ========== SCHMUTZIGE EXPORTE (Strings statt Bools/Ints) ==========
    # Reale Exporte aus CSV/YAML/PowerShell liefern "false" statt false und
    # "8" statt 8. Die Funde müssen trotzdem feuern — und ein String "false"
    # darf niemals als "wahr" fehlgedeutet werden (Fehlalarm).
    Scenario(
        "dns-dirty", "dns", "confuser",
        "DNS-Flags als Strings: \"false\" heißt aus, nicht an",
        {
            "domain": "kmu-dirty.de", "dnssec": "false",
            "caa": ["0 issue \"letsencrypt.org\""],
            "zone_transfer": "false", "wildcard": "0",
        },
        (Expect("dns_security", "DNSSEC nicht aktiv", M),),
        "dnssec=\"false\" muss als AUS gewertet werden (Fund); zone_transfer/"
        "wildcard=\"false\"/\"0\" sind truthy Strings und dürfen KEINE Fehlalarme werfen.",
    ),
    Scenario(
        "ad-dirty", "ad", "confuser",
        "AD-Policy als Zahl-Strings (PowerShell-Export)",
        {
            "domain": "corp.kmu.de",
            "password_policy": {"min_length": "8", "lockout_threshold": "0",
                                "max_age_days": "0", "history_length": "3",
                                "complexity": "false"},
            "krbtgt_password_age_days": "1450",
        },
        (
            Expect("auth_weakness", "Passwort-Mindestlänge zu gering (8 < 12)", H),
            Expect("auth_weakness", "Passwort-Komplexität nicht erzwungen", H),
            Expect("auth_weakness", "Keine Account-Lockout-Policy", H),
            Expect("auth_weakness", "Passwörter laufen nie ab", M),
            Expect("auth_weakness", "Passwort-Historie zu kurz (3)", N),
            Expect("auth_weakness", "krbtgt-Passwort veraltet (1450 Tage)", H),
        ),
        "\"8\" ist kein int — die schwache Policy muss trotzdem erkannt werden.",
    ),
    Scenario(
        "db-dirty", "database", "confuser",
        "DB-Flags als Wort-Strings (\"true\"/\"false\"/\"nein\")",
        {"databases": [{"engine": "redis", "port": "6379", "public": "true",
                        "auth_required": "false", "tls": "no",
                        "default_creds": "nein"}]},
        (
            Expect("exposed_service", "Datenbank öffentlich erreichbar", H),
            Expect("auth_weakness", "Datenbank ohne Authentifizierung", H),
            Expect("transport_security", "Unverschlüsselter Datenbank-Transport", M),
        ),
        "default_creds=\"nein\" darf NICHT als kritischer Default-Creds-Fund erscheinen.",
    ),
    Scenario(
        "backup-dirty", "backup", "confuser",
        "Backup-Fragebogen mit Wort-Antworten",
        {
            "organization": "Muster AG",
            "backups": [{"name": "nas", "copies": "1", "offsite": "nein",
                         "offline_or_immutable": "no", "encrypted": "false",
                         "restore_tested": "ja", "last_restore_test_days": "400",
                         "mfa_on_console": "off", "retention_days": "7"}],
        },
        (
            Expect("backup_resilience", "Höchstens eine Backup-Kopie", H),
            Expect("backup_resilience", "Keine Offsite-Kopie", H),
            Expect("backup_resilience", "Kein offline-/unveränderbares", H),
            Expect("backup_resilience", "Backup nicht verschlüsselt", M),
            Expect("backup_resilience", "Restore-Test überfällig (400 Tage)", H),
            Expect("backup_resilience", "Backup-Konsole ohne MFA", M),
            Expect("backup_resilience", "Zu kurze Backup-Aufbewahrung (7 Tage)", M),
        ),
        "restore_tested=\"ja\" heißt getestet — 'nie getestet' darf nicht feuern; "
        "der 400-Tage-Restore-Test ist trotzdem überfällig.",
    ),
    Scenario(
        "aws-dirty", "aws", "confuser",
        "AWS-Export mit String-Werten",
        {
            "account_id": "999", "root_account": {"mfa_enabled": "false",
                                                  "access_keys": "1"},
            "password_policy": {"minimum_length": "8"},
        },
        (
            Expect("auth_weakness", "Root-Konto ohne MFA", K),
            Expect("access_control", "Root-Konto besitzt Access-Keys", K),
            Expect("auth_weakness", "Schwache IAM-Passwort-Policy (Mindestlänge 8)", M),
        ),
        "mfa_enabled=\"false\" ist ein kritischer Fund — kein stiller Skip.",
    ),
    Scenario(
        "entra-dirty", "entra", "confuser",
        "M365-Export mit String-Bools",
        {
            "tenant": "kmu.onmicrosoft.com",
            "security_defaults_enabled": "false", "legacy_auth_allowed": "true",
            "conditional_access_policies": [],
            "users": [{"upn": "admin@kmu.de", "enabled": "true",
                       "privileged": "true", "mfa_registered": "false"}],
        },
        (
            Expect("misconfiguration", "Weder Security Defaults noch Conditional Access aktiv", H),
            Expect("auth_weakness", "Keine MFA-Erzwingung", H),
            Expect("auth_weakness", "Legacy-Authentifizierung nicht blockiert", H),
            Expect("auth_weakness", "Privilegiertes Konto ohne MFA: admin@kmu.de", K),
        ),
        "privileged=\"true\" + mfa_registered=\"false\" muss KRITISCH ergeben.",
    ),
    Scenario(
        "fw-dirty", "firewall", "confuser",
        "VPN-Flags als Strings, Management \"false\"",
        {
            "device": "fw",
            "vpn": [{"name": "v1", "encryption": "aes256", "ike_version": 2,
                     "mfa": "false", "eol": "true"}],
            "management": {"public": "false", "exposed_interfaces": ["ssh"]},
        },
        (
            Expect("remote_access", "VPN-Zugang ohne MFA", H),
            Expect("outdated_component", "Veraltetes/abgekündigtes VPN-Gateway", H),
        ),
        "public=\"false\" ist ein truthy String — die Management-Funde dürfen "
        "trotzdem NICHT feuern.",
    ),
    Scenario(
        "http-dirty", "http", "confuser",
        "Cookie-Flags als Strings",
        {
            "url": "https://dirty.kmu-web.de",
            "headers": {
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'",
                "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer", "Permissions-Policy": "x=()",
            },
            "cookies": [{"name": "sid", "secure": "false",
                         "httponly": "false", "samesite": "Lax"}],
        },
        (
            Expect("web_security", "Cookie ohne Secure-Flag", M),
            Expect("web_security", "Cookie ohne HttpOnly-Flag", M),
        ),
        "secure=\"false\" (String) muss wie false wirken — sonst blinde Flecken.",
    ),

    # ========== TLS: Werkzeug-Aliasse und EC-Schlüssel ==========
    Scenario(
        "tls-openssl-alias", "tls", "confuser",
        "OpenSSL-Schreibweisen: TLSv1, SSL3",
        {"endpoints": [{
            "host": "legacy.kmu-tls.de:443",
            "certificate": {"days_until_expiry": 200,
                            "signature_algorithm": "sha256WithRSAEncryption",
                            "key_type": "RSA", "key_bits": 2048},
            "protocols": ["TLSv1", "SSL3", "TLSv1.2"],
            "ciphers": ["ECDHE-RSA-AES256-GCM-SHA384"],
        }]},
        (
            Expect("transport_security", "(TLSv1)", M),
            Expect("transport_security", "(SSL3)", H),
        ),
        "OpenSSL nennt TLS 1.0 schlicht 'TLSv1' — genau das liefert der eigene "
        "Live-Kollektor; die Aliasse müssen erkannt werden.",
    ),
    Scenario(
        "tls-ec-bits", "tls", "boundary",
        "EC-Schlüssel: 224 Bit sauber, 192 Bit zu kurz",
        {"endpoints": [
            {"host": "ok.kmu-tls.de:443",
             "certificate": {"days_until_expiry": 200,
                             "signature_algorithm": "ecdsa-with-SHA256",
                             "key_type": "EC", "key_bits": 224},
             "protocols": ["TLSv1.3"], "ciphers": []},
            {"host": "weak.kmu-tls.de:443",
             "certificate": {"days_until_expiry": 200,
                             "signature_algorithm": "ecdsa-with-SHA256",
                             "key_type": "EC", "key_bits": 192},
             "protocols": ["TLSv1.3"], "ciphers": []},
        ]},
        (Expect("crypto_weakness", "zu kurzem Schlüssel (192 Bit)", H),),
        "EC hat eine eigene Schwelle (224): 192 ist zu kurz, 224 exakt sauber.",
    ),
    Scenario(
        "container-dirty", "container", "confuser",
        "Container-Flags als Strings",
        {"containers": [{"name": "web", "image": "nginx:1.25",
                         "privileged": "true", "host_network": "false",
                         "docker_socket_mounted": "no", "user": "1000",
                         "ports": []}]},
        (Expect("container_security", "Privilegierter Container", K),),
        "privileged=\"true\" ist kritisch; host_network/docker_socket=\"false\"/"
        "\"no\" dürfen keine Fehlalarme werfen.",
    ),
]
