"""Erstkontakt-E-Mail-Vorlage fuer die Akquise (personalisiert, defensiv, ehrlich).

Baut aus den Ergebnissen des Live-E-Mail-Checks eine hoefliche, sachliche
Erstkontakt-Mail. Kein Alarmismus, kein Druck: der oeffentlich sichtbare Befund
wird nüchtern benannt, der Nutzen erklaert und ein unverbindlicher, kostenloser
Kurz-Check angeboten.

WICHTIG (rechtlicher Hinweis, siehe auch Runner): Unaufgeforderte Werbe-E-Mails
an Unternehmen sind in Deutschland nach UWG heikel. Diese Vorlage ist bewusst
kein Massen-Spam, sondern fuer einen individuellen, sachbezogenen Erstkontakt
gedacht (idealerweise mit vorheriger Verbindung, z. B. Telefonat, Empfehlung,
Messe, LinkedIn).
"""

from __future__ import annotations

from typing import Any

from .findings import Finding, Severity


def _plain(finding: Finding) -> str:
    """Uebersetzt ein Finding in einen sachlichen Ein-Zeiler."""
    t = finding.title
    if "Kein SPF" in t:
        return "Es ist kein SPF-Eintrag hinterlegt - Absender lassen sich kaum pruefen."
    if "SPF erlaubt beliebige" in t or "beliebige Absender" in t:
        return "Ihr SPF-Eintrag erlaubt praktisch beliebige Absender."
    if "SPF ohne" in t:
        return "Ihr SPF-Eintrag hat keinen klaren Abschluss (-all/~all)."
    if "Kein DMARC" in t:
        return "Es ist kein DMARC-Eintrag hinterlegt - Spoofing wird nicht erkannt."
    if "p=none" in t:
        return ("Ihr DMARC steht nur auf 'p=none' (Beobachtung) - gefaelschte Mails "
                "werden nicht abgewiesen.")
    if "ohne Auswertungs-Reports" in t or "kein rua" in t:
        return "Ihr DMARC sammelt keine Auswertungs-Reports (kein rua)."
    if "Kein DKIM" in t:
        return "Es wurde keine DKIM-Signatur gefunden - Mails sind nicht signiert."
    if "zu schwach" in t:
        return "Ihr DKIM-Schluessel ist zu kurz und gilt als unsicher."
    if "nicht mehr zeitgemaess" in t:
        return "Ihr DKIM-Schluessel ist nach heutigem Stand zu kurz."
    return finding.title


def build_outreach_email(domain: str, findings: list[Finding], *,
                         sender_name: str = "",
                         contact_email: str = "kontakt@specter-security.de",
                         recipient_salutation: str = "Sehr geehrte Damen und Herren"
                         ) -> dict[str, Any]:
    """Erzeugt Betreff und Text einer Erstkontakt-Mail (personalisiert)."""
    signature = sender_name.strip() or "Ihr Specter-Team"
    top = sorted(findings, key=lambda f: -int(f.severity))[:3]

    if top:
        subject = f"Kurzer Hinweis zur E-Mail-Sicherheit von {domain}"
        intro = (
            f"{recipient_salutation},\n\n"
            f"ich beschaeftige mich mit IT-Sicherheit fuer den Mittelstand und habe "
            f"mir die oeffentlich sichtbaren E-Mail-Einstellungen Ihrer Domain "
            f"{domain} angesehen (SPF, DKIM, DMARC - reine oeffentliche "
            f"DNS-Eintraege, kein Zugriff auf Ihre Systeme). Dabei ist mir "
            f"aufgefallen:\n"
        )
        bullets = "\n".join(f"  - {_plain(f)}" for f in top)
        why = (
            "\n\nDiese Einstellungen entscheiden, ob Kriminelle in Ihrem Namen "
            "E-Mails faelschen koennen (z. B. gefaelschte Rechnungen oder "
            "Chef-Betrug). Die gute Nachricht: das laesst sich meist schnell und "
            "guenstig beheben.\n"
        )
        offer = (
            "\nWenn Sie moechten, schicke ich Ihnen unverbindlich und kostenlos "
            "eine kurze, verstaendliche Auswertung mit konkreten Empfehlungen - "
            "oder wir telefonieren 10 Minuten.\n"
        )
    else:
        subject = f"E-Mail-Sicherheit von {domain}: kurzer Check"
        intro = (
            f"{recipient_salutation},\n\n"
            f"ich beschaeftige mich mit IT-Sicherheit fuer den Mittelstand. Die "
            f"oeffentlich sichtbaren E-Mail-Einstellungen Ihrer Domain {domain} "
            f"(SPF, DKIM, DMARC) machen bereits einen guten Eindruck.\n"
        )
        bullets = ""
        why = (
            "\nGerade weil die Grundlagen stimmen, lohnt sich oft ein Blick auf "
            "die naechsten Ebenen (z. B. Firewall-Regeln, Backups gegen "
            "Ransomware, veraltete Software).\n"
        )
        offer = (
            "\nWenn Sie moechten, biete ich Ihnen unverbindlich einen kurzen, "
            "kostenlosen Erst-Check an - verstaendlich aufbereitet, ohne Zugriff "
            "auf Ihre Systeme.\n"
        )

    closing = (
        f"\nMit freundlichen Gruessen\n{signature}\n{contact_email}\n\n"
        "PS: Ich pruefe rein defensiv und werte nur bereitgestellte bzw. "
        "oeffentliche Daten aus - keine Angriffe, kein Eingriff in Ihre Systeme. "
        "Falls kein Interesse besteht, geben Sie mir kurz Bescheid, dann melde "
        "ich mich nicht erneut."
    )
    body = intro + bullets + why + offer + closing
    return {"subject": subject, "body": body}
