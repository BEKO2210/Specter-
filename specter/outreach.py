"""Erstkontakt-E-Mail-Vorlage für die Akquise (personalisiert, defensiv, ehrlich).

Baut aus den Ergebnissen des Live-E-Mail-Checks eine hoefliche, sachliche
Erstkontakt-Mail. Kein Alarmismus, kein Druck: der öffentlich sichtbare Befund
wird nüchtern benannt, der Nutzen erklärt und ein unverbindlicher, kostenloser
Kurz-Check angeboten.

WICHTIG (rechtlicher Hinweis, siehe auch Runner): Unaufgeforderte Werbe-E-Mails
an Unternehmen sind in Deutschland nach UWG heikel. Diese Vorlage ist bewusst
kein Massen-Spam, sondern für einen individuellen, sachbezogenen Erstkontakt
gedacht (idealerweise mit vorheriger Verbindung, z. B. Telefonat, Empfehlung,
Messe, LinkedIn).
"""

from __future__ import annotations

from typing import Any

from .findings import Finding, Severity


def _plain(finding: Finding) -> str:
    """Übersetzt ein Finding in einen sachlichen Ein-Zeiler."""
    t = finding.title
    if "Kein SPF" in t:
        return "Es ist kein SPF-Eintrag hinterlegt - Absender lassen sich kaum prüfen."
    if "SPF erlaubt beliebige" in t or "beliebige Absender" in t:
        return "Ihr SPF-Eintrag erlaubt praktisch beliebige Absender."
    if "SPF ohne" in t:
        return "Ihr SPF-Eintrag hat keinen klaren Abschluss (-all/~all)."
    if "Kein DMARC" in t:
        return "Es ist kein DMARC-Eintrag hinterlegt - Spoofing wird nicht erkannt."
    if "p=none" in t:
        return ("Ihr DMARC steht nur auf 'p=none' (Beobachtung) - gefälschte Mails "
                "werden nicht abgewiesen.")
    if "ohne Auswertungs-Reports" in t or "kein rua" in t:
        return "Ihr DMARC sammelt keine Auswertungs-Reports (kein rua)."
    if "Kein DKIM" in t:
        return "Es wurde keine DKIM-Signatur gefunden - Mails sind nicht signiert."
    if "zu schwach" in t:
        return "Ihr DKIM-Schlüssel ist zu kurz und gilt als unsicher."
    if "nicht mehr zeitgemäß" in t:
        return "Ihr DKIM-Schlüssel ist nach heutigem Stand zu kurz."
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
            f"ich beschaeftige mich mit IT-Sicherheit für den Mittelstand und habe "
            f"mir die öffentlich sichtbaren E-Mail-Einstellungen Ihrer Domain "
            f"{domain} angesehen (SPF, DKIM, DMARC - reine öffentliche "
            f"DNS-Einträge, kein Zugriff auf Ihre Systeme). Dabei ist mir "
            f"aufgefallen:\n"
        )
        bullets = "\n".join(f"  - {_plain(f)}" for f in top)
        why = (
            "\n\nDiese Einstellungen entscheiden, ob Kriminelle in Ihrem Namen "
            "E-Mails fälschen können (z. B. gefälschte Rechnungen oder "
            "Chef-Betrug). Die gute Nachricht: das lässt sich meist schnell und "
            "guenstig beheben.\n"
        )
        offer = (
            "\nWenn Sie moechten, schicke ich Ihnen unverbindlich und kostenlos "
            "eine kurze, verständliche Auswertung mit konkreten Empfehlungen - "
            "oder wir telefonieren 10 Minuten.\n"
        )
    else:
        subject = f"E-Mail-Sicherheit von {domain}: kurzer Check"
        intro = (
            f"{recipient_salutation},\n\n"
            f"ich beschaeftige mich mit IT-Sicherheit für den Mittelstand. Die "
            f"öffentlich sichtbaren E-Mail-Einstellungen Ihrer Domain {domain} "
            f"(SPF, DKIM, DMARC) machen bereits einen guten Eindruck.\n"
        )
        bullets = ""
        why = (
            "\nGerade weil die Grundlagen stimmen, lohnt sich oft ein Blick auf "
            "die nächsten Ebenen (z. B. Firewall-Regeln, Backups gegen "
            "Ransomware, veraltete Software).\n"
        )
        offer = (
            "\nWenn Sie moechten, biete ich Ihnen unverbindlich einen kurzen, "
            "kostenlosen Erst-Check an - verständlich aufbereitet, ohne Zugriff "
            "auf Ihre Systeme.\n"
        )

    closing = (
        f"\nMit freundlichen Gruessen\n{signature}\n{contact_email}\n\n"
        "PS: Ich prüfe rein defensiv und werte nur bereitgestellte bzw. "
        "öffentliche Daten aus - keine Angriffe, kein Eingriff in Ihre Systeme. "
        "Falls kein Interesse besteht, geben Sie mir kurz Bescheid, dann melde "
        "ich mich nicht erneut."
    )
    body = intro + bullets + why + offer + closing
    return {"subject": subject, "body": body}
