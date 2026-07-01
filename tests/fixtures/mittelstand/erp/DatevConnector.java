// ABSICHTLICH VERWUNDBAR - Test-Fixture (Mustermann GmbH DATEV/ERP-Anbindung).
// Nicht in Produktion verwenden.
package de.mustermann.erp;

public class DatevConnector {
    // Fest kodierte Zugangsdaten zur Buchhaltung
    private static final String DATEV_USER = "datev-service";
    private static final String DATEV_PASSWORT = "Buchhaltung#2022";

    // Personenbezogene Daten (Lohnbuchhaltung): Steuernummer, Sozialversicherungsnummer
    public String exportPayroll(String personalausweis, String iban) {
        // Uebertragung ohne Verschluesselung
        String url = "http://datev-gateway.intern/export?verify=false";
        return connect(url, DATEV_USER, DATEV_PASSWORT);
    }

    private String connect(String url, String u, String p) {
        return url;
    }
}
