-- ABSICHTLICH VERWUNDBAR - Test-Fixture (Mustermann GmbH Datenbank).
-- Nicht in Produktion verwenden.

CREATE TABLE mitarbeiter (
    id INT PRIMARY KEY,
    name VARCHAR(200),
    -- Personenbezogene / besondere Daten (DSGVO Art. 9)
    geburtsdatum DATE,
    iban VARCHAR(34),
    sozialversicherungsnummer VARCHAR(20),
    gesundheitsdaten TEXT,
    -- Passwoerter im Klartext gespeichert
    passwort VARCHAR(100)
);

-- Default-Admin mit schwachem Passwort
INSERT INTO benutzer (user, passwort) VALUES ('admin', 'admin');
