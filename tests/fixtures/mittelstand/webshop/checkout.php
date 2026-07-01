<?php
// ABSICHTLICH VERWUNDBAR - Test-Fixture (Mustermann GmbH Webshop).
// Nicht in Produktion verwenden.

// Fest kodierte DB-Zugangsdaten
$db_host = "127.0.0.1";
$db_user = "shop";
$db_password = "Sommer2023!";

$conn = new mysqli($db_host, $db_user, $db_password, "shop");

function get_order($order_id) {
    global $conn;
    // SQL-Injection durch String-Verkettung
    $sql = "SELECT * FROM bestellungen WHERE id = " . $order_id;
    return $conn->query($sql);
}

// Kundendaten werden im Klartext geloggt (DSGVO)
function log_customer($kunde) {
    // IBAN und Geburtsdatum landen im Log
    error_log("Bestellung: IBAN=" . $kunde['iban'] . " Geburtsdatum=" . $kunde['geburtsdatum']);
}
?>
