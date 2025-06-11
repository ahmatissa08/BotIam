<?php
// api/config.php
// Configuration de la base de données
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'root');     // À remplacer par votre utilisateur de base de données
define('DB_PASSWORD', '');         // À remplacer par votre mot de passe
define('DB_NAME', 'chatbot_iam'); // À remplacer par le nom de votre base de données

// Connexion à la base de données
$conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

// Vérifier la connexion
if ($conn->connect_error) {
    // Ne pas utiliser die() en production pour des raisons de sécurité
    // Gérer l'erreur proprement, par exemple en logguant et en affichant un message générique
    error_log("Connection to DB failed: " . $conn->connect_error);
    http_response_code(500); // Internal Server Error
    echo json_encode(['success' => false, 'message' => 'Erreur de connexion à la base de données.']);
    exit();
}

// Définir l'encodage des caractères
$conn->set_charset("utf8mb4");

// --- IMPORTANT POUR LA DÉMO : SIMULATION DE L'AUTHENTIFICATION ADMIN ---
// En production, cette logique devrait être basée sur un JWT sécurisé et des sessions.
// Pour cette démo, un token simple sera utilisé pour valider l'accès admin.
define('ADMIN_DEMO_TOKEN', 'ADMIN_IAM_SECURE_TOKEN_2025'); // Token fixe pour l'admin de la démo

// api/auth_helper.php
// Fonction d'aide pour vérifier l'accès administrateur

?>