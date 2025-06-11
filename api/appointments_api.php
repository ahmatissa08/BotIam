<?php
// api/appointments_api.php

// En-têtes CORS pour permettre les requêtes depuis votre frontend
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, OPTIONS"); // Seules les méthodes POST et OPTIONS sont autorisées
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Content-Type: application/json"); // Indique que la réponse sera en JSON

// Gérer les requêtes OPTIONS (pré-vol pour CORS)
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

require_once 'config.php'; // Inclut les informations de connexion à la DB
require_once 'auth_helper.php'; // Inclut la fonction d'aide pour l'authentification (peut être étendue si besoin)

$response = ['success' => false, 'message' => ''];

// Vérifier l'authentification de l'utilisateur
// Pour l'instant, nous nous basons sur la présence d'un token dans le header.
// En production, une vérification JWT complète serait nécessaire.
$headers = getallheaders();
$auth_header = $headers['Authorization'] ?? '';
$token = str_replace('Bearer ', '', $auth_header);

// Si vous avez un mécanisme de session ou un JWT valide, vérifiez-le ici.
// Pour la démo, nous allons juste vérifier que le token n'est pas vide pour les utilisateurs non-admin
// Un token vide pourrait signifier un utilisateur non connecté ou une erreur.
if (empty($token)) {
    http_response_code(401); // Unauthorized
    echo json_encode(['success' => false, 'message' => 'Authentification requise.']);
    exit();
}

$method = $_SERVER['REQUEST_METHOD'];
$data = json_decode(file_get_contents('php://input'), true);
$action = $data['action'] ?? '';

if ($method === 'POST') {
    if ($action === 'createAppointment') {
        $user_id = $conn->real_escape_string($data['userId'] ?? '');
        $appointment_date = $conn->real_escape_string($data['date'] ?? '');
        $appointment_time = $conn->real_escape_string($data['time'] ?? '');
        $reason = $conn->real_escape_string($data['reason'] ?? '');
        $status = 'pending'; // Statut initial par défaut

        // Validation des données
        if (empty($user_id) || empty($appointment_date) || empty($appointment_time) || empty($reason)) {
            $response['message'] = 'Tous les champs obligatoires (utilisateur, date, heure, motif) sont requis.';
            http_response_code(400); // Bad Request
            echo json_encode($response);
            exit();
        }

        // Vérifier si l'utilisateur existe (sécurité supplémentaire)
        $stmt_user = $conn->prepare("SELECT id FROM users WHERE id = ?");
        $stmt_user->bind_param("i", $user_id);
        $stmt_user->execute();
        $result_user = $stmt_user->get_result();
        if ($result_user->num_rows === 0) {
            $response['message'] = 'Utilisateur non trouvé ou non autorisé.';
            http_response_code(403); // Forbidden
            echo json_encode($response);
            exit();
        }
        $stmt_user->close();

        $stmt = $conn->prepare("INSERT INTO appointments (user_id, appointment_date, appointment_time, reason, status) VALUES (?, ?, ?, ?, ?)");
        $stmt->bind_param("issss", $user_id, $appointment_date, $appointment_time, $reason, $status);

        if ($stmt->execute()) {
            $response['success'] = true;
            $response['message'] = 'Rendez-vous créé avec succès !';
            http_response_code(201); // Created
        } else {
            $response['message'] = 'Erreur lors de la création du rendez-vous: ' . $stmt->error;
            http_response_code(500); // Internal Server Error
        }
        $stmt->close();
    } else {
        $response['message'] = 'Action POST non valide.';
        http_response_code(400); // Bad Request
    }
} else {
    $response['message'] = 'Méthode de requête non supportée.';
    http_response_code(405); // Method Not Allowed
}

$conn->close();
echo json_encode($response);
?>
