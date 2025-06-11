<?php
// api/contact_api.php - Gère l'envoi de messages à l'administration

require_once 'config.php'; // Inclut la connexion à la base de données
require_once 'auth_middleware.php'; // Inclut le middleware d'authentification pour la démo

header('Content-Type: application/json'); // Indique que la réponse sera en JSON

// Gère les requêtes OPTIONS (pré-vol pour CORS)
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Authentifie l'utilisateur avant de procéder
$user = authenticate_request();
if (!$user) {
    echo json_encode(['success' => false, 'message' => 'Non autorisé. Veuillez vous connecter.']);
    exit();
}

// Assurez-vous que seul un étudiant ou un prospect peut accéder à cette API
if ($user['user_type'] !== 'student' && $user['user_type'] !== 'prospect' && $user['user_type'] !== 'admin') {
    echo json_encode(['success' => false, 'message' => 'Accès refusé. Cette fonctionnalité est réservée aux étudiants, prospects ou administrateurs.']);
    exit();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = json_decode(file_get_contents('php://input'), true);

    if (isset($data['action']) && $data['action'] === 'sendMessageToAdmin') {
        $sender_id = $user['id'];
        $subject = $conn->real_escape_string($data['subject'] ?? '');
        $message_text = $conn->real_escape_string($data['message'] ?? '');
        $sender_email = $conn->real_escape_string($user['email'] ?? 'unknown@example.com'); // Utilise l'email de l'utilisateur connecté

        if (empty($subject) || empty($message_text)) {
            echo json_encode(['success' => false, 'message' => 'Le sujet et le message sont requis.']);
            exit();
        }

        // --- SIMULATION D'ENREGISTREMENT OU D'ENVOI D'EMAIL À L'ADMINISTRATION ---
        // En production, vous enregistreriez ceci dans une table 'admin_messages'
        // ou enverriez un email réel aux administrateurs.
        // Exemple d'insertion DB:
        // $stmt = $conn->prepare("INSERT INTO admin_messages (user_id, user_email, subject, message_text) VALUES (?, ?, ?, ?)");
        // $stmt->bind_param("isss", $sender_id, $sender_email, $subject, $message_text);
        // if ($stmt->execute()) {
        //     echo json_encode(['success' => true, 'message' => 'Message envoyé à l\'administration.']);
        // } else {
        //     echo json_encode(['success' => false, 'message' => 'Erreur lors de l\'envoi du message: ' . $stmt->error]);
        // }
        // $stmt->close();

        echo json_encode(['success' => true, 'message' => 'Message à l\'administration simulé. Sujet: "' . $subject . '", Envoyé par: ' . $sender_email]);

    } else {
        echo json_encode(['success' => false, 'message' => 'Action POST non valide.']);
    }
} else {
    echo json_encode(['success' => false, 'message' => 'Méthode de requête non supportée.']);
}

$conn->close();
?>
