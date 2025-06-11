<?php
// api/schedule_api.php - Gère la récupération de l'emploi du temps des étudiants

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

// Assurez-vous que seul un étudiant peut accéder à cette API
if ($user['user_type'] !== 'student' && $user['user_type'] !== 'admin') {
    echo json_encode(['success' => false, 'message' => 'Accès refusé. Cette fonctionnalité est réservée aux étudiants ou administrateurs.']);
    exit();
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    if (isset($_GET['action']) && $_GET['action'] === 'getSchedule') {
        $student_id = $user['id']; // L'ID de l'étudiant connecté

        // --- SIMULATION DE DONNÉES D'EMPLOI DU TEMPS ---
        // En production, vous feriez une requête à votre base de données:
        // $stmt = $conn->prepare("SELECT day, time_slot, subject, room FROM schedule WHERE student_id = ? ORDER BY FIELD(day, 'Lundi', 'Mardi', 'Mercredi', 'Jeudi', 'Vendredi'), time_slot");
        // $stmt->bind_param("i", $student_id);
        // $stmt->execute();
        // $result = $stmt->get_result();
        // $schedule = [];
        // while ($row = $result->fetch_assoc()) { $schedule[] = $row; }
        // echo json_encode(['success' => true, 'schedule' => $schedule]);

        $mock_schedule_data = [
            ['day' => 'Lundi', 'time' => '09:00-12:00', 'subject' => 'Programmation Avancée', 'room' => 'Salle A101'],
            ['day' => 'Mardi', 'time' => '14:00-17:00', 'subject' => 'Base de Données II', 'room' => 'Amphi B'],
            ['day' => 'Mercredi', 'time' => '09:00-12:00', 'subject' => 'Réseaux et Sécurité', 'room' => 'Labo Info 3']
        ];

        echo json_encode(['success' => true, 'schedule' => $mock_schedule_data, 'message' => 'Données d\'emploi du temps simulées.']);

    } else {
        echo json_encode(['success' => false, 'message' => 'Action GET non valide.']);
    }
} else {
    echo json_encode(['success' => false, 'message' => 'Méthode de requête non supportée.']);
}

$conn->close();
?>
