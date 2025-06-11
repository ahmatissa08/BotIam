<?php
// api/resources_api.php - Gère la récupération des ressources pédagogiques

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
    if (isset($_GET['action']) && $_GET['action'] === 'getResources') {
        $student_id = $user['id']; // L'ID de l'étudiant connecté (utilisable pour des ressources spécifiques)

        // --- SIMULATION DE DONNÉES DE RESSOURCES PÉDAGOGIQUES ---
        // En production, vous feriez une requête à votre base de données:
        // $stmt = $conn->prepare("SELECT title, url, type FROM resources WHERE course_id IN (SELECT course_id FROM student_courses WHERE student_id = ?) ORDER BY title");
        // $stmt->bind_param("i", $student_id);
        // $stmt->execute();
        // $result = $stmt->get_result();
        // $resources = [];
        // while ($row = $result->fetch_assoc()) { $resources[] = $row; }
        // echo json_encode(['success' => true, 'resources' => $resources]);

        $mock_resources_data = [
            ['title' => 'Cours Programmation Python', 'url' => '#', 'type' => 'PDF'],
            ['title' => 'Exercices SQL', 'url' => '#', 'type' => 'Document'],
            ['title' => 'Vidéos Algorithmique', 'url' => '#', 'type' => 'Lien externe']
        ];

        echo json_encode(['success' => true, 'resources' => $mock_resources_data, 'message' => 'Données de ressources simulées.']);

    } else {
        echo json_encode(['success' => false, 'message' => 'Action GET non valide.']);
    }
} else {
    echo json_encode(['success' => false, 'message' => 'Méthode de requête non supportée.']);
}

$conn->close();
?>
