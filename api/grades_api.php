<?php
// api/grades_api.php - Gère la récupération des notes des étudiants

require_once 'config.php'; // Inclut la connexion à la base de données
require_once 'auth_middleware.php'; // Inclut le middleware d'authentification pour la démo

header('Content-Type: application/json'); // Indique que la réponse sera en JSON

// Gère les requêtes OPTIONS (pré-vol pour CORS)
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Authentifie l'utilisateur avant de procéder
$user = authenticate_request(); // Vérifie si l'utilisateur est authentifié et récupère ses données
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
    if (isset($_GET['action']) && $_GET['action'] === 'getGrades') {
        // En production: récupérer le userId de l'utilisateur authentifié
        // Pour la démo, utilisons l'ID de l'utilisateur authentifié par auth_middleware.php
        $student_id = $user['id']; // L'ID de l'étudiant connecté

        // --- SIMULATION DE DONNÉES DE NOTES ---
        // En production, vous feriez une requête à votre base de données:
        // $stmt = $conn->prepare("SELECT course, grade, semester FROM grades WHERE student_id = ? ORDER BY semester, course");
        // $stmt->bind_param("i", $student_id);
        // $stmt->execute();
        // $result = $stmt->get_result();
        // $grades = [];
        // while ($row = $result->fetch_assoc()) { $grades[] = $row; }
        // echo json_encode(['success' => true, 'grades' => $grades]);

        $mock_grades_data = [
            // Ces données sont statiques et ne dépendent pas de l'ID de l'étudiant dans cette démo
            // Pour des données spécifiques à l'utilisateur, vous devrez lier $student_id à votre DB
            ['course' => 'Mathématiques', 'grade' => '16/20', 'semester' => 'S1'],
            ['course' => 'Programmation', 'grade' => '14/20', 'semester' => 'S1'],
            ['course' => 'Base de Données', 'grade' => '17/20', 'semester' => 'S1'],
            ['course' => 'Réseaux', 'grade' => '13/20', 'semester' => 'S2'],
            ['course' => 'Projet Fin d\'Études', 'grade' => 'N/A', 'semester' => 'S2']
        ];

        echo json_encode(['success' => true, 'grades' => $mock_grades_data, 'message' => 'Données de notes simulées.']);

    } else {
        echo json_encode(['success' => false, 'message' => 'Action GET non valide.']);
    }
} else {
    echo json_encode(['success' => false, 'message' => 'Méthode de requête non supportée.']);
}

$conn->close();
?>
