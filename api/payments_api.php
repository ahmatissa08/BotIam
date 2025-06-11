<?php
// api/payments_api.php - Gère le suivi des paiements des étudiants

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
    if (isset($_GET['action']) && $_GET['action'] === 'getPayments') {
        $student_id = $user['id']; // L'ID de l'étudiant connecté

        // --- SIMULATION DE DONNÉES DE PAIEMENTS ---
        // En production, vous feriez une requête à votre base de données:
        // $stmt = $conn->prepare("SELECT description, amount, status, date, due_date FROM payments WHERE student_id = ? ORDER BY date DESC");
        // $stmt->bind_param("i", $student_id);
        // $stmt->execute();
        // $result = $stmt->get_result();
        // $payments = [];
        // while ($row = $result->fetch_assoc()) { $payments[] = $row; }
        // echo json_encode(['success' => true, 'payments' => $payments]);

        $mock_payments_data = [
            ['description' => 'Frais de scolarité S1', 'amount' => '2500€', 'status' => 'Payé', 'date' => '2024-09-15', 'dueDate' => null],
            ['description' => 'Frais de scolarité S2', 'amount' => '2500€', 'status' => 'À payer', 'date' => null, 'dueDate' => '2025-02-01'],
            ['description' => 'Cotisation BDE', 'amount' => '50€', 'status' => 'Payé', 'date' => '2024-10-01', 'dueDate' => null]
        ];

        echo json_encode(['success' => true, 'payments' => $mock_payments_data, 'message' => 'Données de paiements simulées.']);

    } else {
        echo json_encode(['success' => false, 'message' => 'Action GET non valide.']);
    }
} else {
    echo json_encode(['success' => false, 'message' => 'Méthode de requête non supportée.']);
}

$conn->close();
?>
