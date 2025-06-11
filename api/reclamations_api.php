<?php
// api/reclamations_api.php - Gère les réclamations (dépôt et gestion)

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

// Pour simplifier la démonstration, nous n'avons pas de table 'reclamations' dans 'database-integration-guide'.
// En production, vous auriez une table comme ceci:
/*
CREATE TABLE reclamations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    user_email VARCHAR(255) NOT NULL,
    type VARCHAR(100) NOT NULL,
    priority ENUM('low', 'medium', 'high', 'urgent') DEFAULT 'medium',
    description TEXT NOT NULL,
    status ENUM('open', 'in_progress', 'resolved', 'closed') DEFAULT 'open',
    resolution_details TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
*/

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = json_decode(file_get_contents('php://input'), true);

    if (isset($data['action']) && $data['action'] === 'fileComplaint') {
        // S'assurer que seul un utilisateur (prospect, étudiant ou admin) peut déposer une réclamation
        if (!in_array($user['user_type'], ['prospect', 'student', 'admin'])) {
            echo json_encode(['success' => false, 'message' => 'Accès refusé. Seuls les utilisateurs enregistrés peuvent déposer des réclamations.']);
            exit();
        }

        $user_id = $user['id'];
        $user_email = $user['email'];
        $type = $conn->real_escape_string($data['type'] ?? '');
        $priority = $conn->real_escape_string($data['priority'] ?? 'medium');
        $description = $conn->real_escape_string($data['description'] ?? '');

        if (empty($type) || empty($description)) {
            echo json_encode(['success' => false, 'message' => 'Type et description de la réclamation sont requis.']);
            exit();
        }

        // --- SIMULATION D'ENREGISTREMENT DE RÉCLAMATION ---
        // En production, vous inséreriez ceci dans votre table `reclamations`
        // $stmt = $conn->prepare("INSERT INTO reclamations (user_id, user_email, type, priority, description) VALUES (?, ?, ?, ?, ?)");
        // $stmt->bind_param("issss", $user_id, $user_email, $type, $priority, $description);
        // if ($stmt->execute()) {
        //     echo json_encode(['success' => true, 'message' => 'Réclamation enregistrée avec succès.']);
        // } else {
        //     echo json_encode(['success' => false, 'message' => 'Erreur lors de l\'enregistrement de la réclamation: ' . $stmt->error]);
        // }
        // $stmt->close();

        echo json_encode(['success' => true, 'message' => 'Réclamation simulée déposée par ' . $user_email . ' (Type: ' . $type . ', Priorité: ' . $priority . ').']);

    } else {
        echo json_encode(['success' => false, 'message' => 'Action POST non valide.']);
    }

} elseif ($_SERVER['REQUEST_METHOD'] === 'GET') {
    if (isset($_GET['action']) && $_GET['action'] === 'getReclamations') {
        // Seuls les administrateurs peuvent voir toutes les réclamations
        if ($user['user_type'] !== 'admin') {
            echo json_encode(['success' => false, 'message' => 'Accès refusé. Seuls les administrateurs peuvent voir les réclamations.']);
            exit();
        }

        // --- SIMULATION DE RÉCUPÉRATION DE RÉCLAMATIONS ---
        // En production, vous récupéreriez les données de votre table `reclamations`
        // $result = $conn->query("SELECT id, user_id, user_email, type, priority, status, description, resolution_details FROM reclamations ORDER BY created_at DESC");
        // $reclamations = [];
        // if ($result) { while ($row = $result->fetch_assoc()) { $reclamations[] = $row; }}
        // echo json_encode(['success' => true, 'reclamations' => $reclamations]);

        $mock_reclamations_data = [
            ['id' => 1, 'user_id' => 1, 'user_email' => 'student1@example.com', 'type' => 'Problème de paiement', 'priority' => 'high', 'status' => 'open', 'description' => 'Facture du S1 non visible.', 'resolution_details' => null],
            ['id' => 2, 'user_id' => 2, 'user_email' => 'prospect1@example.com', 'type' => 'Information formation', 'priority' => 'medium', 'status' => 'in_progress', 'description' => 'Détails du programme Ingénierie. ', 'resolution_details' => null],
            ['id' => 3, 'user_id' => 1, 'user_email' => 'student1@example.com', 'type' => 'Problème académique', 'priority' => 'low', 'status' => 'resolved', 'description' => 'Note de Math incorrecte.', 'resolution_details' => 'Note corrigée après vérification.']
        ];
        echo json_encode(['success' => true, 'reclamations' => $mock_reclamations_data, 'message' => 'Données de réclamations simulées.']);

    } else {
        echo json_encode(['success' => false, 'message' => 'Action GET non valide.']);
    }

} elseif ($_SERVER['REQUEST_METHOD'] === 'PUT') {
    $data = json_decode(file_get_contents('php://input'), true);

    if (isset($data['action']) && $data['action'] === 'updateStatus') {
        // Seuls les administrateurs peuvent modifier le statut d'une réclamation
        if ($user['user_type'] !== 'admin') {
            echo json_encode(['success' => false, 'message' => 'Accès refusé. Seuls les administrateurs peuvent mettre à jour le statut des réclamations.']);
            exit();
        }

        $id = $conn->real_escape_string($data['id'] ?? '');
        $status = $conn->real_escape_string($data['status'] ?? '');

        if (empty($id) || empty($status)) {
            echo json_encode(['success' => false, 'message' => 'ID ou statut manquant.']);
            exit();
        }

        // --- SIMULATION DE MISE À JOUR DE STATUT ---
        // En production, vous mettriez à jour le statut dans votre table `reclamations`
        // $stmt = $conn->prepare("UPDATE reclamations SET status = ? WHERE id = ?");
        // $stmt->bind_param("si", $status, $id);
        // if ($stmt->execute()) {
        //     echo json_encode(['success' => true, 'message' => 'Statut de la réclamation mis à jour avec succès.']);
        // } else {
        //     echo json_encode(['success' => false, 'message' => 'Erreur lors de la mise à jour du statut: ' . $stmt->error]);
        // }
        // $stmt->close();

        echo json_encode(['success' => true, 'message' => 'Statut de la réclamation #' . $id . ' mis à jour à "' . $status . '" (simulé).']);

    } else {
        echo json_encode(['success' => false, 'message' => 'Action PUT non valide.']);
    }
} else {
    echo json_encode(['success' => false, 'message' => 'Méthode de requête non supportée.']);
}

$conn->close();
?>
