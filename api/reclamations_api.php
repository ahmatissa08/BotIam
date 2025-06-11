<?php
// api/reclamations_api.php - Gère les réclamations (dépôt et gestion)

header('Content-Type: application/json');
require_once 'config.php'; // Inclut la connexion à la base de données
require_once 'auth_middleware.php'; // Inclut le middleware d'authentification

// Gère les requêtes OPTIONS (pré-vol pour CORS)
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Authentifie l'utilisateur avant de procéder
$user = authenticate_request();
// Log les informations de l'utilisateur authentifié. Crucial pour le débogage !
error_log("Reclamations API: User authenticated: " . print_r($user, true));

if (!$user) {
    error_log("Reclamations API: Authentication failed. No user found.");
    http_response_code(401); // Unauthorized
    echo json_encode(['success' => false, 'message' => 'Non autorisé. Veuillez vous connecter.']);
    exit();
}

// Vérification de la connexion à la base de données après l'authentification (pour s'assurer qu'elle est toujours valide)
if ($conn->connect_error) {
    error_log("Reclamations API: Database connection error AFTER authentication: " . $conn->connect_error);
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Erreur de connexion à la base de données: ' . $conn->connect_error]);
    exit();
}


// Récupération de la méthode de requête et des données d'entrée
$method = $_SERVER['REQUEST_METHOD'];
$input = json_decode(file_get_contents('php://input'), true);
error_log("Reclamations API: Request Method: " . $method);
error_log("Reclamations API: Raw Input data: " . file_get_contents('php://input')); // Log le contenu brut
error_log("Reclamations API: Decoded Input data: " . print_r($input, true));

if ($method === 'POST') {
    // Vérifier l'action spécifique pour la soumission de réclamation
    if (isset($input['action']) && $input['action'] === 'fileComplaint') {
        // S'assurer que le user_type est autorisé à déposer une réclamation
        // Note: auth_middleware devrait déjà avoir renvoyé 401 si l'utilisateur n'est pas bon.
        // Cette vérification est une sécurité supplémentaire si nécessaire, mais authenticate_request()
        // devrait déjà garantir un utilisateur valide ici.
        if (!isset($user['user_type']) || !in_array($user['user_type'], ['prospect', 'student', 'admin'])) {
            error_log("Reclamations API: Access denied for user type: " . ($user['user_type'] ?? 'UNDEFINED'));
            http_response_code(403); // Forbidden
            echo json_encode(['success' => false, 'message' => 'Accès refusé. Seuls les utilisateurs enregistrés peuvent déposer des réclamations.']);
            exit();
        }

        // Récupération sécurisée des données de l'utilisateur et de la réclamation
        $user_id = $user['id'] ?? null;
        $user_email = $user['email'] ?? null;
        $type = $conn->real_escape_string($input['type'] ?? '');
        $priority = $conn->real_escape_string($input['priority'] ?? 'medium');
        $description = $conn->real_escape_string($input['description'] ?? '');

        // Log les données extraites avant la validation
        error_log("Reclamations API: Extracted complaint data - User ID: {$user_id}, Email: {$user_email}, Type: {$type}, Priority: {$priority}, Description: {$description}");

        // Validation des données requises
        if (empty($type) || empty($description) || $user_id === null || $user_email === null) {
            error_log("Reclamations API: Missing required complaint data. Type: " . (empty($type) ? 'EMPTY' : 'OK') . ", Description: " . (empty($description) ? 'EMPTY' : 'OK') . ", User ID: " . ($user_id === null ? 'NULL' : 'OK') . ", User Email: " . ($user_email === null ? 'NULL' : 'OK'));
            http_response_code(400); // Bad Request
            echo json_encode(['success' => false, 'message' => 'Type, description, ID utilisateur et Email utilisateur sont requis.']);
            exit();
        }

        // --- ENREGISTREMENT DE RÉCLAMATION DANS LA BASE DE DONNÉES ---
        $stmt = $conn->prepare("INSERT INTO reclamations (user_id, user_email, type, priority, description) VALUES (?, ?, ?, ?, ?)");
        if ($stmt === false) {
            // Cette erreur est loggée si la requête préparée est invalide (ex: mauvaise colonne)
            error_log("Reclamations API: SQL Prepare Error: " . $conn->error);
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => 'Erreur de préparation de la requête SQL: ' . $conn->error]);
            exit();
        }
        // Log les types et valeurs bindés
        error_log("Reclamations API: bind_param types and values: i=" . $user_id . ", s=" . $user_email . ", s=" . $type . ", s=" . $priority . ", s=" . $description);
        $stmt->bind_param("issss", $user_id, $user_email, $type, $priority, $description);

        if ($stmt->execute()) {
            error_log("Reclamations API: Complaint registered successfully. New ID: " . $conn->insert_id);
            echo json_encode(['success' => true, 'message' => 'Réclamation enregistrée avec succès.', 'reclamationId' => $conn->insert_id]);
        } else {
            // Cette erreur est loggée si l'exécution échoue (ex: contraintes de DB violées)
            error_log("Reclamations API: SQL Execute Error: " . $stmt->error . " (errno: " . $stmt->errno . ")");
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => 'Erreur lors de l\'enregistrement de la réclamation: ' . $stmt->error]);
        }
        $stmt->close();

    } else {
        error_log("Reclamations API: Invalid POST action received: " . ($input['action'] ?? 'N/A'));
        http_response_code(400); // Bad Request
        echo json_encode(['success' => false, 'message' => 'Action POST non valide.']);
    }

} elseif ($method === 'GET') {
    // Action 'getReclamations' pour les administrateurs
    if (isset($_GET['action']) && $_GET['action'] === 'getReclamations') {
        if ($user['user_type'] !== 'admin') {
            error_log("Reclamations API: Access denied for 'getReclamations' to user type: " . ($user['user_type'] ?? 'UNDEFINED'));
            http_response_code(403); // Forbidden
            echo json_encode(['success' => false, 'message' => 'Accès refusé. Seuls les administrateurs peuvent voir les réclamations.']);
            exit();
        }

        $stmt = $conn->prepare("SELECT id, user_id, user_email, type, priority, status, description, resolution_details, created_at FROM reclamations ORDER BY created_at DESC");
        if ($stmt === false) {
            error_log("Reclamations API: SQL Prepare Error for getReclamations: " . $conn->error);
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => 'Erreur de préparation de la requête: ' . $conn->error]);
            exit();
        }
        $stmt->execute();
        $result = $stmt->get_result();
        $reclamations = [];
        while ($row = $result->fetch_assoc()) {
            $reclamations[] = $row;
        }
        error_log("Reclamations API: Successfully fetched " . count($reclamations) . " reclamations.");
        echo json_encode(['success' => true, 'reclamations' => $reclamations]);
        $stmt->close();

    } else {
        error_log("Reclamations API: Invalid GET action received: " . ($_GET['action'] ?? 'N/A'));
        http_response_code(400); // Bad Request
        echo json_encode(['success' => false, 'message' => 'Action GET non valide.']);
    }

} elseif ($method === 'PUT') {
    // Action 'updateStatus' pour les administrateurs
    if (isset($input['action']) && $input['action'] === 'updateStatus') {
        if ($user['user_type'] !== 'admin') {
            error_log("Reclamations API: Access denied for 'updateStatus' to user type: " . ($user['user_type'] ?? 'UNDEFINED'));
            http_response_code(403); // Forbidden
            echo json_encode(['success' => false, 'message' => 'Accès refusé. Seuls les administrateurs peuvent mettre à jour le statut des réclamations.']);
            exit();
        }

        $id = $input['id'] ?? null;
        $status = $conn->real_escape_string($input['status'] ?? '');

        if (empty($id) || empty($status)) {
            error_log("Reclamations API: Missing ID or Status for update. ID: " . ($id ?? 'NULL') . ", Status: " . (empty($status) ? 'EMPTY' : $status));
            http_response_code(400); // Bad Request
            echo json_encode(['success' => false, 'message' => 'ID ou statut manquant.']);
            exit();
        }

        $stmt = $conn->prepare("UPDATE reclamations SET status = ? WHERE id = ?");
        if ($stmt === false) {
            error_log("Reclamations API: SQL Prepare Error for updateStatus: " . $conn->error);
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => 'Erreur de préparation de la requête: ' . $conn->error]);
            exit();
        }
        $stmt->bind_param("si", $status, $id);
        error_log("Reclamations API: bind_param for updateStatus: s=" . $status . ", i=" . $id);

        if ($stmt->execute()) {
            if ($stmt->affected_rows > 0) {
                error_log("Reclamations API: Reclamation ID {$id} status updated to {$status}.");
                echo json_encode(['success' => true, 'message' => 'Statut de la réclamation mis à jour avec succès.']);
            } else {
                error_log("Reclamations API: Reclamation ID {$id} not found or no change in status.");
                http_response_code(404);
                echo json_encode(['success' => false, 'message' => 'Réclamation non trouvée ou aucun changement de statut.']);
            }
        } else {
            error_log("Reclamations API: SQL Execute Error for updateStatus: " . $stmt->error . " (errno: " . $stmt->errno . ")");
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => 'Erreur lors de la mise à jour du statut: ' . $stmt->error]);
        }
        $stmt->close();

    } else {
        error_log("Reclamations API: Invalid PUT action received: " . ($input['action'] ?? 'N/A'));
        http_response_code(400); // Bad Request
        echo json_encode(['success' => false, 'message' => 'Action PUT non valide.']);
    }
} else {
    error_log("Reclamations API: Unsupported request method: " . $method);
    http_response_code(405); // Method Not Allowed
    echo json_encode(['success' => false, 'message' => 'Méthode de requête non supportée.']);
}

$conn->close();
?>
