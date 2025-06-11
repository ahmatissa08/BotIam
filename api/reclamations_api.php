    <?php
    // api/reclamations_api.php

    header("Access-Control-Allow-Origin: *");
    header("Access-Control-Allow-Methods: GET, PUT, OPTIONS");
    header("Access-Control-Allow-Headers: Content-Type, Authorization");
    header("Content-Type: application/json");

    if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
        http_response_code(200);
        exit();
    }

    require_once 'config.php';
    require_once 'auth_helper.php';

    $response = ['success' => false, 'message' => ''];

    $admin_user = verify_admin_access($conn);
    if (!$admin_user) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Accès non autorisé. Seuls les administrateurs peuvent effectuer cette action.']);
        exit();
    }

    $method = $_SERVER['REQUEST_METHOD'];
    $data = json_decode(file_get_contents('php://input'), true);
    $action = $_GET['action'] ?? ($data['action'] ?? '');

    switch ($method) {
        case 'GET':
            if ($action === 'getReclamations') {
                $stmt = $conn->prepare("SELECT r.id, r.user_id, u.email AS user_email, r.type, r.priority, r.description, r.status, r.resolution_details, r.created_at, r.updated_at FROM reclamations r LEFT JOIN users u ON r.user_id = u.id ORDER BY r.created_at DESC");
                $stmt->execute();
                $result = $stmt->get_result();
                $reclamations = [];
                while ($row = $result->fetch_assoc()) {
                    $reclamations[] = $row;
                }
                $response['success'] = true;
                $response['message'] = 'Réclamations récupérées avec succès.';
                $response['reclamations'] = $reclamations;
            } elseif ($action === 'getReclamationById' && isset($_GET['id'])) {
                $id = $conn->real_escape_string($_GET['id']);
                $stmt = $conn->prepare("SELECT r.id, r.user_id, u.email AS user_email, r.type, r.priority, r.description, r.status, r.resolution_details, r.created_at, r.updated_at FROM reclamations r LEFT JOIN users u ON r.user_id = u.id WHERE r.id = ?");
                $stmt->bind_param("i", $id);
                $stmt->execute();
                $result = $stmt->get_result();
                if ($result->num_rows === 1) {
                    $response['success'] = true;
                    $response['message'] = 'Réclamation trouvée.';
                    $response['reclamation'] = $result->fetch_assoc();
                } else {
                    $response['message'] = 'Réclamation non trouvée.';
                }
            } else {
                $response['message'] = 'Action GET non valide.';
            }
            break;

        case 'PUT':
            if ($action === 'updateStatus' && isset($data['id'], $data['status'])) {
                $id = $conn->real_escape_string($data['id']);
                $status = $conn->real_escape_string($data['status']);

                $stmt = $conn->prepare("UPDATE reclamations SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?");
                $stmt->bind_param("si", $status, $id);

                if ($stmt->execute()) {
                    $response['success'] = true;
                    $response['message'] = 'Statut de la réclamation mis à jour avec succès.';
                } else {
                    $response['message'] = 'Erreur lors de la mise à jour du statut: ' . $stmt->error;
                }
                $stmt->close();
            } elseif ($action === 'updateResolution' && isset($data['id'], $data['resolution_details'])) {
                $id = $conn->real_escape_string($data['id']);
                $resolution_details = $conn->real_escape_string($data['resolution_details']);

                $stmt = $conn->prepare("UPDATE reclamations SET resolution_details = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?");
                $stmt->bind_param("si", $resolution_details, $id);

                if ($stmt->execute()) {
                    $response['success'] = true;
                    $response['message'] = 'Détails de résolution mis à jour avec succès.';
                } else {
                    $response['message'] = 'Erreur lors de la mise à jour des détails de résolution: ' . $stmt->error;
                }
                $stmt->close();
            } else {
                $response['message'] = 'Action PUT non valide ou données manquantes.';
            }
            break;

        default:
            $response['message'] = 'Méthode de requête non supportée.';
            break;
    }

    $conn->close();
    echo json_encode($response);
    ?>
    