<?php
// api/users_api.php

// En-têtes CORS pour permettre les requêtes depuis votre frontend
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Content-Type: application/json"); // Indique que la réponse sera en JSON

// Gérer les requêtes OPTIONS (pré-vol pour CORS)
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

require_once 'config.php'; // Inclut les informations de connexion à la DB
require_once 'auth_helper.php'; // Inclut la fonction d'aide pour l'authentification

$response = ['success' => false, 'message' => ''];

// Vérifier l'accès administrateur pour toutes les actions de ce fichier
$admin_user = verify_admin_access($conn); // Passer la connexion pour une vérification potentielle en DB
if (!$admin_user) {
    http_response_code(403); // Forbidden
    echo json_encode(['success' => false, 'message' => 'Accès non autorisé. Seuls les administrateurs peuvent effectuer cette action.']);
    exit();
}

$method = $_SERVER['REQUEST_METHOD'];
$data = json_decode(file_get_contents('php://input'), true);
$action = $_GET['action'] ?? ($data['action'] ?? '');

switch ($method) {
    case 'GET':
        if ($action === 'getUsers') {
            $stmt = $conn->prepare("SELECT id, name, email, phone, user_type, created_at FROM users");
            $stmt->execute();
            $result = $stmt->get_result();
            $users = [];
            while ($row = $result->fetch_assoc()) {
                $users[] = $row;
            }
            $response['success'] = true;
            $response['message'] = 'Utilisateurs récupérés avec succès.';
            $response['users'] = $users;
        } elseif ($action === 'getUserById' && isset($_GET['id'])) {
            $id = $conn->real_escape_string($_GET['id']);
            $stmt = $conn->prepare("SELECT id, name, email, phone, user_type FROM users WHERE id = ?");
            $stmt->bind_param("i", $id);
            $stmt->execute();
            $result = $stmt->get_result();
            if ($result->num_rows === 1) {
                $response['success'] = true;
                $response['message'] = 'Utilisateur trouvé.';
                $response['user'] = $result->fetch_assoc();
            } else {
                $response['message'] = 'Utilisateur non trouvé.';
            }
        } else {
            $response['message'] = 'Action GET non valide.';
        }
        break;

    case 'POST':
        if ($action === 'addUser') {
            $name = $conn->real_escape_string($data['name'] ?? '');
            $email = $conn->real_escape_string($data['email'] ?? '');
            $phone = $conn->real_escape_string($data['phone'] ?? '');
            $user_type = $conn->real_escape_string($data['user_type'] ?? '');
            $password = $data['password'] ?? '';

            if (empty($name) || empty($email) || empty($user_type) || empty($password)) {
                $response['message'] = 'Tous les champs obligatoires sont requis.';
                break;
            }

            $password_hash = password_hash($password, PASSWORD_DEFAULT);

            $stmt = $conn->prepare("INSERT INTO users (name, email, password_hash, phone, user_type) VALUES (?, ?, ?, ?, ?)");
            $stmt->bind_param("sssss", $name, $email, $password_hash, $phone, $user_type);

            if ($stmt->execute()) {
                $response['success'] = true;
                $response['message'] = 'Utilisateur ajouté avec succès.';
            } else {
                if ($conn->errno == 1062) { // Duplicate entry for UNIQUE email
                    $response['message'] = 'Cet email est déjà utilisé.';
                } else {
                    $response['message'] = 'Erreur lors de l\'ajout de l\'utilisateur: ' . $stmt->error;
                }
            }
            $stmt->close();
        } else {
            $response['message'] = 'Action POST non valide.';
        }
        break;

    case 'PUT':
        if ($action === 'updateUser' && isset($data['id'])) {
            $id = $conn->real_escape_string($data['id']);
            $name = $conn->real_escape_string($data['name'] ?? '');
            $email = $conn->real_escape_string($data['email'] ?? '');
            $phone = $conn->real_escape_string($data['phone'] ?? '');
            $user_type = $conn->real_escape_string($data['user_type'] ?? '');
            $password = $data['password'] ?? null; // Mot de passe optionnel pour la mise à jour

            if (empty($name) || empty($email) || empty($user_type)) {
                $response['message'] = 'Les champs nom, email et type sont requis.';
                break;
            }

            $query_parts = [];
            $params = [];
            $types = "";

            $query_parts[] = "name = ?";
            $params[] = $name;
            $types .= "s";

            $query_parts[] = "email = ?";
            $params[] = $email;
            $types .= "s";

            $query_parts[] = "phone = ?";
            $params[] = $phone;
            $types .= "s";

            $query_parts[] = "user_type = ?";
            $params[] = $user_type;
            $types .= "s";

            if ($password) {
                $password_hash = password_hash($password, PASSWORD_DEFAULT);
                $query_parts[] = "password_hash = ?";
                $params[] = $password_hash;
                $types .= "s";
            }

            $query_string = implode(", ", $query_parts);
            $sql = "UPDATE users SET " . $query_string . " WHERE id = ?";
            $params[] = $id;
            $types .= "i";

            $stmt = $conn->prepare($sql);
            // Utilisation de call_user_func_array pour bind_param car le nombre de paramètres est dynamique
            call_user_func_array([$stmt, 'bind_param'], array_merge([$types], $params));

            if ($stmt->execute()) {
                $response['success'] = true;
                $response['message'] = 'Utilisateur mis à jour avec succès.';
            } else {
                if ($conn->errno == 1062) {
                    $response['message'] = 'Cet email est déjà utilisé par un autre utilisateur.';
                } else {
                    $response['message'] = 'Erreur lors de la mise à jour de l\'utilisateur: ' . $stmt->error;
                }
            }
            $stmt->close();
        } else {
            $response['message'] = 'Action PUT non valide ou ID manquant.';
        }
        break;

    case 'DELETE':
        if ($action === 'deleteUser' && isset($data['id'])) {
            $id = $conn->real_escape_string($data['id']);
            $stmt = $conn->prepare("DELETE FROM users WHERE id = ?");
            $stmt->bind_param("i", $id);

            if ($stmt->execute()) {
                $response['success'] = true;
                $response['message'] = 'Utilisateur supprimé avec succès.';
            } else {
                $response['message'] = 'Erreur lors de la suppression de l\'utilisateur: ' . $stmt->error;
            }
            $stmt->close();
        } else {
            $response['message'] = 'Action DELETE non valide ou ID manquant.';
        }
        break;

    default:
        $response['message'] = 'Méthode de requête non supportée.';
        break;
}

$conn->close();
echo json_encode($response);
?>
