<?php
// api/chat.php

header('Content-Type: application/json');
require_once 'config.php';
require_once 'auth_middleware.php'; // Inclure le middleware d'authentification centralisé

// Gère les requêtes OPTIONS (pré-vol pour CORS)
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Vérification de la connexion à la base de données
if ($conn->connect_error) {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Erreur de connexion à la base de données: ' . $conn->connect_error]);
    exit();
}

// Authentifier l'utilisateur via le middleware centralisé.
// Toutes les requêtes à cette API doivent être authentifiées, qu'elles soient pour un admin, étudiant ou prospect.
$user = authenticate_request();
if (!$user) {
    // Si authenticate_request() retourne null, l'utilisateur n'est pas authentifié.
    http_response_code(401); // Unauthorized
    echo json_encode(['success' => false, 'message' => 'Non autorisé. Veuillez vous connecter ou votre token est invalide.']);
    exit();
}

// Récupérer la méthode de requête et les données d'entrée
$method = $_SERVER['REQUEST_METHOD'];
$input = json_decode(file_get_contents('php://input'), true);

// Récupérer l'action de l'URL pour les requêtes GET, ou du corps pour POST/PUT/DELETE
$action = $_GET['action'] ?? ($input['action'] ?? '');

// L'utilisateur est maintenant authentifié et ses données sont disponibles dans $user['id'], $user['user_type'], etc.

switch ($action) {
    case 'createConversation':
        if ($method === 'POST') {
            // L'ID utilisateur est déjà dans $user après l'authentification
            $userId = $user['id'];
            $title = $input['title'] ?? null; // Le titre peut être optionnel au début

            // Créer une nouvelle conversation
            $stmt = $conn->prepare("INSERT INTO conversations (user_id, title) VALUES (?, ?)");
            $stmt->bind_param("is", $userId, $title);

            if ($stmt->execute()) {
                $conversationId = $conn->insert_id;
                echo json_encode(['success' => true, 'message' => 'Nouvelle conversation créée.', 'conversationId' => $conversationId]);
            } else {
                http_response_code(500);
                echo json_encode(['success' => false, 'message' => 'Erreur lors de la création de la conversation: ' . $conn->error]);
            }
            $stmt->close();
        } else {
            http_response_code(405); // Method Not Allowed
            echo json_encode(['success' => false, 'message' => 'Méthode non autorisée pour cette action.']);
        }
        break;

    case 'sendMessage':
        if ($method === 'POST') {
            $userId = $user['id']; // ID de l'utilisateur authentifié
            $messageText = $input['message'] ?? '';
            $sender = $input['sender'] ?? ''; // 'user' ou 'bot'
            $conversationId = $input['conversationId'] ?? null; // Peut être null si c'est le premier message d'une nouvelle conversation

            if (empty($messageText) || empty($sender)) {
                http_response_code(400); // Bad Request
                echo json_encode(['success' => false, 'message' => 'Message et expéditeur sont requis.']);
                exit();
            }

            // Si aucune conversation_id n'est fournie, ou si c'est une nouvelle conversation (ex: premier message du chat),
            // créez une nouvelle conversation.
            if (empty($conversationId)) {
                // Créer une nouvelle conversation
                $stmt = $conn->prepare("INSERT INTO conversations (user_id) VALUES (?)");
                $stmt->bind_param("i", $userId);
                if ($stmt->execute()) {
                    $conversationId = $conn->insert_id;
                    $stmt->close(); // Fermer le statement précédent

                    // Tenter de définir un titre basé sur le premier message de l'utilisateur
                    if ($sender === 'user' && strlen($messageText) > 0) {
                        $truncatedTitle = substr($messageText, 0, 100); // Tronquer le titre
                        $updateStmt = $conn->prepare("UPDATE conversations SET title = ? WHERE id = ?");
                        $updateStmt->bind_param("si", $truncatedTitle, $conversationId);
                        $updateStmt->execute();
                        $updateStmt->close();
                    }

                } else {
                    http_response_code(500);
                    echo json_encode(['success' => false, 'message' => 'Erreur lors de la création de la conversation pour le message: ' . $conn->error]);
                    exit();
                }
            } else {
                // Vérifier si la conversation appartient bien à l'utilisateur
                $stmt = $conn->prepare("SELECT id FROM conversations WHERE id = ? AND user_id = ?");
                $stmt->bind_param("ii", $conversationId, $userId);
                $stmt->execute();
                $result = $stmt->get_result();
                if ($result->num_rows === 0) {
                    http_response_code(403); // Forbidden
                    echo json_encode(['success' => false, 'message' => 'Accès refusé à cette conversation ou conversation non trouvée.']);
                    exit();
                }
                $stmt->close();
            }


            // Enregistrer le message dans la base de données
            $stmt = $conn->prepare("INSERT INTO messages (user_id, conversation_id, message_text, sender, timestamp) VALUES (?, ?, ?, ?, NOW())");
            $stmt->bind_param("iiss", $userId, $conversationId, $messageText, $sender);

            if ($stmt->execute()) {
                echo json_encode(['success' => true, 'message' => 'Message enregistré.', 'conversationId' => $conversationId]);
            } else {
                http_response_code(500);
                echo json_encode(['success' => false, 'message' => 'Erreur lors de l\'enregistrement du message: ' . $conn->error]);
            }
            $stmt->close();
        } else {
            http_response_code(405);
            echo json_encode(['success' => false, 'message' => 'Méthode non autorisée.']);
        }
        break;

    case 'getChatHistory':
        if ($method === 'GET') {
            $userId = $user['id']; // ID de l'utilisateur authentifié
            $conversationId = $_GET['conversationId'] ?? null;

            if (empty($conversationId)) {
                http_response_code(400);
                echo json_encode(['success' => false, 'message' => 'ID de conversation requis.']);
                exit();
            }

            // Vérifier si la conversation appartient bien à l'utilisateur
            $stmt = $conn->prepare("SELECT id FROM conversations WHERE id = ? AND user_id = ?");
            $stmt->bind_param("ii", $conversationId, $userId);
            $stmt->execute();
            $result = $stmt->get_result();
            if ($result->num_rows === 0) {
                http_response_code(403); // Forbidden
                echo json_encode(['success' => false, 'message' => 'Accès refusé à cette conversation ou conversation non trouvée.']);
                exit();
            }
            $stmt->close();

            $stmt = $conn->prepare("SELECT message_text, sender, timestamp FROM messages WHERE conversation_id = ? ORDER BY timestamp ASC");
            $stmt->bind_param("i", $conversationId);
            $stmt->execute();
            $result = $stmt->get_result();
            $history = [];
            while ($row = $result->fetch_assoc()) {
                $history[] = $row;
            }
            echo json_encode(['success' => true, 'history' => $history]);
            $stmt->close();
        } else {
            http_response_code(405);
            echo json_encode(['success' => false, 'message' => 'Méthode non autorisée.']);
        }
        break;

    case 'getConversations':
        if ($method === 'GET') {
            $userId = $user['id']; // ID de l'utilisateur authentifié

            $stmt = $conn->prepare("SELECT id, start_time, title FROM conversations WHERE user_id = ? ORDER BY start_time DESC");
            $stmt->bind_param("i", $userId);
            $stmt->execute();
            $result = $stmt->get_result();
            $conversations = [];
            while ($row = $result->fetch_assoc()) {
                // Si le titre est null, utiliser le début du premier message comme titre
                if (empty($row['title'])) {
                    $firstMessageStmt = $conn->prepare("SELECT message_text FROM messages WHERE conversation_id = ? ORDER BY timestamp ASC LIMIT 1");
                    $firstMessageStmt->bind_param("i", $row['id']);
                    $firstMessageStmt->execute();
                    $firstMessageResult = $firstMessageStmt->get_result();
                    if ($firstMessageRow = $firstMessageResult->fetch_assoc()) {
                        $row['title'] = substr($firstMessageRow['message_text'], 0, 50) . '...'; // Tronquer le titre
                    } else {
                        $row['title'] = 'Nouvelle conversation';
                    }
                    $firstMessageStmt->close();
                }
                $conversations[] = $row;
            }
            echo json_encode(['success' => true, 'conversations' => $conversations]);
            $stmt->close();
        } else {
            http_response_code(405);
            echo json_encode(['success' => false, 'message' => 'Méthode non autorisée.']);
        }
        break;

    case 'deleteConversation':
        if ($method === 'DELETE') {
            $userId = $user['id'];
            $conversationId = $input['conversationId'] ?? null;

            if (empty($conversationId)) {
                http_response_code(400);
                echo json_encode(['success' => false, 'message' => 'ID de conversation requis.']);
                exit();
            }

            // Vérifier que la conversation appartient à l'utilisateur avant de la supprimer
            $stmt = $conn->prepare("DELETE FROM conversations WHERE id = ? AND user_id = ?");
            $stmt->bind_param("ii", $conversationId, $userId);

            if ($stmt->execute()) {
                if ($stmt->affected_rows > 0) {
                    echo json_encode(['success' => true, 'message' => 'Conversation supprimée avec succès.']);
                } else {
                    http_response_code(404);
                    echo json_encode(['success' => false, 'message' => 'Conversation non trouvée ou non autorisée.']);
                }
            } else {
                http_response_code(500);
                echo json_encode(['success' => false, 'message' => 'Erreur lors de la suppression de la conversation: ' . $conn->error]);
            }
            $stmt->close();
        } else {
            http_response_code(405);
            echo json_encode(['success' => false, 'message' => 'Méthode non autorisée.']);
        }
        break;

    case 'renameConversation':
        if ($method === 'PUT') {
            $userId = $user['id'];
            $conversationId = $input['conversationId'] ?? null;
            $newTitle = $input['newTitle'] ?? '';

            if (empty($conversationId) || empty($newTitle)) {
                http_response_code(400);
                echo json_encode(['success' => false, 'message' => 'ID de conversation et nouveau titre requis.']);
                exit();
            }

            // Vérifier que la conversation appartient à l'utilisateur avant de la renommer
            $stmt = $conn->prepare("UPDATE conversations SET title = ? WHERE id = ? AND user_id = ?");
            $stmt->bind_param("sii", $newTitle, $conversationId, $userId);

            if ($stmt->execute()) {
                if ($stmt->affected_rows > 0) {
                    echo json_encode(['success' => true, 'message' => 'Titre de conversation mis à jour.']);
                } else {
                    http_response_code(404);
                    echo json_encode(['success' => false, 'message' => 'Conversation non trouvée ou non autorisée.']);
                }
            } else {
                http_response_code(500);
                echo json_encode(['success' => false, 'message' => 'Erreur lors de la mise à jour du titre: ' . $conn->error]);
            }
            $stmt->close();
        } else {
            http_response_code(405);
            echo json_encode(['success' => false, 'message' => 'Méthode non autorisée.']);
        }
        break;

    default:
        http_response_code(400); // Bad Request
        echo json_encode(['success' => false, 'message' => 'Action non spécifiée ou inconnue.']);
        break;
}

$conn->close();
?>
