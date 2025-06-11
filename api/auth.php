<?php
// api/auth.php (Revised for demo token system)

header('Content-Type: application/json');
require_once 'config.php'; // Inclut la connexion $conn

$input = json_decode(file_get_contents('php://input'), true);
$action = $input['action'] ?? '';

switch ($action) {
    case 'register':
        $name = $input['name'] ?? '';
        $email = $input['email'] ?? '';
        $phone = $input['phone'] ?? '';
        $type = $input['type'] ?? 'prospect';
        $password = $input['password'] ?? '';

        if (empty($name) || empty($email) || empty($password)) {
            echo json_encode(['success' => false, 'message' => 'Nom, email et mot de passe sont requis.']);
            exit();
        }

        // --- DANGER: POUR LA DÉMO SEULEMENT ---
        // En production, stockez un hachage sécurisé du mot de passe (e.g., password_hash($password, PASSWORD_DEFAULT);)
        // et utilisez un JWT comme token.
        // Ici, le mot de passe en clair est stocké comme "token" pour une comparaison simple.
        $demo_token_for_comparison = $password; // Stocke le mot de passe en clair comme token de démo

        // Vérifier si l'email existe déjà
        $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            echo json_encode(['success' => false, 'message' => 'Cet email est déjà enregistré.']);
        } else {
            $stmt->close();
            $stmt = $conn->prepare("INSERT INTO users (name, email, phone, user_type, password_hash) VALUES (?, ?, ?, ?, ?)");
            $stmt->bind_param("sssss", $name, $email, $phone, $type, $demo_token_for_comparison); // Utilisez $demo_token_for_comparison ici

            if ($stmt->execute()) {
                echo json_encode(['success' => true, 'message' => 'Inscription réussie.']);
            } else {
                echo json_encode(['success' => false, 'message' => 'Erreur lors de l\'inscription: ' . $conn->error]);
            }
        }
        $stmt->close();
        break;

    case 'login':
        $email = $input['email'] ?? '';
        $password = $input['password'] ?? '';

        if (empty($email) || empty($password)) {
            echo json_encode(['success' => false, 'message' => 'Email et mot de passe sont requis.']);
            exit();
        }

        $stmt = $conn->prepare("SELECT id, name, email, user_type, password_hash FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 1) {
            $user = $result->fetch_assoc();
            // --- DANGER: POUR LA DÉMO SEULEMENT ---
            // En production, utilisez password_verify($password, $user['password_hash']).
            // Ici, nous comparons le mot de passe entré directement avec le "token" (mot de passe en clair) stocké.
            if ($password === $user['password_hash']) { // Comparez directement
                // Retourne le "token" (le mot de passe en clair pour la démo) pour que le frontend l'utilise
                echo json_encode([
                    'success' => true,
                    'message' => 'Connexion réussie.',
                    'user' => [
                        'id' => $user['id'],
                        'name' => $user['name'],
                        'email' => $user['email'],
                        'type' => $user['user_type'],
                        'token' => $user['password_hash'] // Le token est le mot de passe en clair pour la démo
                    ]
                ]);
            } else {
                echo json_encode(['success' => false, 'message' => 'Mot de passe incorrect.']);
            }
        } else {
            echo json_encode(['success' => false, 'message' => 'Email non trouvé.']);
        }
        $stmt->close();
        break;

    default:
        echo json_encode(['success' => false, 'message' => 'Action non spécifiée.']);
        break;
}

$conn->close();
?>
