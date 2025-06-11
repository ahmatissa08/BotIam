    <?php
    // api/stats_api.php

    header("Access-Control-Allow-Origin: *");
    header("Access-Control-Allow-Methods: GET, OPTIONS");
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
    $action = $_GET['action'] ?? '';

    if ($method === 'GET' && $action === 'getStats') {
        $stats = [];

        // Total Utilisateurs
        $stmt = $conn->prepare("SELECT COUNT(id) AS totalUsers FROM users");
        $stmt->execute();
        $result = $stmt->get_result();
        $stats['totalUsers'] = $result->fetch_assoc()['totalUsers'];
        $stmt->close();

        // Total Messages envoyés (tous, user + bot)
        $stmt = $conn->prepare("SELECT COUNT(id) AS totalMessages FROM chat_history");
        $stmt->execute();
        $result = $stmt->get_result();
        $stats['totalMessages'] = $result->fetch_assoc()['totalMessages'];
        $stmt->close();

        // Réclamations en attente (statut 'open' ou 'in_progress')
        $stmt = $conn->prepare("SELECT COUNT(id) AS pendingReclamations FROM reclamations WHERE status IN ('open', 'in_progress')");
        $stmt->execute();
        $result = $stmt->get_result();
        $stats['pendingReclamations'] = $result->fetch_assoc()['pendingReclamations'];
        $stmt->close();

        // Nombre d'administrateurs
        $stmt = $conn->prepare("SELECT COUNT(id) AS adminUsers FROM users WHERE user_type = 'admin'");
        $stmt->execute();
        $result = $stmt->get_result();
        $stats['adminUsers'] = $result->fetch_assoc()['adminUsers'];
        $stmt->close();

        // NOUVEAU: Nombre de rendez-vous à venir (statut 'pending' et date future)
        $stmt = $conn->prepare("SELECT COUNT(id) AS upcomingAppointments FROM appointments WHERE status = 'pending' AND appointment_date >= CURDATE()");
        $stmt->execute();
        $result = $stmt->get_result();
        $stats['upcomingAppointments'] = $result->fetch_assoc()['upcomingAppointments'];
        $stmt->close();

        // NOUVEAU: Nombre d'étudiants
        $stmt = $conn->prepare("SELECT COUNT(id) AS studentUsers FROM users WHERE user_type = 'student'");
        $stmt->execute();
        $result = $stmt->get_result();
        $stats['studentUsers'] = $result->fetch_assoc()['studentUsers'];
        $stmt->close();


        $response['success'] = true;
        $response['message'] = 'Statistiques récupérées avec succès.';
        $response['stats'] = $stats;

    } else {
        $response['message'] = 'Action GET non valide.';
    }

    $conn->close();
    echo json_encode($response);
    ?>
    