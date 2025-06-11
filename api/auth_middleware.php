<?php
// api/auth_middleware.php - Middleware d'authentification pour la démo
// Ce fichier n'est pas une API en soi, mais une fonction utilitaire pour les APIs.

// Inclut la connexion à la base de données si ce n'est pas déjà fait
if (!isset($conn)) {
    require_once 'config.php';
}

// Headers pour les requêtes Cross-Origin (CORS) - À ajuster pour la production
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");

/**
 * Fonction d'authentification pour la démo.
 * En production, cette fonction devrait valider un JWT et récupérer les informations de l'utilisateur.
 * Pour cette démo, elle utilise le mot de passe en clair (le "token" / le mot de passe) pour trouver l'utilisateur.
 *
 * @return array|null Les informations de l'utilisateur authentifié ou null si non authentifié.
 */
function authenticate_request() {
    global $conn; // Accéder à la connexion globale à la base de données

    $auth_header = null;
    // Tenter d'obtenir l'en-tête Authorization de différentes sources pour une meilleure robustesse
    if (function_exists('getallheaders')) {
        $headers = getallheaders();
        // Normaliser la clé 'Authorization' (peut être 'Authorization' ou 'authorization' selon le serveur)
        $auth_header = $headers['Authorization'] ?? $headers['authorization'] ?? null;
    }
    // Fallback pour les serveurs où getallheaders() pourrait ne pas fonctionner ou ne pas transmettre l'en-tête Authorization
    if ($auth_header === null && isset($_SERVER['HTTP_AUTHORIZATION'])) {
        $auth_header = $_SERVER['HTTP_AUTHORIZATION'];
    }

    error_log("Auth Header reçu dans authenticate_request: " . ($auth_header ?? 'AUCUN')); // Log pour le débogage

    $token = str_replace('Bearer ', '', $auth_header ?? ''); // $token est le mot de passe en clair envoyé par le frontend

    if (empty($token)) {
        error_log("Authentification échouée: Aucun token fourni.");
        return null; // Pas de token, pas d'authentification
    }

    error_log("Token extrait: " . $token); // Log du token extrait

    // --- AVERTISSEMENT DE SÉCURITÉ : DÉMO SEULEMENT ---
    // Dans un environnement de production, l'authentification ne devrait JAMAIS se faire en
    // recherchant par le mot de passe en clair. Cette logique est un contournement
    // pour gérer la coexistence de mots de passe en clair et hachés dans votre base de données
    // de démonstration, étant donné que le frontend envoie le mot de passe en clair comme "token".
    // Un système de jetons JWT basé sur des hachages serait la bonne approche pour la production.

    // Première tentative : Comparaison directe du token (mot de passe en clair) avec le champ `password_hash`.
    // Ceci fonctionne pour les utilisateurs dont le mot de passe est stocké en clair dans `password_hash`
    $stmt_direct_compare = $conn->prepare("SELECT id, name, email, user_type, password_hash FROM users WHERE password_hash = ?");
    if ($stmt_direct_compare === false) {
        error_log("Erreur de préparation de la requête directe: " . $conn->error);
        return null;
    }
    $stmt_direct_compare->bind_param("s", $token);
    $stmt_direct_compare->execute();
    $result_direct_compare = $stmt_direct_compare->get_result();

    if ($result_direct_compare->num_rows === 1) {
        $user = $result_direct_compare->fetch_assoc();
        $stmt_direct_compare->close();
        error_log("Authentification réussie: Correspondance directe pour l'utilisateur " . $user['email']);
        unset($user['password_hash']);
        return $user;
    }
    $stmt_direct_compare->close();
    error_log("Authentification échouée: Aucune correspondance directe de mot de passe pour le token.");


    // Deuxième tentative : Si la comparaison directe échoue, itérer sur les utilisateurs et tenter `password_verify()`.
    $stmt_all_users = $conn->prepare("SELECT id, name, email, user_type, password_hash FROM users");
    if ($stmt_all_users === false) {
        error_log("Erreur de préparation de la requête tous les utilisateurs: " . $conn->error);
        return null;
    }
    $stmt_all_users->execute();
    $result_all_users = $stmt_all_users->get_result();

    while ($user = $result_all_users->fetch_assoc()) {
        // password_verify gère gracieusement les non-hachages, mais pour la performance
        // et la clarté, nous ne vérifions que les chaînes qui ressemblent à des hachages bcrypt.
        if (preg_match('/^\$2y\$.{56}$/', $user['password_hash'])) {
            if (password_verify($token, $user['password_hash'])) {
                $stmt_all_users->close();
                error_log("Authentification réussie: Correspondance password_verify pour l'utilisateur " . $user['email']);
                unset($user['password_hash']);
                return $user;
            }
        }
    }
    $stmt_all_users->close();
    error_log("Authentification échouée: Aucune correspondance password_verify pour le token.");

    return null; // Aucun utilisateur trouvé après les deux tentatives
}
?>
