<?php
// api/auth_helper.php
// Fonction d'aide pour vérifier l'accès administrateur
function verify_admin_access($conn) {
    // Récupère tous les en-têtes de la requête HTTP
    $headers = getallheaders();
    // Extrait l'en-tête 'Authorization', par défaut à une chaîne vide si non présent
    $auth_header = $headers['Authorization'] ?? '';
    // Supprime le préfixe 'Bearer ' pour obtenir le token pur
    $token = str_replace('Bearer ', '', $auth_header);

    // Pour cette démo, la vérification est simple : le token doit correspondre au token admin fixe.
    // En production, cette logique serait plus complexe (vérification JWT, expiration, etc.).
    if ($token === ADMIN_DEMO_TOKEN) {
        // Si le token est valide pour l'administrateur, retourne un tableau simulant les informations de l'utilisateur admin.
        // L'ID, l'email et le type sont ici des valeurs fixes pour la démo.
        return ['id' => 1, 'email' => 'admin@iam.com', 'user_type' => 'admin'];
    }

    // Si aucun token n'est fourni ou si le token est invalide, l'accès est refusé.
    return false;
}
?>
