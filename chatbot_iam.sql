-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Hôte : 127.0.0.1
-- Généré le : mer. 11 juin 2025 à 05:15
-- Version du serveur : 10.4.32-MariaDB
-- Version de PHP : 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Base de données : `chatbot_iam`
--

-- --------------------------------------------------------

--
-- Structure de la table `appointments`
--

CREATE TABLE `appointments` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `appointment_date` date NOT NULL,
  `appointment_time` time NOT NULL,
  `reason` text DEFAULT NULL,
  `status` enum('pending','confirmed','cancelled','completed') DEFAULT 'pending',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Déchargement des données de la table `appointments`
--

INSERT INTO `appointments` (`id`, `user_id`, `appointment_date`, `appointment_time`, `reason`, `status`, `created_at`, `updated_at`) VALUES
(1, 1, '2025-06-12', '11:00:00', 'AIIIIIIIIIIIIZZZZZZZZZZ', 'pending', '2025-06-10 17:36:59', '2025-06-10 17:36:59');

-- --------------------------------------------------------

--
-- Structure de la table `chat_history`
--

CREATE TABLE `chat_history` (
  `id` int(11) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  `message_text` text NOT NULL,
  `sender` enum('user','bot') NOT NULL,
  `timestamp` datetime DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Déchargement des données de la table `chat_history`
--

INSERT INTO `chat_history` (`id`, `user_id`, `message_text`, `sender`, `timestamp`) VALUES
(1, 1, 'Quelles sont les formations disponibles ?', 'user', '2025-06-10 00:28:54'),
(2, 1, 'Quels sont vos tarifs ?', 'user', '2025-06-10 00:28:56'),
(3, 1, 'Où êtes-vous situés ?', 'user', '2025-06-10 00:28:57'),
(4, 1, 'Comment s\\\'inscrire ?', 'user', '2025-06-10 00:29:02'),
(5, 1, 'Où êtes-vous situés ?', 'user', '2025-06-10 00:29:03'),
(6, 1, 'Quels sont vos tarifs ?', 'user', '2025-06-10 00:29:08'),
(7, 1, 'Comment s\\\'inscrire ?', 'user', '2025-06-10 00:29:12'),
(8, 1, 'Comment s\\\'inscrire ?', 'user', '2025-06-10 00:29:20'),
(9, 1, 'Quels sont vos tarifs ?', 'user', '2025-06-10 00:29:23'),
(10, 1, 'Quelles sont les formations disponibles ?', 'user', '2025-06-10 00:29:25'),
(11, 1, 'Quels sont vos tarifs ?', 'user', '2025-06-10 17:10:21'),
(12, 1, 'Où êtes-vous situés ?', 'user', '2025-06-10 17:11:34'),
(13, 1, 'Prendre rendez-vous', 'user', '2025-06-10 17:12:42'),
(14, 1, 'Prendre rendez-vous', 'user', '2025-06-10 17:27:51'),
(15, 1, 'En tant que Mode Prospect, je ne peux pas prendre de rendez-vous. Je peux vous fournir des informations sur nos services, nos tarifs et notre localisation. Pour prendre rendez-vous, vous devrez contacter directement notre service client.\\n', 'bot', '2025-06-10 17:27:52'),
(16, 1, 'Prendre rendez-vous', 'user', '2025-06-10 17:30:48'),
(17, 1, 'En tant que Mode Prospect, je ne peux pas prendre de rendez-vous. Cependant, je peux vous donner les informations nécessaires pour contacter notre service client afin de prendre rendez-vous.  Avez-vous besoin de ces informations?\\n', 'bot', '2025-06-10 17:30:50'),
(18, 1, 'Salut', 'user', '2025-06-10 17:37:19'),
(19, 1, 'Salut Issa Sougui AHMAT ! Comment puis-je vous aider aujourd\\\'hui ?\\n', 'bot', '2025-06-10 17:37:20'),
(20, 1, 'Quels sont les prix des formations', 'user', '2025-06-10 17:37:39'),
(21, 1, 'En tant que Mode Prospect, je peux vous donner un aperçu des types de formations que nous offrons. Pour obtenir des informations précises sur les prix des formations qui vous intéressent, veuillez nous fournir plus de détails sur le domaine ou le type de formation recherché. Cela me permettra de vous orienter vers les informations les plus pertinentes.\\n', 'bot', '2025-06-10 17:37:40'),
(22, 1, 'Informatique', 'user', '2025-06-10 17:37:56'),
(23, 1, 'D\\\'accord, \\\"Informatique\\\" est un domaine vaste. Pour vous donner des prix plus précis, pourriez-vous me préciser quel type de formation en informatique vous intéresse ? Par exemple :\\n\\n*   **Développement web :** Formation pour créer des sites web (front-end, back-end, full-stack)\\n*   **Développement mobile :** Formation pour créer des applications pour smartphones (iOS, Android)\\n*   **Data Science / Analyse de données :** Formation pour analyser des données et en tirer des conclusions\\n*   **Cybersécurité :** Formation pour protéger les systèmes informatiques contre les menaces\\n*   **Administration de réseaux :** Formation pour gérer et maintenir des réseaux informatiques\\n*   **Bureautique :** Formation sur les logiciels de bureau (Word, Excel, PowerPoint, etc.)\\n*   **Autres ?** (Spécifiez)\\n\\nPlus vous serez précis, plus je pourrai vous orienter vers les informations tarifaires adéquates.\\n', 'bot', '2025-06-10 17:37:58');

-- --------------------------------------------------------

--
-- Structure de la table `conversations`
--

CREATE TABLE `conversations` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `start_time` datetime DEFAULT current_timestamp(),
  `title` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Déchargement des données de la table `conversations`
--

INSERT INTO `conversations` (`id`, `user_id`, `start_time`, `title`) VALUES
(1, 1, '2025-06-11 01:19:22', NULL);

-- --------------------------------------------------------

--
-- Structure de la table `formations`
--

CREATE TABLE `formations` (
  `id` int(11) NOT NULL,
  `name` varchar(255) NOT NULL,
  `description` text DEFAULT NULL,
  `duration_years` int(11) DEFAULT NULL,
  `price_fcfa` decimal(10,2) DEFAULT NULL,
  `status` enum('active','inactive') DEFAULT 'active',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Structure de la table `grades`
--

CREATE TABLE `grades` (
  `id` int(11) NOT NULL,
  `student_id` int(11) NOT NULL,
  `subject` varchar(255) NOT NULL,
  `grade` decimal(4,2) NOT NULL,
  `max_grade` decimal(4,2) DEFAULT 20.00,
  `exam_date` date DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Structure de la table `messages`
--

CREATE TABLE `messages` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `conversation_id` int(11) DEFAULT NULL,
  `message_text` text NOT NULL,
  `sender` varchar(50) NOT NULL,
  `timestamp` datetime DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Structure de la table `payments`
--

CREATE TABLE `payments` (
  `id` int(11) NOT NULL,
  `student_id` int(11) NOT NULL,
  `amount_due` decimal(10,2) NOT NULL,
  `amount_paid` decimal(10,2) DEFAULT 0.00,
  `payment_date` date DEFAULT NULL,
  `due_date` date DEFAULT NULL,
  `payment_status` enum('pending','paid','overdue','partial') NOT NULL DEFAULT 'pending',
  `description` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Structure de la table `reclamations`
--

CREATE TABLE `reclamations` (
  `id` int(11) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  `type` varchar(100) DEFAULT NULL,
  `priority` enum('low','medium','high','urgent') NOT NULL DEFAULT 'medium',
  `description` text NOT NULL,
  `status` enum('open','in_progress','resolved','closed') NOT NULL DEFAULT 'open',
  `resolution_details` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Structure de la table `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `name` varchar(255) NOT NULL,
  `email` varchar(255) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `phone` varchar(50) DEFAULT NULL,
  `user_type` enum('prospect','student','admin') NOT NULL DEFAULT 'prospect',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Déchargement des données de la table `users`
--

INSERT INTO `users` (`id`, `name`, `email`, `password_hash`, `phone`, `user_type`, `created_at`) VALUES
(1, 'Issa Sougui AHMAT', 'issasougui08@gmail.com', '$2y$10$ffb1qGHXeXl3tGkTrkVFHeHZeVWAH/.vXKuaJplNyf3YbKrqvneui', '7448383', 'prospect', '2025-06-10 00:19:15'),
(2, 'Admin IAM', 'admin@iam.com', 'ADMIN_IAM_SECURE_TOKEN_2025', '0123456789', 'admin', '2025-06-11 00:44:52'),
(3, 'denidddddddd', 'ais@gmail.com', '$2y$10$g6bspbS6R39Vq3SNLnHLM.AZ7SRTeDCbnQWX6YtlcRfpDyQNTvjZ2', '737636363', 'admin', '2025-06-11 01:12:31'),
(4, 'Issa Sougui AHMAT', 'issasougui09@gmail.com', '123456', '7448383', 'prospect', '2025-06-11 01:23:18'),
(5, 'YY', 'aisa@gmail.com', '$2y$10$nJfnmpR.u.cJkGPagDc4ROdSnZdMIkB678QivunV4oo5fK1wAdkVK', '73737', 'student', '2025-06-11 03:01:24'),
(6, 'UZBBBBB', 'addimi@gmail.com', '123456', '888282', 'student', '2025-06-11 03:03:56');

--
-- Index pour les tables déchargées
--

--
-- Index pour la table `appointments`
--
ALTER TABLE `appointments`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`);

--
-- Index pour la table `chat_history`
--
ALTER TABLE `chat_history`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`);

--
-- Index pour la table `conversations`
--
ALTER TABLE `conversations`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`);

--
-- Index pour la table `formations`
--
ALTER TABLE `formations`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `name` (`name`);

--
-- Index pour la table `grades`
--
ALTER TABLE `grades`
  ADD PRIMARY KEY (`id`),
  ADD KEY `student_id` (`student_id`);

--
-- Index pour la table `messages`
--
ALTER TABLE `messages`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`),
  ADD KEY `conversation_id` (`conversation_id`);

--
-- Index pour la table `payments`
--
ALTER TABLE `payments`
  ADD PRIMARY KEY (`id`),
  ADD KEY `student_id` (`student_id`);

--
-- Index pour la table `reclamations`
--
ALTER TABLE `reclamations`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`);

--
-- Index pour la table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `email` (`email`);

--
-- AUTO_INCREMENT pour les tables déchargées
--

--
-- AUTO_INCREMENT pour la table `appointments`
--
ALTER TABLE `appointments`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT pour la table `chat_history`
--
ALTER TABLE `chat_history`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=24;

--
-- AUTO_INCREMENT pour la table `conversations`
--
ALTER TABLE `conversations`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT pour la table `formations`
--
ALTER TABLE `formations`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT pour la table `grades`
--
ALTER TABLE `grades`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT pour la table `messages`
--
ALTER TABLE `messages`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT pour la table `payments`
--
ALTER TABLE `payments`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT pour la table `reclamations`
--
ALTER TABLE `reclamations`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT pour la table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- Contraintes pour les tables déchargées
--

--
-- Contraintes pour la table `appointments`
--
ALTER TABLE `appointments`
  ADD CONSTRAINT `appointments_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Contraintes pour la table `chat_history`
--
ALTER TABLE `chat_history`
  ADD CONSTRAINT `chat_history_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Contraintes pour la table `conversations`
--
ALTER TABLE `conversations`
  ADD CONSTRAINT `conversations_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Contraintes pour la table `grades`
--
ALTER TABLE `grades`
  ADD CONSTRAINT `grades_ibfk_1` FOREIGN KEY (`student_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Contraintes pour la table `messages`
--
ALTER TABLE `messages`
  ADD CONSTRAINT `messages_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `messages_ibfk_2` FOREIGN KEY (`conversation_id`) REFERENCES `conversations` (`id`) ON DELETE SET NULL;

--
-- Contraintes pour la table `payments`
--
ALTER TABLE `payments`
  ADD CONSTRAINT `payments_ibfk_1` FOREIGN KEY (`student_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Contraintes pour la table `reclamations`
--
ALTER TABLE `reclamations`
  ADD CONSTRAINT `reclamations_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
