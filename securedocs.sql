-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: May 18, 2025 at 03:40 AM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `securedocs`
--

-- --------------------------------------------------------

--
-- Table structure for table `audit_logs`
--

CREATE TABLE `audit_logs` (
  `id` int(11) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  `action` varchar(255) NOT NULL,
  `timestamp` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `documents`
--

CREATE TABLE `documents` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `filename` varchar(255) NOT NULL,
  `file_path` varchar(255) NOT NULL,
  `file_hash` varchar(64) NOT NULL,
  `signature` text DEFAULT NULL,
  `uploaded_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `hmac` varchar(128) DEFAULT NULL,
  `encrypted_data` longblob NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `username` varchar(50) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `role` enum('user','admin') DEFAULT 'user',
  `two_factor_secret` varchar(100) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `username`, `email`, `password_hash`, `role`, `two_factor_secret`, `created_at`) VALUES
(1, 'ma', 'ma@gmail.com', 'scrypt:32768:8:1$RBJJYWorPvR2Qqhl$60a582717520b0357159b7e33688ec0c19f880e344dd938497b0eeda160088e1d7a0d96850e9f62ac42a927988817127c8d762cec457f0f8687d37a2f8d57f5a', 'user', 'JXLTXZJSXJQ2VOITYNJUTO3NCNHGXFPJ', '2025-05-15 21:43:07'),
(4, 'Admin', 'admin@ma.com', 'pbkdf2:sha256:1000000$yWxAocmYb1ojgFzK$3756f21cabda7377a4c4a160c8734321953a8121ea9d0009d283fbbb6eda7122', 'admin', 'G55RJXBGVH634WCPEEG3E2QE5JCQI2IP', '2025-05-16 01:31:58'),
(7, 'mo', 'mo@mo.com', 'scrypt:32768:8:1$p6kascNaADDHPJkV$4821af7f86047489127e9864554dc1652c6ee46403069782bb243988f4d361fe2fe0d4c1e955782f2f10ad5cde315069e38f44d6a9e2e33a9e92a213dd78893e', 'user', NULL, '2025-05-16 18:54:58'),
(8, 'zaghloula', 'mahmoud.zaghloula88@gmail.com', 'scrypt:32768:8:1$JUpWY83XX6vZdsVv$39fed437dca1be18b451bdd63a89ca46e395afea8d73c2bb5502b724c120a63d05623492d3cb7e51f2e50592e292c50b8a8b65dfb5f5c3033402586ea2dd1199', 'user', 'VR3RMWHFQP3A24L5RXXFWNOVBUSM4UGZ', '2025-05-17 19:43:04'),
(9, 'test@te.com', 'test@te.com', 'scrypt:32768:8:1$PrAiJ5xFUUtRMUcp$e37458a12102879962e6311b992b61d842d0d558b836dd9d950a17ba5b88cfb684562d3cc696026b244ed22bb61f9218321fb439f38f4540a525b196a12f3e0a', 'user', '43RJOCAZ27XMRHXAZPEYQV2JCCQP3D3K', '2025-05-17 20:00:56');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `audit_logs`
--
ALTER TABLE `audit_logs`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `documents`
--
ALTER TABLE `documents`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `audit_logs`
--
ALTER TABLE `audit_logs`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `documents`
--
ALTER TABLE `documents`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=10;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
