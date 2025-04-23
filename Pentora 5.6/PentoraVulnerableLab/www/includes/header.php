<?php
// Common header for Pentora Vulnerable Lab
session_start();

// Set default content type
header('Content-Type: text/html; charset=utf-8');

// Security headers (intentionally incomplete for the vulnerable lab)
header('X-Content-Type-Options: nosniff');

// Function to sanitize output
function html_escape($text) {
    return htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
}

// Function to generate a CSRF token
function generate_csrf_token() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

// Common site information
$site_title = "Pentora Vulnerable Lab";
$site_description = "A deliberately vulnerable application for testing Pentora scanner";
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $site_title; ?> - <?php echo isset($page_title) ? html_escape($page_title) : 'Vulnerability Demo'; ?></title>
    <link rel="stylesheet" href="/assets/css/bootstrap.min.css">
    <link rel="stylesheet" href="/assets/css/style.css">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="/"><?php echo $site_title; ?></a>
            <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ml-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="/">Home</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/vulnerabilities/">Vulnerabilities</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <div class="row">
            <div class="col-md-12">
                <h1><?php echo isset($page_title) ? html_escape($page_title) : 'Vulnerability Demo'; ?></h1>
                <hr>
