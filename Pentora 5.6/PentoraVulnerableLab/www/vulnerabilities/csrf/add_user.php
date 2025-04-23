<?php
// Start session
session_start();

// Check if user is logged in and is admin
$is_admin = false;
if (isset($_SESSION['user_id'])) {
    // Connect to the database
    $db = new SQLite3('users.db');
    
    // Check if user is admin
    $stmt = $db->prepare("SELECT is_admin FROM users WHERE id = :id");
    $stmt->bindValue(':id', $_SESSION['user_id'], SQLITE3_INTEGER);
    $result = $stmt->execute();
    $user = $result->fetchArray(SQLITE3_ASSOC);
    
    if ($user && $user['is_admin'] == 1) {
        $is_admin = true;
    }
}

// If not admin, redirect to main page
if (!$is_admin) {
    header("Location: index.php");
    exit;
}

// Handle user creation
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];
    $email = $_POST['email'];
    $is_admin_new = isset($_POST['is_admin']) ? (int)$_POST['is_admin'] : 0;
    
    // Check if username already exists
    $stmt = $db->prepare("SELECT id FROM users WHERE username = :username");
    $stmt->bindValue(':username', $username, SQLITE3_TEXT);
    $result = $stmt->execute();
    $existing_user = $result->fetchArray(SQLITE3_ASSOC);
    
    if ($existing_user) {
        // Username already exists
        header("Location: index.php?error=username_exists");
        exit;
    }
    
    // Insert the new user
    $stmt = $db->prepare("INSERT INTO users (username, password, email, is_admin) VALUES (:username, :password, :email, :is_admin)");
    $stmt->bindValue(':username', $username, SQLITE3_TEXT);
    $stmt->bindValue(':password', $password, SQLITE3_TEXT);
    $stmt->bindValue(':email', $email, SQLITE3_TEXT);
    $stmt->bindValue(':is_admin', $is_admin_new, SQLITE3_INTEGER);
    $result = $stmt->execute();
    
    // Redirect back to the main page with success message
    header("Location: index.php?add=success");
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Add User</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <div class="alert alert-danger">
            <h4 class="alert-heading">Error!</h4>
            <p>Something went wrong while adding the user.</p>
            <hr>
            <p class="mb-0">Please try again.</p>
        </div>
        
        <div class="mt-3">
            <a href="index.php" class="btn btn-primary">Back to Admin Panel</a>
        </div>
    </div>
</body>
</html>
