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

// Handle user deletion
if (isset($_GET['id'])) {
    $user_id = (int)$_GET['id'];
    
    // Don't allow deleting the current user
    if ($user_id == $_SESSION['user_id']) {
        header("Location: index.php?error=cannot_delete_self");
        exit;
    }
    
    // Delete the user
    $stmt = $db->prepare("DELETE FROM users WHERE id = :id");
    $stmt->bindValue(':id', $user_id, SQLITE3_INTEGER);
    $result = $stmt->execute();
    
    // Redirect back to the main page with success message
    header("Location: index.php?delete=success");
    exit;
}

// If no ID provided, redirect back
header("Location: index.php");
exit;
?>
