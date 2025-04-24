<?php
// Start session
session_start();

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: index.php");
    exit;
}

// Connect to the database
$db = new SQLite3('users.db');

// Handle profile update
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $user_id = $_SESSION['user_id'];
    $email = $_POST['email'];
    
    // Update the user's email
    $stmt = $db->prepare("UPDATE users SET email = :email WHERE id = :id");
    $stmt->bindValue(':email', $email, SQLITE3_TEXT);
    $stmt->bindValue(':id', $user_id, SQLITE3_INTEGER);
    $result = $stmt->execute();
    
    // Redirect back to the main page with success message
    header("Location: index.php?update=success");
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Update Profile</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <div class="alert alert-danger">
            <h4 class="alert-heading">Error!</h4>
            <p>Something went wrong with your profile update.</p>
            <hr>
            <p class="mb-0">Please try again.</p>
        </div>
        
        <div class="mt-3">
            <a href="index.php" class="btn btn-primary">Back to Profile</a>
        </div>
    </div>
</body>
</html>
