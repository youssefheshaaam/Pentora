<?php
// Backup Files Vulnerability Example - Login Page

// Include the secure configuration file
require_once('config.php');

// Initialize variables
$error = '';
$success = false;

// Handle login form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = isset($_POST['username']) ? $_POST['username'] : '';
    $password = isset($_POST['password']) ? $_POST['password'] : '';
    
    // Simple authentication check
    if ($username === 'admin' && $password === 'admin123') {
        $success = true;
    } else {
        $error = 'Invalid username or password';
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Backup Files - Pentora Vulnerable Lab</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>Login Page</h1>
        
        <?php if ($success): ?>
            <div class="alert alert-success">
                <strong>Success!</strong> You have successfully logged in.
            </div>
            
            <div class="card mb-4">
                <div class="card-header">
                    <h5>Admin Dashboard</h5>
                </div>
                <div class="card-body">
                    <p>Welcome to the admin dashboard. This is a placeholder for admin content.</p>
                    <p>In a real application, this would contain sensitive information.</p>
                </div>
            </div>
        <?php else: ?>
            <?php if (!empty($error)): ?>
                <div class="alert alert-danger">
                    <strong>Error:</strong> <?php echo htmlspecialchars($error); ?>
                </div>
            <?php endif; ?>
            
            <div class="card mb-4">
                <div class="card-header">
                    <h5>Login</h5>
                </div>
                <div class="card-body">
                    <form action="login.php" method="POST">
                        <div class="mb-3">
                            <label for="username" class="form-label">Username:</label>
                            <input type="text" class="form-control" id="username" name="username" required>
                        </div>
                        <div class="mb-3">
                            <label for="password" class="form-label">Password:</label>
                            <input type="password" class="form-control" id="password" name="password" required>
                        </div>
                        <button type="submit" class="btn btn-primary">Login</button>
                    </form>
                </div>
            </div>
        <?php endif; ?>
        
        <a href="index.php" class="btn btn-secondary">Back to Backup Files Tests</a>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
