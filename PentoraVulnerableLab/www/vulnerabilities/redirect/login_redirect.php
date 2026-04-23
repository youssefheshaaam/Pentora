<?php
// Start a session to store login state
session_start();

// Vulnerable login with redirect
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = isset($_POST['username']) ? $_POST['username'] : '';
    $password = isset($_POST['password']) ? $_POST['password'] : '';
    $redirect_to = isset($_POST['redirect_to']) ? $_POST['redirect_to'] : 'dashboard.php';
    
    // Very simple authentication (for demonstration purposes)
    // In a real app, you would validate against a database and use password hashing
    if ($username === 'user' && $password === 'password') {
        // Successful login
        $_SESSION['logged_in'] = true;
        $_SESSION['username'] = $username;
        
        // Log the login and redirect
        error_log("User '{$username}' logged in, redirecting to: {$redirect_to}");
        
        // Vulnerable redirect - no validation of the redirect_to parameter
        header("Location: " . $redirect_to);
        exit;
    } else {
        $error = "Invalid username or password";
    }
} else {
    $error = "Invalid request method";
}

// If we get here, login failed
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Failed</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <div class="alert alert-danger">
            <h4 class="alert-heading">Login Failed!</h4>
            <p><?php echo htmlspecialchars($error); ?></p>
        </div>
        
        <div class="card">
            <div class="card-header">
                <h5>Login Form</h5>
            </div>
            <div class="card-body">
                <form action="login_redirect.php" method="post">
                    <input type="hidden" name="redirect_to" value="dashboard.php">
                    <div class="mb-3">
                        <label for="username" class="form-label">Username</label>
                        <input type="text" name="username" id="username" class="form-control" value="user" required>
                        <div class="form-text">Hint: The username is "user"</div>
                    </div>
                    <div class="mb-3">
                        <label for="password" class="form-label">Password</label>
                        <input type="password" name="password" id="password" class="form-control" required>
                        <div class="form-text">Hint: The password is "password"</div>
                    </div>
                    <button type="submit" class="btn btn-primary">Login</button>
                </form>
            </div>
        </div>
        
        <div class="mt-3">
            <a href="index.php" class="btn btn-secondary">Back to Open Redirect Tests</a>
        </div>
    </div>
</body>
</html>
