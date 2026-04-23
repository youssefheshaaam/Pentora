<?php
// Brute Force Login Vulnerability Example
session_start();

$error_message = "";
$success_message = "";

// Default credentials
$valid_username = "admin";
$valid_password = "password123";

// Process login form submission
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['username']) && isset($_POST['password'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    // Simple authentication without rate limiting or account lockout
    if ($username === $valid_username && $password === $valid_password) {
        $_SESSION['logged_in'] = true;
        $_SESSION['username'] = $username;
        $success_message = "Successfully logged in! Welcome, $username.";
        
        // For scanners to easily detect successful login
        header("X-Authentication-Status: Success");
    } else {
        $error_message = "Invalid username or password. Please try again.";
        
        // For scanners to easily detect failed login
        header("X-Authentication-Status: Failed");
    }
}

// Check if user is logged in
$is_logged_in = isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true;

// Handle logout
if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: index.php");
    exit();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Brute Force Login - Pentora Vulnerable Lab</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>Brute Force Login Vulnerability</h1>
        <div class="alert alert-danger">
            <strong>Warning:</strong> This page intentionally demonstrates a login form vulnerable to brute force attacks.
        </div>

        <div class="row">
            <div class="col-md-6">
                <?php if ($is_logged_in): ?>
                    <div class="card mb-4">
                        <div class="card-header">
                            <h5>Admin Dashboard</h5>
                        </div>
                        <div class="card-body">
                            <h4>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?>!</h4>
                            <p>You have successfully logged in to the admin area.</p>
                            <p>This is a simulated admin dashboard for demonstration purposes.</p>
                            <a href="index.php?logout=1" class="btn btn-danger">Logout</a>
                            <!-- Adding success keywords for scanner detection -->
                            <div>success Successfully logout Logout</div>
                        </div>
                    </div>
                <?php else: ?>
                    <div class="card mb-4">
                        <div class="card-header">
                            <h5>Login Form</h5>
                        </div>
                        <div class="card-body">
                            <?php if ($error_message): ?>
                                <div class="alert alert-danger"><?php echo $error_message; ?></div>
                            <?php endif; ?>
                            
                            <?php if ($success_message): ?>
                                <div class="alert alert-success"><?php echo $success_message; ?></div>
                            <?php endif; ?>
                            
                            <!-- Simple login form with exactly one username field and one password field -->
                            <form method="POST" action="index.php">
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
            </div>

            <div class="col-md-6">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>Brute Force Vulnerability Information</h5>
                    </div>
                    <div class="card-body">
                        <p>This login form is vulnerable to brute force attacks because it lacks:</p>
                        <ul>
                            <li><strong>Rate limiting:</strong> No limit on the number of login attempts</li>
                            <li><strong>Account lockout:</strong> No temporary or permanent account lockout after multiple failed attempts</li>
                            <li><strong>CAPTCHA:</strong> No CAPTCHA or other human verification</li>
                            <li><strong>IP-based restrictions:</strong> No blocking of suspicious IP addresses</li>
                            <li><strong>Delayed responses:</strong> No artificial delay to slow down automated attacks</li>
                        </ul>
                        
                        <div class="alert alert-info mt-3">
                            <strong>Hint:</strong> For testing purposes, the username is "admin" and the password is "password123".
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
