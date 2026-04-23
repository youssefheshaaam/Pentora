<?php
// Start a session to check login state
session_start();

// Check if user is logged in
$logged_in = isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true;
$username = $logged_in ? $_SESSION['username'] : 'Guest';

// If not logged in, we'll still show the page but with limited content
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <div class="card">
            <div class="card-header bg-primary text-white">
                <h4>User Dashboard</h4>
            </div>
            <div class="card-body">
                <?php if ($logged_in): ?>
                    <div class="alert alert-success">
                        <h4 class="alert-heading">Welcome, <?php echo htmlspecialchars($username); ?>!</h4>
                        <p>You have successfully logged in to your account.</p>
                    </div>
                    
                    <div class="row mt-4">
                        <div class="col-md-4">
                            <div class="card mb-3">
                                <div class="card-body text-center">
                                    <h5 class="card-title">Profile</h5>
                                    <p class="card-text">View and edit your profile information</p>
                                    <a href="#" class="btn btn-outline-primary">Go to Profile</a>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="card mb-3">
                                <div class="card-body text-center">
                                    <h5 class="card-title">Messages</h5>
                                    <p class="card-text">You have 3 unread messages</p>
                                    <a href="#" class="btn btn-outline-primary">View Messages</a>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="card mb-3">
                                <div class="card-body text-center">
                                    <h5 class="card-title">Settings</h5>
                                    <p class="card-text">Configure your account settings</p>
                                    <a href="#" class="btn btn-outline-primary">Go to Settings</a>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="d-flex justify-content-between mt-3">
                        <a href="index.php" class="btn btn-secondary">Back to Open Redirect Tests</a>
                        <a href="logout.php" class="btn btn-danger">Logout</a>
                    </div>
                <?php else: ?>
                    <div class="alert alert-warning">
                        <h4 class="alert-heading">Not Logged In</h4>
                        <p>You are viewing the dashboard as a guest. Some features are restricted.</p>
                        <hr>
                        <p class="mb-0">Please <a href="index.php">go back</a> and log in to access all features.</p>
                    </div>
                    
                    <div class="row mt-4">
                        <div class="col-md-4">
                            <div class="card mb-3 bg-light">
                                <div class="card-body text-center">
                                    <h5 class="card-title text-muted">Profile</h5>
                                    <p class="card-text text-muted">Login required</p>
                                    <button class="btn btn-outline-secondary" disabled>Restricted</button>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="card mb-3 bg-light">
                                <div class="card-body text-center">
                                    <h5 class="card-title text-muted">Messages</h5>
                                    <p class="card-text text-muted">Login required</p>
                                    <button class="btn btn-outline-secondary" disabled>Restricted</button>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="card mb-3 bg-light">
                                <div class="card-body text-center">
                                    <h5 class="card-title text-muted">Settings</h5>
                                    <p class="card-text text-muted">Login required</p>
                                    <button class="btn btn-outline-secondary" disabled>Restricted</button>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="mt-3">
                        <a href="index.php" class="btn btn-primary">Back to Login</a>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
</body>
</html>
