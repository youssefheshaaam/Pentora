<?php
// Hidden Admin Panel
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Panel - Pentora Vulnerable Lab</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>Hidden Admin Panel</h1>
        <div class="alert alert-success">
            <strong>Success!</strong> You've discovered the hidden admin panel.
        </div>

        <div class="card mb-4">
            <div class="card-header">
                <h5>Admin Dashboard</h5>
            </div>
            <div class="card-body">
                <p>This is a simulated admin dashboard that would normally be protected.</p>
                <p>In a real application, this page should not be accessible without proper authentication.</p>
                
                <h6 class="mt-4">System Information:</h6>
                <ul>
                    <li><strong>Server:</strong> Apache/2.4.54 (Debian)</li>
                    <li><strong>PHP Version:</strong> <?php echo phpversion(); ?></li>
                    <li><strong>Database:</strong> MySQL 8.0.28</li>
                    <li><strong>Users:</strong> 15 registered</li>
                </ul>
                
                <div class="alert alert-warning mt-3">
                    <strong>Security Note:</strong> In a secure application, this admin panel would be:
                    <ul>
                        <li>Located at a non-guessable URL</li>
                        <li>Protected by strong authentication</li>
                        <li>Possibly restricted by IP address</li>
                        <li>Not directly accessible from the internet</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
