<?php
// Development Directory
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Development Area - Pentora Vulnerable Lab</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>Development Directory</h1>
        <div class="alert alert-success">
            <strong>Success!</strong> You've discovered the hidden development directory.
        </div>

        <div class="card mb-4">
            <div class="card-header">
                <h5>Development Environment</h5>
            </div>
            <div class="card-body">
                <p>This is a simulated development environment that would normally not be accessible in production.</p>
                
                <h6 class="mt-4">Development Notes:</h6>
                <ul>
                    <li><strong>TODO:</strong> Implement proper authentication for admin panel</li>
                    <li><strong>TODO:</strong> Remove hardcoded credentials from config files</li>
                    <li><strong>TODO:</strong> Fix SQL injection in search.php</li>
                    <li><strong>TODO:</strong> Secure file upload functionality</li>
                </ul>
                
                <h6 class="mt-4">Development Links:</h6>
                <ul>
                    <li><a href="config.txt">Database Configuration</a></li>
                    <li><a href="test_data.php">Test Data Generator</a></li>
                </ul>
                
                <div class="alert alert-warning mt-3">
                    <strong>Security Note:</strong> In a secure application, development directories would be:
                    <ul>
                        <li>Not deployed to production servers</li>
                        <li>Protected by access controls if they must exist</li>
                        <li>Sanitized of sensitive information</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
