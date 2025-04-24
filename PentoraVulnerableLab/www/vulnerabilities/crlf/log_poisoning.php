<?php
// CRLF Log Poisoning Vulnerability Example

// Get the username from the request
$username = isset($_GET['username']) ? $_GET['username'] : 'anonymous';

// Vulnerable code: directly logging user input without sanitization
file_put_contents('user_log.txt', date('Y-m-d H:i:s') . " - User activity: " . $username . "\n", FILE_APPEND);

// Create the log file if it doesn't exist
if (!file_exists('user_log.txt')) {
    file_put_contents('user_log.txt', "Log created on " . date('Y-m-d H:i:s') . "\n", FILE_APPEND);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Log Poisoning - Pentora Vulnerable Lab</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <div class="alert alert-success">
            <strong>Success!</strong> Activity for user '<?php echo htmlspecialchars($username); ?>' has been logged.
        </div>
        
        <div class="card">
            <div class="card-header">
                <h5>Log Contents</h5>
            </div>
            <div class="card-body">
                <pre><?php 
                    if (file_exists('user_log.txt')) {
                        // Vulnerable: Directly displaying log contents without sanitization
                        echo file_get_contents('user_log.txt');
                    } else {
                        echo "No log file found.";
                    }
                ?></pre>
            </div>
        </div>
        
        <a href="index.php" class="btn btn-primary mt-3">Back to CRLF Injection Tests</a>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
