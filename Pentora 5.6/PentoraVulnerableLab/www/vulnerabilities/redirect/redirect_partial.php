<?php
// Vulnerable redirect implementation with incomplete validation
if (isset($_GET['url'])) {
    $url = $_GET['url'];
    
    // Attempt to validate the URL (but with flaws)
    // This validation can be bypassed in multiple ways
    
    // Check 1: URL must start with http:// or https://
    if (preg_match('/^https?:\/\//i', $url)) {
        // Check 2: URL must not contain localhost or 127.0.0.1
        // This is easily bypassed with IP encoding, alternate representations, etc.
        if (!preg_match('/localhost|127\.0\.0\.1/i', $url)) {
            // Log the redirect attempt
            error_log("Partial validated redirect to: " . $url);
            
            // Perform the redirect
            header("Location: " . $url);
            exit;
        } else {
            $error = "Redirects to localhost are not allowed.";
        }
    } else {
        $error = "Invalid URL format. URL must start with http:// or https://";
    }
} else {
    $error = "No URL specified for redirect.";
}

// If we get here, there was an error
header("HTTP/1.1 400 Bad Request");
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Redirect Error</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <div class="alert alert-danger">
            <h4 class="alert-heading">Redirect Error!</h4>
            <p><?php echo htmlspecialchars($error); ?></p>
        </div>
        
        <div class="card mt-4">
            <div class="card-header">
                <h5>Validation Information</h5>
            </div>
            <div class="card-body">
                <p>The URL must meet the following criteria:</p>
                <ul>
                    <li>Must start with http:// or https://</li>
                    <li>Must not contain references to localhost or 127.0.0.1</li>
                </ul>
                <p class="text-muted">Note: This validation is intentionally flawed for demonstration purposes.</p>
            </div>
        </div>
        
        <div class="mt-3">
            <a href="index.php" class="btn btn-primary">Back to Open Redirect Tests</a>
        </div>
    </div>
</body>
</html>
