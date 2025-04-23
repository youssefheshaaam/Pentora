<?php
// Vulnerable redirect implementation - no validation
if (isset($_GET['url'])) {
    $url = $_GET['url'];
    
    // Log the redirect attempt
    error_log("Redirect requested to: " . $url);
    
    // Perform the redirect without any validation
    header("Location: " . $url);
    exit;
} else {
    // If no URL specified, show an error
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
            <h4 class="alert-heading">Error!</h4>
            <p>No URL specified for redirect.</p>
        </div>
        
        <div class="mt-3">
            <a href="index.php" class="btn btn-primary">Back to Open Redirect Tests</a>
        </div>
    </div>
</body>
</html>
<?php
}
?>
