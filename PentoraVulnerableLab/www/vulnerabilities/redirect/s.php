<?php
// Short URL redirect handler
if (isset($_GET['c'])) {
    $short_code = $_GET['c'];
    
    // Connect to the database
    $db = new SQLite3('urls.db');
    
    // Look up the short code
    $stmt = $db->prepare("SELECT long_url FROM urls WHERE short_code = :code");
    $stmt->bindValue(':code', $short_code, SQLITE3_TEXT);
    $result = $stmt->execute();
    $row = $result->fetchArray(SQLITE3_ASSOC);
    
    if ($row) {
        $long_url = $row['long_url'];
        
        // Log the redirect
        error_log("Short URL redirect: {$short_code} -> {$long_url}");
        
        // Vulnerable redirect - no validation of the destination URL
        header("Location: " . $long_url);
        exit;
    } else {
        $error = "Short URL not found";
    }
} else {
    $error = "No short code specified";
}

// If we get here, there was an error
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>URL Shortener Error</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <div class="alert alert-danger">
            <h4 class="alert-heading">Error!</h4>
            <p><?php echo htmlspecialchars($error); ?></p>
        </div>
        
        <div class="mt-3">
            <a href="shortener.php" class="btn btn-primary">Back to URL Shortener</a>
        </div>
    </div>
</body>
</html>
