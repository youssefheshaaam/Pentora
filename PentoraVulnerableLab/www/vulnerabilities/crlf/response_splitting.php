<?php
// CRLF HTTP Response Splitting Vulnerability Example

// Get the language from the request
$lang = isset($_GET['lang']) ? $_GET['lang'] : 'en';

// Vulnerable code: directly using user input in a header
header("Content-Language: " . $lang);

// Set a cookie with the language preference
setcookie("language", $lang, time() + 3600, "/");
?>
<!DOCTYPE html>
<html lang="<?php echo htmlspecialchars($lang); ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HTTP Response Splitting - Pentora Vulnerable Lab</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <div class="alert alert-success">
            <strong>Success!</strong> Language preference set to: <?php echo htmlspecialchars($lang); ?>
        </div>
        
        <div class="card">
            <div class="card-header">
                <h5>Response Headers</h5>
            </div>
            <div class="card-body">
                <p>The following headers were sent in the response:</p>
                <pre>Content-Language: <?php echo htmlspecialchars($lang); ?>
Set-Cookie: language=<?php echo htmlspecialchars($lang); ?>; expires=<?php echo date('D, d M Y H:i:s', time() + 3600); ?> GMT; path=/</pre>
            </div>
        </div>
        
        <a href="index.php" class="btn btn-primary mt-3">Back to CRLF Injection Tests</a>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
