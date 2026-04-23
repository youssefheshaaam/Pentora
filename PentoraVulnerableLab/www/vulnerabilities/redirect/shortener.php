<?php
// Create a database for storing shortened URLs if it doesn't exist
$db_file = 'urls.db';
$init_db = !file_exists($db_file);

$db = new SQLite3($db_file);

// Create table if it doesn't exist
if ($init_db) {
    $db->exec('CREATE TABLE urls (id INTEGER PRIMARY KEY, short_code TEXT, long_url TEXT, created_at TEXT)');
}

// Function to generate a random short code
function generateShortCode($length = 6) {
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $code = '';
    for ($i = 0; $i < $length; $i++) {
        $code .= $chars[rand(0, strlen($chars) - 1)];
    }
    return $code;
}

// Handle URL shortening
$short_url = '';
$error = '';
$success = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['long_url'])) {
    $long_url = $_POST['long_url'];
    
    // Basic URL validation (very minimal)
    if (filter_var($long_url, FILTER_VALIDATE_URL)) {
        // Generate a unique short code
        $short_code = generateShortCode();
        
        // Check if the code already exists (unlikely but possible)
        $stmt = $db->prepare("SELECT id FROM urls WHERE short_code = :code");
        $stmt->bindValue(':code', $short_code, SQLITE3_TEXT);
        $result = $stmt->execute();
        
        if ($result->fetchArray(SQLITE3_ASSOC)) {
            // If it exists, generate a new one
            $short_code = generateShortCode(8);
        }
        
        // Insert the URL into the database
        $stmt = $db->prepare("INSERT INTO urls (short_code, long_url, created_at) VALUES (:code, :url, :created)");
        $stmt->bindValue(':code', $short_code, SQLITE3_TEXT);
        $stmt->bindValue(':url', $long_url, SQLITE3_TEXT);
        $stmt->bindValue(':created', date('Y-m-d H:i:s'), SQLITE3_TEXT);
        $result = $stmt->execute();
        
        if ($result) {
            // Build the short URL
            $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
            $host = $_SERVER['HTTP_HOST'];
            $path = dirname($_SERVER['PHP_SELF']);
            $short_url = "$protocol://$host$path/s.php?c=$short_code";
            $success = true;
        } else {
            $error = "Failed to create short URL. Please try again.";
        }
    } else {
        $error = "Invalid URL format. Please enter a valid URL.";
    }
}

// Get recent URLs for display
$recent_urls = [];
$results = $db->query("SELECT short_code, long_url, created_at FROM urls ORDER BY id DESC LIMIT 5");
while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
    $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'];
    $path = dirname($_SERVER['PHP_SELF']);
    $row['short_url'] = "$protocol://$host$path/s.php?c=" . $row['short_code'];
    $recent_urls[] = $row;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>URL Shortener</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>URL Shortener</h1>
        <p class="lead">Create shortened URLs that redirect to your destination.</p>
        
        <div class="alert alert-danger">
            <strong>Warning:</strong> This URL shortener is intentionally vulnerable to open redirect attacks.
        </div>
        
        <?php if ($error): ?>
            <div class="alert alert-danger">
                <?php echo htmlspecialchars($error); ?>
            </div>
        <?php endif; ?>
        
        <?php if ($success): ?>
            <div class="alert alert-success">
                <h4 class="alert-heading">URL Shortened Successfully!</h4>
                <p>Your shortened URL is:</p>
                <div class="input-group mb-3">
                    <input type="text" class="form-control" value="<?php echo htmlspecialchars($short_url); ?>" id="shortUrl" readonly>
                    <button class="btn btn-outline-secondary" type="button" onclick="copyToClipboard()">Copy</button>
                </div>
                <p class="mb-0">Share this URL with others to redirect them to your original URL.</p>
            </div>
        <?php endif; ?>
        
        <div class="card">
            <div class="card-header">
                <h5>Shorten a URL</h5>
            </div>
            <div class="card-body">
                <form action="shortener.php" method="post">
                    <div class="mb-3">
                        <label for="long_url" class="form-label">URL to Shorten</label>
                        <input type="url" name="long_url" id="long_url" class="form-control" placeholder="https://example.com" required>
                    </div>
                    <button type="submit" class="btn btn-primary">Create Short URL</button>
                </form>
            </div>
        </div>
        
        <?php if (!empty($recent_urls)): ?>
            <div class="card mt-4">
                <div class="card-header">
                    <h5>Recent Shortened URLs</h5>
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-striped">
                            <thead>
                                <tr>
                                    <th>Short URL</th>
                                    <th>Original URL</th>
                                    <th>Created</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($recent_urls as $url): ?>
                                    <tr>
                                        <td><a href="<?php echo htmlspecialchars($url['short_url']); ?>" target="_blank"><?php echo htmlspecialchars($url['short_url']); ?></a></td>
                                        <td><?php echo htmlspecialchars(strlen($url['long_url']) > 50 ? substr($url['long_url'], 0, 50) . '...' : $url['long_url']); ?></td>
                                        <td><?php echo htmlspecialchars($url['created_at']); ?></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        <?php endif; ?>
        
        <div class="mt-4">
            <a href="index.php" class="btn btn-secondary">Back to Open Redirect Tests</a>
        </div>
    </div>
    
    <script>
        function copyToClipboard() {
            var copyText = document.getElementById("shortUrl");
            copyText.select();
            copyText.setSelectionRange(0, 99999);
            document.execCommand("copy");
            alert("Copied the URL: " + copyText.value);
        }
    </script>
</body>
</html>
