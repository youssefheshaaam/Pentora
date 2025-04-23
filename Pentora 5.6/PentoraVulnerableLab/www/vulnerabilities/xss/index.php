<?php
// Initialize the database for stored XSS
$db_file = 'comments.db';
$init_db = !file_exists($db_file);

$db = new SQLite3($db_file);

// Create tables if they don't exist
if ($init_db) {
    $db->exec('CREATE TABLE comments (id INTEGER PRIMARY KEY, name TEXT, comment TEXT, date TEXT)');
    $db->exec("INSERT INTO comments (name, comment, date) VALUES 
        ('Admin', 'Welcome to our vulnerable comment system!', '2025-03-14'),
        ('User1', 'This is a test comment.', '2025-03-14')");
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XSS Vulnerabilities</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>XSS (Cross-Site Scripting) Vulnerabilities</h1>
        <p class="lead">This page contains various XSS vulnerabilities for testing Pentora.</p>
        
        <div class="row mt-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>Reflected XSS (GET)</h5>
                    </div>
                    <div class="card-body">
                        <p>Search for something:</p>
                        <form action="reflected_get.php" method="get" class="mb-3">
                            <div class="input-group">
                                <input type="text" name="query" class="form-control" placeholder="Enter search term">
                                <button type="submit" class="btn btn-primary">Search</button>
                            </div>
                        </form>
                        <div class="alert alert-info">
                            <strong>Hint:</strong> Try <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>Reflected XSS (POST)</h5>
                    </div>
                    <div class="card-body">
                        <p>Submit your feedback:</p>
                        <form action="reflected_post.php" method="post">
                            <div class="mb-3">
                                <label for="name" class="form-label">Your Name</label>
                                <input type="text" name="name" id="name" class="form-control">
                            </div>
                            <div class="mb-3">
                                <label for="feedback" class="form-label">Feedback</label>
                                <textarea name="feedback" id="feedback" class="form-control" rows="3"></textarea>
                            </div>
                            <button type="submit" class="btn btn-primary">Submit Feedback</button>
                        </form>
                        <div class="alert alert-info mt-3">
                            <strong>Hint:</strong> Try <code>&lt;img src="x" onerror="alert('XSS')"&gt;</code>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="row mt-4">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header">
                        <h5>Stored XSS (Comment System)</h5>
                    </div>
                    <div class="card-body">
                        <h6>Leave a Comment</h6>
                        <form action="stored.php" method="post" class="mb-4">
                            <div class="mb-3">
                                <label for="comment_name" class="form-label">Your Name</label>
                                <input type="text" name="name" id="comment_name" class="form-control">
                            </div>
                            <div class="mb-3">
                                <label for="comment_text" class="form-label">Comment</label>
                                <textarea name="comment" id="comment_text" class="form-control" rows="3"></textarea>
                            </div>
                            <button type="submit" class="btn btn-primary">Post Comment</button>
                        </form>
                        
                        <h6>Comments</h6>
                        <?php
                        $results = $db->query("SELECT * FROM comments ORDER BY id DESC");
                        
                        while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
                            echo "<div class='card mb-2'>";
                            echo "<div class='card-body'>";
                            echo "<h6 class='card-subtitle mb-2 text-muted'>Posted by: " . $row['name'] . " on " . $row['date'] . "</h6>";
                            echo "<p class='card-text'>" . $row['comment'] . "</p>";
                            echo "</div>";
                            echo "</div>";
                        }
                        ?>
                        
                        <div class="alert alert-info mt-3">
                            <strong>Hint:</strong> Try <code>&lt;script&gt;document.cookie&lt;/script&gt;</code> in your comment
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="row mt-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>DOM-Based XSS</h5>
                    </div>
                    <div class="card-body">
                        <p>Change the page theme:</p>
                        <div class="mb-3">
                            <select id="theme" class="form-select">
                                <option value="light">Light Theme</option>
                                <option value="dark">Dark Theme</option>
                                <option value="blue">Blue Theme</option>
                            </select>
                        </div>
                        <button id="apply_theme" class="btn btn-primary">Apply Theme</button>
                        
                        <div id="theme_output" class="mt-3"></div>
                        
                        <div class="alert alert-info mt-3">
                            <strong>Hint:</strong> Try adding <code>#&lt;img src=x onerror=alert('DOM XSS')&gt;</code> to the URL
                        </div>
                        
                        <script>
                            // Vulnerable DOM-based XSS
                            document.getElementById('apply_theme').addEventListener('click', function() {
                                var theme = document.getElementById('theme').value;
                                document.getElementById('theme_output').innerHTML = "Theme set to: " + theme;
                            });
                            
                            // Extract the theme from the URL fragment
                            function loadThemeFromHash() {
                                if(window.location.hash) {
                                    // Vulnerable code - directly inserting hash value into the DOM
                                    var theme = window.location.hash.substring(1);
                                    document.getElementById('theme_output').innerHTML = "Theme loaded from URL: " + theme;
                                }
                            }
                            
                            // Call when page loads
                            window.onload = loadThemeFromHash;
                            // Call when hash changes
                            window.addEventListener('hashchange', loadThemeFromHash);
                        </script>
                    </div>
                </div>
            </div>
            
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>XSS in HTML Attributes</h5>
                    </div>
                    <div class="card-body">
                        <p>Set your profile picture URL:</p>
                        <form action="attribute.php" method="get">
                            <div class="mb-3">
                                <input type="text" name="image_url" class="form-control" placeholder="Enter image URL">
                            </div>
                            <button type="submit" class="btn btn-primary">Set Profile Picture</button>
                        </form>
                        <div class="alert alert-info mt-3">
                            <strong>Hint:</strong> Try <code>" onerror="alert('XSS')</code>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="mt-4">
            <a href="../../index.php" class="btn btn-secondary">Back to Home</a>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
