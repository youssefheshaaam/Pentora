<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Search Results</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>Search Results</h1>
        
        <?php
        // Vulnerable reflected XSS - directly outputting user input without sanitization
        if (isset($_GET['query'])) {
            $query = $_GET['query'];
            
            echo "<div class='alert alert-info'>";
            echo "You searched for: " . $query;
            echo "</div>";
            
            // Simulate search results
            echo "<p>No results found for your search.</p>";
        } else {
            echo "<div class='alert alert-warning'>No search query provided.</div>";
        }
        ?>
        
        <div class="mt-3">
            <a href="index.php" class="btn btn-primary">Back to XSS Tests</a>
        </div>
    </div>
</body>
</html>
