<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Feedback Submitted</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>Feedback Submitted</h1>
        
        <?php
        // Vulnerable reflected XSS via POST - directly outputting user input without sanitization
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $name = $_POST['name'];
            $feedback = $_POST['feedback'];
            
            echo "<div class='card'>";
            echo "<div class='card-header'>Feedback from: " . $name . "</div>";
            echo "<div class='card-body'>";
            echo "<p class='card-text'>" . $feedback . "</p>";
            echo "</div>";
            echo "</div>";
            
            echo "<div class='alert alert-success mt-3'>Thank you for your feedback!</div>";
        } else {
            echo "<div class='alert alert-warning'>No feedback submitted.</div>";
        }
        ?>
        
        <div class="mt-3">
            <a href="index.php" class="btn btn-primary">Back to XSS Tests</a>
        </div>
    </div>
</body>
</html>
