<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Profile Picture</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>Profile Picture</h1>
        
        <?php
        // Vulnerable XSS in HTML attributes - directly inserting user input into an attribute
        if (isset($_GET['image_url'])) {
            $image_url = $_GET['image_url'];
            
            echo "<div class='card'>";
            echo "<div class='card-header'>Your Profile Picture</div>";
            echo "<div class='card-body text-center'>";
            // Vulnerable code - directly inserting user input into an HTML attribute
            echo "<img src='" . $image_url . "' alt='Profile Picture' style='max-width: 300px; max-height: 300px;'>";
            echo "</div>";
            echo "</div>";
        } else {
            echo "<div class='alert alert-warning'>No image URL provided.</div>";
        }
        ?>
        
        <div class="mt-3">
            <a href="index.php" class="btn btn-primary">Back to XSS Tests</a>
        </div>
    </div>
</body>
</html>
