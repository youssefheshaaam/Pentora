<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Website Status Check</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>Website Status Check</h1>
        
        <?php
        // Vulnerable blind command execution - directly using user input in a system command
        if (isset($_GET['url'])) {
            $url = $_GET['url'];
            
            echo "<div class='alert alert-info'>";
            echo "Checking website: <strong>" . htmlspecialchars($url) . "</strong>";
            echo "</div>";
            
            // Vulnerable code - direct command injection
            // This is a blind injection because we're not displaying the output
            $command = "curl -s -I " . $url . " > /dev/null 2>&1";
            
            // Start timer to demonstrate time-based blind injection
            $start_time = microtime(true);
            
            // Execute the command without capturing output
            system($command);
            
            // End timer
            $end_time = microtime(true);
            $execution_time = ($end_time - $start_time) * 1000; // Convert to milliseconds
            
            echo "<div class='alert alert-success'>";
            echo "Check completed in " . number_format($execution_time, 2) . " ms.";
            echo "</div>";
            
            echo "<p>The website appears to be online.</p>";
            
        } else {
            echo "<div class='alert alert-warning'>No URL specified.</div>";
        }
        ?>
        
        <div class="mt-3">
            <a href="index.php" class="btn btn-primary">Back to Command Execution Tests</a>
        </div>
    </div>
</body>
</html>
