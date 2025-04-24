<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DNS Lookup Results</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>DNS Lookup Results</h1>
        
        <?php
        // Vulnerable command execution via POST - directly using user input in a system command
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['domain'])) {
            $domain = $_POST['domain'];
            
            echo "<div class='alert alert-info'>";
            echo "Looking up domain: <strong>" . htmlspecialchars($domain) . "</strong>";
            echo "</div>";
            
            // Vulnerable code - direct command injection
            $command = "nslookup " . $domain;
            echo "<p>Executing command: <code>" . htmlspecialchars($command) . "</code></p>";
            
            // Execute the command and capture output
            $output = shell_exec($command);
            
            // Display the output
            echo "<pre class='bg-dark text-light p-3'>";
            echo htmlspecialchars($output);
            echo "</pre>";
        } else {
            echo "<div class='alert alert-warning'>No domain specified.</div>";
        }
        ?>
        
        <div class="mt-3">
            <a href="index.php" class="btn btn-primary">Back to Command Execution Tests</a>
        </div>
    </div>
</body>
</html>
