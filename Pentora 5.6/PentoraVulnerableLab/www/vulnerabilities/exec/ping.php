<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ping Results</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>Ping Results</h1>
        
        <?php
        // Vulnerable command execution - directly using user input in a system command
        if (isset($_GET['host'])) {
            $host = $_GET['host'];
            
            echo "<div class='alert alert-info'>";
            echo "Pinging host: <strong>" . htmlspecialchars($host) . "</strong>";
            echo "</div>";
            
            // Vulnerable code - direct command injection
            $command = "ping -n 3 " . $host;
            echo "<p>Executing command: <code>" . htmlspecialchars($command) . "</code></p>";
            
            // Execute the command and capture output
            $output = shell_exec($command);
            
            // Display the output
            echo "<pre class='bg-dark text-light p-3'>";
            echo htmlspecialchars($output);
            echo "</pre>";
        } else {
            echo "<div class='alert alert-warning'>No host specified.</div>";
        }
        ?>
        
        <div class="mt-3">
            <a href="index.php" class="btn btn-primary">Back to Command Execution Tests</a>
        </div>
    </div>
</body>
</html>
