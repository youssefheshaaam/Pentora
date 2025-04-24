<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>System Information</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>System Information</h1>
        
        <?php
        // Vulnerable command execution with attempted filtering
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['type'])) {
            $type = $_POST['type'];
            
            // Attempt to filter input (but still vulnerable)
            $type = str_replace(array('&', '|', ';'), '', $type);
            
            echo "<div class='alert alert-info'>";
            echo "Getting information for: <strong>" . htmlspecialchars($type) . "</strong>";
            echo "</div>";
            
            // Command mapping based on type
            $commands = array(
                'os' => "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\"",
                'cpu' => "wmic cpu get name, maxclockspeed, currentclockspeed",
                'memory' => "wmic memorychip get capacity, speed",
                'disk' => "wmic logicaldisk get caption, description, freespace, size"
            );
            
            // Check if type exists in our allowed commands
            if (array_key_exists($type, $commands)) {
                $command = $commands[$type];
                echo "<p>Executing command: <code>" . htmlspecialchars($command) . "</code></p>";
                
                // Execute the command and capture output
                $output = shell_exec($command);
                
                // Display the output
                echo "<pre class='bg-dark text-light p-3'>";
                echo htmlspecialchars($output);
                echo "</pre>";
            } else {
                echo "<div class='alert alert-danger'>Invalid information type selected.</div>";
            }
        } else {
            echo "<div class='alert alert-warning'>No information type specified.</div>";
        }
        ?>
        
        <div class="mt-3">
            <a href="index.php" class="btn btn-primary">Back to Command Execution Tests</a>
        </div>
    </div>
</body>
</html>
