<?php
// Function to safely display command output
function displayOutput($output) {
    echo "<pre class='bg-dark text-light p-3 mt-3'>";
    if (empty($output)) {
        echo "No output or command failed.";
    } else {
        echo htmlspecialchars($output);
    }
    echo "</pre>";
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Command Execution Vulnerabilities</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>Command Execution Vulnerabilities</h1>
        <p class="lead">This page contains various command injection vulnerabilities for testing Pentora.</p>
        
        <div class="alert alert-danger">
            <strong>Warning:</strong> These examples demonstrate dangerous vulnerabilities. In a real application, never execute system commands with user input without proper validation and sanitization.
        </div>
        
        <div class="row mt-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>Basic Command Injection (GET)</h5>
                    </div>
                    <div class="card-body">
                        <p>Ping a host:</p>
                        <form action="ping.php" method="get" class="mb-3">
                            <div class="input-group">
                                <input type="text" name="host" class="form-control" placeholder="Enter hostname or IP">
                                <button type="submit" class="btn btn-primary">Ping</button>
                            </div>
                        </form>
                        <div class="alert alert-info">
                            <strong>Hint:</strong> Try <code>127.0.0.1 && dir</code> or <code>127.0.0.1 | whoami</code>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>Command Injection (POST)</h5>
                    </div>
                    <div class="card-body">
                        <p>DNS Lookup:</p>
                        <form action="dns.php" method="post">
                            <div class="mb-3">
                                <label for="domain" class="form-label">Domain Name</label>
                                <input type="text" name="domain" id="domain" class="form-control">
                            </div>
                            <button type="submit" class="btn btn-primary">Lookup</button>
                        </form>
                        <div class="alert alert-info mt-3">
                            <strong>Hint:</strong> Try <code>example.com; net user</code>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="row mt-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>Blind Command Injection</h5>
                    </div>
                    <div class="card-body">
                        <p>Check if a website is up:</p>
                        <form action="check.php" method="get">
                            <div class="input-group">
                                <input type="text" name="url" class="form-control" placeholder="Enter website URL">
                                <button type="submit" class="btn btn-primary">Check</button>
                            </div>
                        </form>
                        <div class="alert alert-info mt-3">
                            <strong>Hint:</strong> Try <code>example.com & ping -n 10 127.0.0.1</code> (notice the delay)
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>Command Injection with Filtering</h5>
                    </div>
                    <div class="card-body">
                        <p>Get system information:</p>
                        <form action="sysinfo.php" method="post">
                            <div class="mb-3">
                                <label class="form-label">Information Type</label>
                                <select name="type" class="form-select">
                                    <option value="os">Operating System</option>
                                    <option value="cpu">CPU Info</option>
                                    <option value="memory">Memory Info</option>
                                    <option value="disk">Disk Space</option>
                                </select>
                            </div>
                            <button type="submit" class="btn btn-primary">Get Info</button>
                        </form>
                        <div class="alert alert-info mt-3">
                            <strong>Hint:</strong> Try injecting commands by modifying the POST request
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
