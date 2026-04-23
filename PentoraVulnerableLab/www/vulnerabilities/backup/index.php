<?php
// Backup Files Vulnerability Example
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Backup Files - Pentora Vulnerable Lab</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>Backup Files Vulnerability</h1>
        <div class="alert alert-danger">
            <strong>Warning:</strong> This section demonstrates vulnerabilities related to backup files that may expose sensitive information.
        </div>

        <div class="row">
            <div class="col-md-6">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>Login Page</h5>
                    </div>
                    <div class="card-body">
                        <form action="login.php" method="POST">
                            <div class="mb-3">
                                <label for="username" class="form-label">Username:</label>
                                <input type="text" class="form-control" id="username" name="username" required>
                            </div>
                            <div class="mb-3">
                                <label for="password" class="form-label">Password:</label>
                                <input type="password" class="form-control" id="password" name="password" required>
                            </div>
                            <button type="submit" class="btn btn-primary">Login</button>
                        </form>
                    </div>
                </div>
            </div>

            <div class="col-md-6">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>Backup Files Vulnerability</h5>
                    </div>
                    <div class="card-body">
                        <p>This section demonstrates how backup files can expose sensitive information if left on a web server.</p>
                        <p>Common backup file extensions include:</p>
                        <ul>
                            <li><code>.bak</code></li>
                            <li><code>.backup</code></li>
                            <li><code>.old</code></li>
                            <li><code>.tmp</code></li>
                            <li><code>.swp</code></li>
                            <li><code>~</code> (tilde suffix)</li>
                            <li><code>.copy</code></li>
                            <li><code>.orig</code></li>
                        </ul>
                        <p>Try accessing these files:</p>
                        <ul>
                            <li><a href="login.php.bak" target="_blank">login.php.bak</a></li>
                            <li><a href="config.php.old" target="_blank">config.php.old</a></li>
                            <li><a href="database.yml.backup" target="_blank">database.yml.backup</a></li>
                            <li><a href=".config.php.swp" target="_blank">.config.php.swp</a></li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>

        <div class="card mb-4">
            <div class="card-header">
                <h5>About Backup Files Vulnerability</h5>
            </div>
            <div class="card-body">
                <p>Backup files vulnerability occurs when developers or systems create backup copies of files that remain accessible on the web server.</p>
                <p>These files can expose sensitive information such as:</p>
                <ul>
                    <li>Source code containing security vulnerabilities</li>
                    <li>Database credentials</li>
                    <li>API keys and tokens</li>
                    <li>Internal system paths</li>
                    <li>Authentication mechanisms</li>
                </ul>
                <p>To prevent this vulnerability:</p>
                <ul>
                    <li>Store backup files outside the web root directory</li>
                    <li>Use proper version control systems instead of creating backup files</li>
                    <li>Configure web servers to deny access to backup file extensions</li>
                    <li>Regularly scan for and remove backup files</li>
                </ul>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
