<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pentora Vulnerable Lab</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { padding-top: 20px; }
        .vulnerability-card { margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <header class="text-center mb-5">
            <img src="assets/images/Pentora_logo.png" alt="Pentora Logo" class="img-fluid mb-3" style="max-width: 200px;">
            <h1>Pentora Vulnerable Lab</h1>
            <p class="lead">A testing environment containing vulnerabilities that Pentora scans for</p>
        </header>

        <div class="row">
            <div class="col-md-12">
                <div class="alert alert-warning">
                    <strong>Warning:</strong> This application intentionally contains security vulnerabilities for testing purposes.
                    Do not deploy this in a production environment or expose it to the internet.
                </div>
            </div>
        </div>

        <div class="row">
            <?php
            $vulnerabilities = [
                [
                    'name' => 'SQL Injection',
                    'description' => 'Test SQL injection vulnerabilities',
                    'link' => 'vulnerabilities/sql/',
                    'icon' => 'database'
                ],
                [
                    'name' => 'Time-based SQL Injection',
                    'description' => 'Test time-based SQL injection vulnerabilities',
                    'link' => 'vulnerabilities/timesql/',
                    'icon' => 'hourglass-split'
                ],
                [
                    'name' => 'XSS (Cross-Site Scripting)',
                    'description' => 'Test reflected XSS vulnerabilities',
                    'link' => 'vulnerabilities/xss/',
                    'icon' => 'code'
                ],
                [
                    'name' => 'Persistent XSS',
                    'description' => 'Test stored/persistent XSS vulnerabilities',
                    'link' => 'vulnerabilities/permanentxss/',
                    'icon' => 'pin-angle'
                ],
                [
                    'name' => 'Command Execution',
                    'description' => 'Test command injection vulnerabilities',
                    'link' => 'vulnerabilities/exec/',
                    'icon' => 'terminal'
                ],
                [
                    'name' => 'File Upload',
                    'description' => 'Test insecure file upload vulnerabilities',
                    'link' => 'vulnerabilities/upload/',
                    'icon' => 'file-arrow-up'
                ],
                [
                    'name' => 'XXE',
                    'description' => 'Test XML external entity vulnerabilities',
                    'link' => 'vulnerabilities/xxe/',
                    'icon' => 'file-code'
                ],
                [
                    'name' => 'CSRF',
                    'description' => 'Test cross-site request forgery vulnerabilities',
                    'link' => 'vulnerabilities/csrf/',
                    'icon' => 'shield-exclamation'
                ],
                [
                    'name' => 'Path Traversal',
                    'description' => 'Test directory traversal vulnerabilities',
                    'link' => 'vulnerabilities/traversal/',
                    'icon' => 'folder-symlink'
                ],
                [
                    'name' => 'Open Redirect',
                    'description' => 'Test open redirect vulnerabilities',
                    'link' => 'vulnerabilities/redirect/',
                    'icon' => 'box-arrow-right'
                ],
                [
                    'name' => 'CRLF Injection',
                    'description' => 'Test CRLF injection vulnerabilities',
                    'link' => 'vulnerabilities/crlf/',
                    'icon' => 'arrow-return-right'
                ],
                [
                    'name' => 'HTTP Headers',
                    'description' => 'Test HTTP header security issues',
                    'link' => 'vulnerabilities/headers/',
                    'icon' => 'list-columns'
                ],
                [
                    'name' => 'LDAP Injection',
                    'description' => 'Test LDAP injection vulnerabilities',
                    'link' => 'vulnerabilities/ldap/',
                    'icon' => 'diagram-3'
                ],
                [
                    'name' => 'Shellshock',
                    'description' => 'Test Bash Shellshock vulnerability (CVE-2014-6271)',
                    'link' => 'vulnerabilities/shellshock/',
                    'icon' => 'terminal-fill'
                ],
                [
                    'name' => 'HTTP Methods',
                    'description' => 'Test HTTP method security issues',
                    'link' => 'vulnerabilities/methods/',
                    'icon' => 'arrow-left-right'
                ],
                [
                    'name' => 'Backup Files',
                    'description' => 'Test for exposed backup files',
                    'link' => 'vulnerabilities/backup/',
                    'icon' => 'file-earmark-zip'
                ],
                [
                    'name' => 'Content Security Policy',
                    'description' => 'Test CSP header configurations',
                    'link' => 'vulnerabilities/csp/',
                    'icon' => 'shield'
                ],
                [
                    'name' => 'Brute Force Login',
                    'description' => 'Test login form brute force protection',
                    'link' => 'vulnerabilities/brute_login_form/',
                    'icon' => 'key'
                ],
                [
                    'name' => 'Directory Buster',
                    'description' => 'Test for hidden directories and files',
                    'link' => 'vulnerabilities/buster/',
                    'icon' => 'folder-symlink'
                ],

            ];
            
            foreach ($vulnerabilities as $vulnerability) {
                echo '<div class="col-md-4">';
                echo '<div class="card vulnerability-card">';
                echo '<div class="card-body">';
                echo '<h5 class="card-title"><i class="bi bi-' . $vulnerability['icon'] . '"></i> ' . $vulnerability['name'] . '</h5>';
                echo '<p class="card-text">' . $vulnerability['description'] . '</p>';
                echo '<a href="' . $vulnerability['link'] . '" class="btn btn-primary">Test ' . $vulnerability['name'] . '</a>';
                echo '</div>';
                echo '</div>';
                echo '</div>';
            }
            ?>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
</body>
</html>
