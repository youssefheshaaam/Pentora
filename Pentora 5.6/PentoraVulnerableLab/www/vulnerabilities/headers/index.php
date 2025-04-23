<?php
// HTTP Headers Vulnerability Example

// Set some insecure headers for demonstration
header("X-Powered-By: PHP/7.4.3");
header("Server: Apache/2.4.41 (Ubuntu)");
header("X-AspNet-Version: 4.0.30319");
header("X-Frame-Options: ALLOWALL");
header("Access-Control-Allow-Origin: *");

// Missing important security headers:
// - Content-Security-Policy
// - Strict-Transport-Security
// - X-Content-Type-Options
// - X-XSS-Protection
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HTTP Headers - Pentora Vulnerable Lab</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>HTTP Headers Vulnerability</h1>
        <div class="alert alert-danger">
            <strong>Warning:</strong> This page intentionally uses insecure HTTP headers for demonstration purposes.
        </div>

        <div class="row">
            <div class="col-md-6">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>Current Headers</h5>
                    </div>
                    <div class="card-body">
                        <p>This page is sending the following insecure headers:</p>
                        <ul>
                            <li><code>X-Powered-By: PHP/7.4.3</code> - Reveals technology information</li>
                            <li><code>Server: Apache/2.4.41 (Ubuntu)</code> - Reveals server information</li>
                            <li><code>X-AspNet-Version: 4.0.30319</code> - Reveals framework version</li>
                            <li><code>X-Frame-Options: ALLOWALL</code> - Allows framing from any domain</li>
                            <li><code>Access-Control-Allow-Origin: *</code> - Allows cross-origin requests from any domain</li>
                        </ul>
                        <p>Additionally, the following important security headers are missing:</p>
                        <ul>
                            <li><code>Content-Security-Policy</code> - Prevents XSS and data injection attacks</li>
                            <li><code>Strict-Transport-Security</code> - Enforces HTTPS connections</li>
                            <li><code>X-Content-Type-Options</code> - Prevents MIME-sniffing</li>
                            <li><code>X-XSS-Protection</code> - Enables browser's XSS filtering</li>
                        </ul>
                    </div>
                </div>
            </div>

            <div class="col-md-6">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>Test Different Header Configurations</h5>
                    </div>
                    <div class="card-body">
                        <p>Click the links below to see different header configurations:</p>
                        <div class="list-group">
                            <a href="insecure_cors.php" class="list-group-item list-group-item-action">Insecure CORS Headers</a>
                            <a href="insecure_csp.php" class="list-group-item list-group-item-action">Missing/Weak Content Security Policy</a>
                            <a href="information_disclosure.php" class="list-group-item list-group-item-action">Information Disclosure Headers</a>
                            <a href="clickjacking.php" class="list-group-item list-group-item-action">Clickjacking Vulnerability (X-Frame-Options)</a>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="card mb-4">
            <div class="card-header">
                <h5>View Response Headers</h5>
            </div>
            <div class="card-body">
                <p>You can view the response headers of this page using browser developer tools:</p>
                <ol>
                    <li>Right-click on the page and select "Inspect" or press F12</li>
                    <li>Go to the "Network" tab</li>
                    <li>Refresh the page</li>
                    <li>Click on the first item (usually the HTML document)</li>
                    <li>Look at the "Headers" tab, specifically the "Response Headers" section</li>
                </ol>
                <p>Or you can use tools like curl:</p>
                <pre>curl -I <?php echo htmlspecialchars("http://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']); ?></pre>
            </div>
        </div>

        <div class="card mb-4">
            <div class="card-header">
                <h5>About HTTP Headers Vulnerability</h5>
            </div>
            <div class="card-body">
                <p>HTTP Headers vulnerabilities occur when:</p>
                <ul>
                    <li>Security-related headers are missing or misconfigured</li>
                    <li>Headers reveal sensitive information about the server or application</li>
                    <li>Cross-Origin Resource Sharing (CORS) headers are too permissive</li>
                </ul>
                <p>Common security issues include:</p>
                <ul>
                    <li><strong>Information Disclosure:</strong> Headers like Server, X-Powered-By reveal technology stack details</li>
                    <li><strong>Clickjacking:</strong> Missing or weak X-Frame-Options header</li>
                    <li><strong>Cross-Site Scripting (XSS):</strong> Missing Content-Security-Policy or X-XSS-Protection</li>
                    <li><strong>MIME Sniffing:</strong> Missing X-Content-Type-Options: nosniff</li>
                    <li><strong>HTTPS Downgrade:</strong> Missing Strict-Transport-Security header</li>
                    <li><strong>Cross-Origin Issues:</strong> Overly permissive CORS headers</li>
                </ul>
                <p>To secure HTTP headers:</p>
                <ul>
                    <li>Remove or obscure technology information headers</li>
                    <li>Implement all recommended security headers</li>
                    <li>Use restrictive CORS policies</li>
                    <li>Regularly audit and test header configurations</li>
                </ul>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
