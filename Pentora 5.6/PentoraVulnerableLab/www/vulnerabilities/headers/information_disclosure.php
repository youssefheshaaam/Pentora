<?php
// HTTP Headers Vulnerability Example - Information Disclosure Headers

// Set headers that disclose sensitive information
header("X-Powered-By: PHP/7.4.3");
header("Server: Apache/2.4.41 (Ubuntu)");
header("X-AspNet-Version: 4.0.30319");
header("X-Runtime: 0.012345");
header("X-Backend-Server: web-server-01.internal.example.com");
header("X-Database: MySQL 8.0.27");
header("X-Environment: production");
header("X-Generator: WordPress 5.9.3");
header("X-App-Version: 2.5.1");
header("X-Instance-ID: i-0abc123def456789");
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Information Disclosure Headers - Pentora Vulnerable Lab</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>Information Disclosure Headers</h1>
        <div class="alert alert-danger">
            <strong>Warning:</strong> This page intentionally uses headers that disclose sensitive information for demonstration purposes.
        </div>

        <div class="row">
            <div class="col-md-6">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>Information Disclosure Headers</h5>
                    </div>
                    <div class="card-body">
                        <p>This page is sending the following headers that disclose sensitive information:</p>
                        <ul>
                            <li><code>X-Powered-By: PHP/7.4.3</code> - Reveals technology and version</li>
                            <li><code>Server: Apache/2.4.41 (Ubuntu)</code> - Reveals server software and version</li>
                            <li><code>X-AspNet-Version: 4.0.30319</code> - Reveals framework version</li>
                            <li><code>X-Runtime: 0.012345</code> - Reveals execution time (useful for timing attacks)</li>
                            <li><code>X-Backend-Server: web-server-01.internal.example.com</code> - Reveals internal hostname</li>
                            <li><code>X-Database: MySQL 8.0.27</code> - Reveals database technology and version</li>
                            <li><code>X-Environment: production</code> - Reveals deployment environment</li>
                            <li><code>X-Generator: WordPress 5.9.3</code> - Reveals CMS and version</li>
                            <li><code>X-App-Version: 2.5.1</code> - Reveals application version</li>
                            <li><code>X-Instance-ID: i-0abc123def456789</code> - Reveals cloud instance ID</li>
                        </ul>
                    </div>
                </div>
            </div>

            <div class="col-md-6">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>Security Risks</h5>
                    </div>
                    <div class="card-body">
                        <p>Disclosing this information poses several security risks:</p>
                        <ul>
                            <li><strong>Version Targeting:</strong> Attackers can find known vulnerabilities for specific versions</li>
                            <li><strong>Fingerprinting:</strong> Helps attackers build a profile of your technology stack</li>
                            <li><strong>Internal Information:</strong> Reveals internal hostnames, architecture, and infrastructure</li>
                            <li><strong>Timing Information:</strong> Can be used to develop timing-based attacks</li>
                        </ul>
                        <p>For example, if an attacker knows you're running PHP 7.4.3, they can look up CVEs specific to that version.</p>
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
                
                <div class="alert alert-info mt-3">
                    <strong>Note:</strong> Security scanners like Pentora specifically look for these types of information disclosure headers.
                </div>
            </div>
        </div>

        <div class="card mb-4">
            <div class="card-header">
                <h5>Secure Configuration</h5>
            </div>
            <div class="card-body">
                <p>To prevent information disclosure via headers:</p>
                <ol>
                    <li><strong>Remove or Obscure Technology Headers:</strong>
                        <ul>
                            <li>In PHP: <code>expose_php = Off</code> in php.ini</li>
                            <li>In Apache: <code>ServerTokens Prod</code> and <code>ServerSignature Off</code></li>
                            <li>In Nginx: <code>server_tokens off;</code></li>
                        </ul>
                    </li>
                    <li><strong>Custom Headers:</strong> Don't add custom headers that reveal internal information</li>
                    <li><strong>Web Application Firewalls:</strong> Configure to strip sensitive headers</li>
                    <li><strong>Framework Configuration:</strong> Most frameworks have options to disable version headers</li>
                </ol>
                <p>Example secure Apache configuration:</p>
                <pre class="bg-dark text-light p-3">
# /etc/apache2/apache2.conf or httpd.conf
ServerTokens Prod
ServerSignature Off

# In .htaccess
Header unset X-Powered-By
Header unset Server
                </pre>
            </div>
        </div>
        
        <a href="index.php" class="btn btn-secondary mb-4">Back to HTTP Headers Tests</a>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
