<?php
// Content Security Policy (CSP) Vulnerability Example

// Set a weak/misconfigured CSP header
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' *; style-src 'self' 'unsafe-inline';");

// Vulnerable CSP configurations:
// 1. 'unsafe-inline' allows inline scripts
// 2. Wildcard (*) in script-src allows loading scripts from any domain
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Content Security Policy - Pentora Vulnerable Lab</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>Content Security Policy (CSP) Vulnerabilities</h1>
        <div class="alert alert-danger">
            <strong>Warning:</strong> This page intentionally demonstrates misconfigured Content Security Policies.
        </div>

        <div class="row">
            <div class="col-md-6">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>Unsafe Inline Scripts</h5>
                    </div>
                    <div class="card-body">
                        <p>This page allows inline scripts due to the 'unsafe-inline' directive:</p>
                        <button class="btn btn-primary" onclick="alert('This inline JavaScript execution should be blocked by a proper CSP')">
                            Click Me (Inline JavaScript)
                        </button>
                    </div>
                </div>
            </div>

            <div class="col-md-6">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>External Script from Any Domain</h5>
                    </div>
                    <div class="card-body">
                        <p>This page allows loading scripts from any domain due to the wildcard (*) in script-src:</p>
                        <div id="external-script-result">Loading external script...</div>
                        <script>
                            // Simulate loading an external script
                            document.getElementById('external-script-result').innerHTML = 
                                'Successfully loaded script from external domain (simulated)';
                        </script>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-md-12">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>CSP Header Information</h5>
                    </div>
                    <div class="card-body">
                        <p>This page sets the following CSP header:</p>
                        <pre class="bg-light p-3">Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' *; style-src 'self' 'unsafe-inline';</pre>
                        
                        <h6 class="mt-4">Vulnerabilities:</h6>
                        <ul>
                            <li><strong>'unsafe-inline'</strong> - Allows execution of inline scripts, which can be exploited in XSS attacks</li>
                            <li><strong>Wildcard (*) in script-src</strong> - Allows loading scripts from any domain, potentially enabling attackers to load malicious scripts</li>
                        </ul>
                        
                        <h6 class="mt-4">Secure CSP Example:</h6>
                        <pre class="bg-light p-3">Content-Security-Policy: default-src 'self'; script-src 'self' nonce-{random-nonce}; style-src 'self';</pre>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
