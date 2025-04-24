<?php
// HTTP Headers Vulnerability Example - Insecure Content Security Policy

// Set a weak/missing Content Security Policy
// This allows inline scripts and styles, and loading resources from any domain
header("Content-Security-Policy: default-src 'self' * 'unsafe-inline' 'unsafe-eval' data: blob:;");

// In some cases, no CSP header is set at all, which is even worse
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Insecure Content Security Policy - Pentora Vulnerable Lab</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    
    <!-- Inline style - allowed by the weak CSP -->
    <style>
        .red-text { color: red; }
        .blue-text { color: blue; }
    </style>
</head>
<body>
    <div class="container mt-5">
        <h1>Insecure Content Security Policy</h1>
        <div class="alert alert-danger">
            <strong>Warning:</strong> This page intentionally uses an insecure Content Security Policy for demonstration purposes.
        </div>

        <div class="row">
            <div class="col-md-6">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>Current CSP Header</h5>
                    </div>
                    <div class="card-body">
                        <p>This page is using the following weak Content Security Policy:</p>
                        <pre class="bg-dark text-light p-3">Content-Security-Policy: default-src 'self' * 'unsafe-inline' 'unsafe-eval' data: blob:;</pre>
                        <p>This policy has several security issues:</p>
                        <ul>
                            <li>Allows loading resources from any domain (<code>*</code>)</li>
                            <li>Allows inline scripts and styles (<code>'unsafe-inline'</code>)</li>
                            <li>Allows the use of <code>eval()</code> and similar functions (<code>'unsafe-eval'</code>)</li>
                            <li>Allows data: URIs which can be used for XSS</li>
                            <li>Uses a single directive (<code>default-src</code>) instead of specific ones</li>
                        </ul>
                    </div>
                </div>
            </div>

            <div class="col-md-6">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>XSS Vulnerability Demo</h5>
                    </div>
                    <div class="card-body">
                        <p>Due to the weak CSP, this page is vulnerable to XSS attacks:</p>
                        
                        <div class="mb-3">
                            <label for="user-input" class="form-label">Enter some text (try entering script tags):</label>
                            <input type="text" class="form-control" id="user-input" placeholder="<script>alert('XSS')</script>">
                            <button class="btn btn-primary mt-2" id="submit-button">Submit</button>
                        </div>
                        
                        <div class="alert alert-info mt-3">
                            <p>Output:</p>
                            <div id="output"></div>
                        </div>
                        
                        <div class="alert alert-warning">
                            <strong>Note:</strong> With a proper CSP, script injection would be blocked by the browser.
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="card mb-4">
            <div class="card-header">
                <h5>External Resource Loading</h5>
            </div>
            <div class="card-body">
                <p>The weak CSP also allows loading resources from any domain:</p>
                
                <div class="mb-3">
                    <label for="external-js-url" class="form-label">Enter URL of an external JavaScript file:</label>
                    <input type="text" class="form-control" id="external-js-url" value="https://example.com/potentially-malicious.js">
                    <button class="btn btn-primary mt-2" id="load-js-button">Load JavaScript</button>
                </div>
                
                <div id="external-js-status" class="mt-3"></div>
                
                <div class="alert alert-info mt-3">
                    <p>In a real attack scenario, this could load malicious JavaScript from an attacker's domain.</p>
                </div>
            </div>
        </div>

        <div class="card mb-4">
            <div class="card-header">
                <h5>Secure CSP Configuration</h5>
            </div>
            <div class="card-body">
                <p>A secure Content Security Policy would look like this:</p>
                <pre class="bg-dark text-light p-3">
Content-Security-Policy: 
    default-src 'none';
    script-src 'self' https://cdn.jsdelivr.net;
    style-src 'self' https://cdn.jsdelivr.net;
    img-src 'self';
    font-src 'self';
    connect-src 'self';
    frame-src 'none';
    object-src 'none';
    base-uri 'self';
    form-action 'self';
    frame-ancestors 'none';
    upgrade-insecure-requests;
                </pre>
                <p>Key security principles:</p>
                <ul>
                    <li>Use specific directives instead of just <code>default-src</code></li>
                    <li>Avoid <code>'unsafe-inline'</code> and <code>'unsafe-eval'</code></li>
                    <li>Explicitly specify trusted domains for each resource type</li>
                    <li>Use <code>'none'</code> for resource types you don't need</li>
                    <li>Consider using nonces or hashes for inline scripts if necessary</li>
                    <li>Include <code>upgrade-insecure-requests</code> to enforce HTTPS</li>
                    <li>Set <code>frame-ancestors 'none'</code> to prevent clickjacking</li>
                </ul>
            </div>
        </div>
        
        <a href="index.php" class="btn btn-secondary mb-4">Back to HTTP Headers Tests</a>
    </div>

    <!-- Inline script - allowed by the weak CSP -->
    <script>
        document.getElementById('submit-button').addEventListener('click', function() {
            const userInput = document.getElementById('user-input').value;
            document.getElementById('output').innerHTML = userInput;
        });
        
        document.getElementById('load-js-button').addEventListener('click', function() {
            const jsUrl = document.getElementById('external-js-url').value;
            const statusDiv = document.getElementById('external-js-status');
            
            statusDiv.innerHTML = `<div class="alert alert-info">Attempting to load JavaScript from: ${jsUrl}</div>`;
            
            const script = document.createElement('script');
            script.src = jsUrl;
            script.onerror = function() {
                statusDiv.innerHTML = `<div class="alert alert-danger">Failed to load JavaScript from: ${jsUrl}</div>`;
            };
            script.onload = function() {
                statusDiv.innerHTML = `<div class="alert alert-success">Successfully loaded JavaScript from: ${jsUrl}</div>`;
            };
            
            document.head.appendChild(script);
        });
    </script>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
