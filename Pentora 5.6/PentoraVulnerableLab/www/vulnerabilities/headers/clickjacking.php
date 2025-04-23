<?php
// HTTP Headers Vulnerability Example - Clickjacking (X-Frame-Options)

// Set insecure X-Frame-Options header or don't set it at all
// Uncomment one of these to test different scenarios:

// Insecure: Invalid X-Frame-Options value (not recognized by browsers)
header("X-Frame-Options: INVALID-VALUE");

// Insecure: No X-Frame-Options header at all
// This is the default if you don't set any header

// Secure: Prevents framing completely
// header("X-Frame-Options: DENY");

// Secure: Only allows framing from same origin
// header("X-Frame-Options: SAMEORIGIN");

// Secure: Only allows framing from specific domain
// header("X-Frame-Options: ALLOW-FROM https://trusted-site.com");

// Note: X-Frame-Options: ALLOW-FROM is deprecated in favor of CSP frame-ancestors
// A proper CSP would be:
// header("Content-Security-Policy: frame-ancestors 'self' https://trusted-site.com");
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Clickjacking Vulnerability - Pentora Vulnerable Lab</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .demo-frame {
            width: 100%;
            height: 300px;
            border: 2px solid #ccc;
        }
    </style>
</head>
<body>
    <div class="container mt-5">
        <h1>Clickjacking Vulnerability (X-Frame-Options)</h1>
        <div class="alert alert-danger">
            <strong>Warning:</strong> This page intentionally has insecure X-Frame-Options configuration for demonstration purposes.
        </div>

        <div class="row">
            <div class="col-md-6">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>Current X-Frame-Options</h5>
                    </div>
                    <div class="card-body">
                        <p>This page has the following X-Frame-Options header:</p>
                        <pre class="bg-dark text-light p-3">X-Frame-Options: INVALID-VALUE</pre>
                        <p>This is insecure because:</p>
                        <ul>
                            <li>It uses an invalid X-Frame-Options value that is not recognized by browsers</li>
                            <li>This makes the page vulnerable to clickjacking attacks</li>
                            <li>Invalid X-Frame-Options values can be used by attackers to bypass security measures</li>
                        </ul>
                        <p>In some cases, no X-Frame-Options header is set at all, which is equally insecure.</p>
                    </div>
                </div>
            </div>

            <div class="col-md-6">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>Vulnerable User Interface</h5>
                    </div>
                    <div class="card-body">
                        <p>This is a simulated sensitive action that could be targeted by clickjacking:</p>
                        <div class="alert alert-info">
                            <strong>Account Settings</strong>
                        </div>
                        <form action="#" method="POST" id="settings-form">
                            <div class="mb-3">
                                <label for="email" class="form-label">Email address:</label>
                                <input type="email" class="form-control" id="email" value="user@example.com">
                            </div>
                            <div class="mb-3">
                                <label for="password" class="form-label">New Password:</label>
                                <input type="password" class="form-control" id="password">
                            </div>
                            <button type="submit" class="btn btn-danger">Update Account</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>

        <div class="card mb-4">
            <div class="card-header">
                <h5>Clickjacking Attack Demo</h5>
            </div>
            <div class="card-body">
                <p>This demonstrates how a malicious site could embed this page in an iframe and trick users into clicking buttons they didn't intend to click:</p>
                
                <div class="mb-4">
                    <button class="btn btn-primary" id="toggle-demo">Show/Hide Clickjacking Demo</button>
                </div>
                
                <div id="demo-container" style="display: none;">
                    <div class="position-relative mb-4" style="width: 100%; height: 350px;">
                        <!-- Malicious overlay -->
                        <div class="position-absolute" style="z-index: 2; width: 100%; height: 100%; pointer-events: none;">
                            <div class="card">
                                <div class="card-header bg-success text-white">
                                    <h5>Win a Free Prize!</h5>
                                </div>
                                <div class="card-body">
                                    <p>Congratulations! You've been selected to win a free gift card!</p>
                                    <p>Click the "Claim Now" button below to receive your prize.</p>
                                    <div class="d-grid gap-2">
                                        <button class="btn btn-success" style="position: absolute; top: 245px; left: 120px; opacity: 0.0; pointer-events: none;">Claim Now</button>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Transparent iframe containing the vulnerable page -->
                        <iframe src="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>" class="position-absolute demo-frame" style="z-index: 1; opacity: 0.2;"></iframe>
                    </div>
                    
                    <div class="alert alert-warning">
                        <strong>How this works:</strong> The "Claim Now" button is positioned directly over the "Update Account" button in the transparent iframe. When a user thinks they're clicking "Claim Now", they're actually clicking "Update Account" in the iframe.
                    </div>
                </div>
            </div>
        </div>

        <div class="card mb-4">
            <div class="card-header">
                <h5>Secure Configuration</h5>
            </div>
            <div class="card-body">
                <p>To prevent clickjacking attacks, use one of these secure configurations:</p>
                
                <h6>Option 1: X-Frame-Options</h6>
                <pre class="bg-dark text-light p-3">
// Prevent framing completely
header("X-Frame-Options: DENY");

// Or, only allow framing from same origin
header("X-Frame-Options: SAMEORIGIN");
                </pre>
                
                <h6>Option 2: Content Security Policy (modern approach)</h6>
                <pre class="bg-dark text-light p-3">
// Prevent framing completely
header("Content-Security-Policy: frame-ancestors 'none';");

// Or, only allow framing from same origin
header("Content-Security-Policy: frame-ancestors 'self';");

// Or, only allow framing from specific domains
header("Content-Security-Policy: frame-ancestors 'self' https://trusted-site.com;");
                </pre>
                
                <div class="alert alert-info mt-3">
                    <strong>Note:</strong> CSP's frame-ancestors directive is more flexible and is replacing X-Frame-Options in modern browsers, but for maximum compatibility, it's recommended to use both.
                </div>
            </div>
        </div>
        
        <a href="index.php" class="btn btn-secondary mb-4">Back to HTTP Headers Tests</a>
    </div>

    <script>
        // Demo form submission handler
        document.getElementById('settings-form').addEventListener('submit', function(e) {
            e.preventDefault();
            alert('Form submitted! In a real attack, your account settings would have been changed.');
        });
        
        // Toggle demo visibility
        document.getElementById('toggle-demo').addEventListener('click', function() {
            const demoContainer = document.getElementById('demo-container');
            if (demoContainer.style.display === 'none') {
                demoContainer.style.display = 'block';
            } else {
                demoContainer.style.display = 'none';
            }
        });
    </script>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
