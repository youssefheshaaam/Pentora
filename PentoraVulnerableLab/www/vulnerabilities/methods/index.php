<?php
// HTTP Methods Vulnerability Example

// Get the current request method
$method = $_SERVER['REQUEST_METHOD'];

// Set the Allow header for all requests to make the vulnerability detectable
// This header tells clients which HTTP methods are allowed on this endpoint
header('Allow: GET, POST, PUT, DELETE, OPTIONS, TRACE, PATCH, CONNECT');

// For OPTIONS requests, we need to respond with a 200 OK status and no content
if ($method === 'OPTIONS') {
    // Set status code to 200 OK
    http_response_code(200);
    // No content needed for OPTIONS response
    exit;
}

// Handle different HTTP methods
$response = '';
switch ($method) {
    case 'GET':
        $response = "This is a normal GET request.";
        break;
    case 'POST':
        $response = "You sent a POST request.";
        break;
    case 'PUT':
        $response = "You sent a PUT request. In a real application, this might update a resource.";
        break;
    case 'DELETE':
        $response = "You sent a DELETE request. In a real application, this might delete a resource.";
        break;
    case 'TRACE':
        // For TRACE requests, echo back all received headers to simulate the vulnerability
        $response = "You sent a TRACE request. Here are the headers you sent:\n\n";
        foreach (getallheaders() as $name => $value) {
            $response .= "$name: $value\n";
        }
        break;
    default:
        $response = "You sent a $method request.";
        break;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HTTP Methods - Pentora Vulnerable Lab</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>HTTP Methods Vulnerability</h1>
        <div class="alert alert-danger">
            <strong>Warning:</strong> This page intentionally allows dangerous HTTP methods for testing purposes.
        </div>

        <div class="row">
            <div class="col-md-6">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>Current Request</h5>
                    </div>
                    <div class="card-body">
                        <p><strong>Method:</strong> <?php echo htmlspecialchars($method); ?></p>
                        <p><strong>Response:</strong> <?php echo htmlspecialchars($response); ?></p>
                    </div>
                </div>
            </div>

            <div class="col-md-6">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>Test Different Methods</h5>
                    </div>
                    <div class="card-body">
                        <p>Use the buttons below to test different HTTP methods:</p>
                        
                        <div class="d-grid gap-2">
                            <button class="btn btn-primary" onclick="sendRequest('GET')">GET</button>
                            <button class="btn btn-primary" onclick="sendRequest('POST')">POST</button>
                            <button class="btn btn-warning" onclick="sendRequest('PUT')">PUT</button>
                            <button class="btn btn-warning" onclick="sendRequest('DELETE')">DELETE</button>
                            <button class="btn btn-danger" onclick="sendRequest('OPTIONS')">OPTIONS</button>
                            <button class="btn btn-danger" onclick="sendRequest('TRACE')">TRACE</button>
                        </div>
                        
                        <div class="mt-3">
                            <p>You can also use tools like curl to test methods:</p>
                            <pre>curl -X PUT <?php echo htmlspecialchars("http://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']); ?></pre>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="card mb-4">
            <div class="card-header">
                <h5>Admin Panel (Method-Based Access Control)</h5>
            </div>
            <div class="card-body">
                <p>This admin panel is vulnerable because it only checks if the request method is POST, but doesn't properly authenticate users.</p>
                
                <a href="admin_panel.php" class="btn btn-secondary">View Admin Panel</a>
            </div>
        </div>

        <div class="card mb-4">
            <div class="card-header">
                <h5>About HTTP Methods Vulnerability</h5>
            </div>
            <div class="card-body">
                <p>HTTP Methods vulnerabilities occur when a web server allows dangerous HTTP methods that should be restricted.</p>
                <p>Common security issues include:</p>
                <ul>
                    <li><strong>PUT/DELETE:</strong> Can allow unauthorized file uploads or deletion if not properly secured</li>
                    <li><strong>TRACE/TRACK:</strong> Can enable Cross-Site Tracing (XST) attacks</li>
                    <li><strong>OPTIONS:</strong> Can reveal supported methods, helping attackers plan further attacks</li>
                    <li><strong>Method-based access control:</strong> Relying only on HTTP method for access control is insecure</li>
                </ul>
                <p>To prevent these vulnerabilities, web servers should:</p>
                <ul>
                    <li>Disable unnecessary HTTP methods</li>
                    <li>Implement proper authentication and authorization for all endpoints</li>
                    <li>Use proper CORS headers to restrict cross-origin requests</li>
                </ul>
            </div>
        </div>
    </div>

    <script>
        function sendRequest(method) {
            const xhr = new XMLHttpRequest();
            xhr.open(method, window.location.href, true);
            xhr.onload = function() {
                // Reload the page to show the response
                window.location.reload();
            };
            xhr.onerror = function() {
                alert('Error sending ' + method + ' request');
            };
            xhr.send();
        }
    </script>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
