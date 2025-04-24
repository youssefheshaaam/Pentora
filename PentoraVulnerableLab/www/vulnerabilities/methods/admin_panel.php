<?php
// HTTP Methods Vulnerability Example - Admin Panel

// Vulnerable code: Only checking the request method for authentication
$isAdmin = false;
$message = '';

// Vulnerable: Only checking if the method is POST, not actually authenticating the user
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $isAdmin = true;
    $message = "You've accessed the admin panel using POST. In a secure application, proper authentication would be required.";
} else {
    $message = "Access denied. This page is only accessible via POST requests. Try changing your request method.";
}

// Handle admin actions
$action = isset($_REQUEST['action']) ? $_REQUEST['action'] : '';
$actionResult = '';

if ($isAdmin && !empty($action)) {
    switch ($action) {
        case 'list_users':
            $actionResult = "User list: admin, user1, user2, user3";
            break;
        case 'reset_password':
            $actionResult = "Password reset for all users";
            break;
        case 'delete_user':
            $user = isset($_REQUEST['user']) ? $_REQUEST['user'] : '';
            $actionResult = "User '$user' deleted";
            break;
        default:
            $actionResult = "Unknown action: $action";
            break;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Panel - HTTP Methods - Pentora Vulnerable Lab</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>Admin Panel</h1>
        
        <?php if ($isAdmin): ?>
            <div class="alert alert-success">
                <strong>Success!</strong> <?php echo htmlspecialchars($message); ?>
            </div>
            
            <div class="row">
                <div class="col-md-6">
                    <div class="card mb-4">
                        <div class="card-header">
                            <h5>Admin Actions</h5>
                        </div>
                        <div class="card-body">
                            <div class="d-grid gap-2">
                                <button class="btn btn-primary" onclick="adminAction('list_users')">List Users</button>
                                <button class="btn btn-warning" onclick="adminAction('reset_password')">Reset All Passwords</button>
                                <button class="btn btn-danger" onclick="adminAction('delete_user', 'user1')">Delete User1</button>
                            </div>
                            
                            <?php if (!empty($actionResult)): ?>
                                <div class="alert alert-info mt-3">
                                    <strong>Result:</strong> <?php echo htmlspecialchars($actionResult); ?>
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
                
                <div class="col-md-6">
                    <div class="card mb-4">
                        <div class="card-header">
                            <h5>Security Vulnerability</h5>
                        </div>
                        <div class="card-body">
                            <p>This admin panel is vulnerable because it only checks if the request method is POST, but doesn't properly authenticate users.</p>
                            <p>An attacker can bypass the "authentication" by simply sending a POST request instead of a GET request.</p>
                            <p>Try this command:</p>
                            <pre>curl -X POST <?php echo htmlspecialchars("http://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']); ?></pre>
                        </div>
                    </div>
                </div>
            </div>
        <?php else: ?>
            <div class="alert alert-danger">
                <strong>Access Denied!</strong> <?php echo htmlspecialchars($message); ?>
            </div>
            
            <div class="card mb-4">
                <div class="card-header">
                    <h5>Hint</h5>
                </div>
                <div class="card-body">
                    <p>This page is vulnerable to HTTP method manipulation. Try accessing it with a POST request instead of GET.</p>
                    <p>You can use tools like curl:</p>
                    <pre>curl -X POST <?php echo htmlspecialchars("http://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']); ?></pre>
                    <p>Or you can use the button below:</p>
                    <button class="btn btn-primary" onclick="sendPostRequest()">Access with POST</button>
                </div>
            </div>
        <?php endif; ?>
        
        <a href="index.php" class="btn btn-secondary">Back to HTTP Methods Tests</a>
    </div>

    <script>
        function sendPostRequest() {
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = window.location.href;
            document.body.appendChild(form);
            form.submit();
        }
        
        function adminAction(action, user = '') {
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = window.location.href;
            
            const actionInput = document.createElement('input');
            actionInput.type = 'hidden';
            actionInput.name = 'action';
            actionInput.value = action;
            form.appendChild(actionInput);
            
            if (user) {
                const userInput = document.createElement('input');
                userInput.type = 'hidden';
                userInput.name = 'user';
                userInput.value = user;
                form.appendChild(userInput);
            }
            
            document.body.appendChild(form);
            form.submit();
        }
    </script>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
