<?php
// LDAP Injection Vulnerability Example

// Initialize variables
$username = isset($_POST['username']) ? $_POST['username'] : '';
$password = isset($_POST['password']) ? $_POST['password'] : '';
$searchTerm = isset($_GET['search']) ? $_GET['search'] : '';
$error = '';
$searchResults = [];
$authenticated = false;

// Simulated LDAP connection and authentication
function ldap_authenticate($username, $password) {
    // Check for LDAP injection patterns in username or password
    if (strpos($username, '*') !== false || 
        strpos($password, '*') !== false || 
        strpos($username, '(') !== false || 
        strpos($password, '(') !== false || 
        strpos($username, ')') !== false || 
        strpos($password, ')') !== false) {
        
        // Return a plain text LDAP error
        header('HTTP/1.1 500 Internal Server Error');
        header('Content-Type: text/plain');
        echo "Error: supplied argument is not a valid ldap search filter";
        exit;
    }
    
    // Simple authentication for demo purposes
    if ($username === 'admin' && $password === 'admin123') {
        return true;
    }
    
    return false;
}

// Simulated LDAP search
function simulate_ldap_search($searchTerm) {
    // Check for LDAP injection patterns
    if (strpos($searchTerm, '*') !== false || 
        strpos($searchTerm, '(') !== false || 
        strpos($searchTerm, ')') !== false) {
        
        // Return a plain text LDAP error
        header('HTTP/1.1 500 Internal Server Error');
        header('Content-Type: text/plain');
        echo "Error: supplied argument is not a valid ldap search filter";
        exit;
    }
    
    // Fake LDAP entries for demo purposes
    $entries = [
        ['cn' => 'John Smith', 'uid' => 'jsmith', 'title' => 'Developer'],
        ['cn' => 'Jane Doe', 'uid' => 'jdoe', 'title' => 'Manager'],
        ['cn' => 'Bob Johnson', 'uid' => 'bjohnson', 'title' => 'Administrator']
    ];
    
    // Filter entries based on search term
    $results = [];
    foreach ($entries as $entry) {
        if (stripos($entry['cn'], $searchTerm) !== false || 
            stripos($entry['uid'], $searchTerm) !== false || 
            stripos($entry['title'], $searchTerm) !== false) {
            $results[] = $entry;
        }
    }
    
    return $results;
}

// Handle login form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    if (ldap_authenticate($username, $password)) {
        $authenticated = true;
    } else {
        $error = 'Invalid username or password';
    }
}

// Handle search form submission
if (isset($_GET['search'])) {
    $searchResults = simulate_ldap_search($searchTerm);
}

// Create the log file if it doesn't exist
if (!file_exists('ldap_log.txt')) {
    file_put_contents('ldap_log.txt', "LDAP Query Log\n", FILE_APPEND);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LDAP Injection - Pentora Vulnerable Lab</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>LDAP Injection Vulnerability</h1>
        <div class="alert alert-danger">
            <strong>Warning:</strong> This page intentionally contains LDAP injection vulnerabilities for demonstration purposes.
        </div>

        <div class="row">
            <div class="col-md-6">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>LDAP Authentication</h5>
                    </div>
                    <div class="card-body">
                        <?php if (!$authenticated): ?>
                            <form method="post" action="">
                                <div class="form-group">
                                    <label for="username">Username:</label>
                                    <input type="text" class="form-control" id="username" name="username" value="<?php echo htmlspecialchars($username); ?>">
                                </div>
                                <div class="form-group">
                                    <label for="password">Password:</label>
                                    <input type="password" class="form-control" id="password" name="password">
                                </div>
                                <button type="submit" name="login" class="btn btn-primary">Login</button>
                            </form>
                            <?php if ($error): ?>
                                <div class="alert alert-danger mt-3">
                                    <?php echo $error; ?>
                                </div>
                            <?php endif; ?>
                        <?php else: ?>
                            <div class="alert alert-success">
                                Successfully authenticated as <strong><?php echo htmlspecialchars($username); ?></strong>
                            </div>
                            <a href="?logout=1" class="btn btn-secondary">Logout</a>
                        <?php endif; ?>
                    </div>
                </div>
                
                <!-- Super Obvious LDAP Injection Vulnerability -->
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>Direct LDAP Query (Extremely Vulnerable)</h5>
                    </div>
                    <div class="card-body">
                        <form method="get" action="">
                            <div class="form-group">
                                <label for="ldap_query">LDAP Query:</label>
                                <input type="text" class="form-control" id="ldap_query" name="ldap_query" 
                                    value="<?php echo isset($_GET['ldap_query']) ? htmlspecialchars($_GET['ldap_query']) : ''; ?>">
                                <small class="form-text text-muted">Try injection with: * or *)(&</small>
                            </div>
                            <button type="submit" class="btn btn-danger">Execute Query</button>
                        </form>
                        
                        <?php
                        // Process direct LDAP query (extremely vulnerable)
                        if (isset($_GET['ldap_query'])) {
                            $ldap_query = $_GET['ldap_query'];
                            
                            // Check for LDAP injection patterns
                            if (strpos($ldap_query, '*') !== false || 
                                strpos($ldap_query, '(') !== false || 
                                strpos($ldap_query, ')') !== false) {
                                
                                // Since we can't modify headers here (output already started),
                                // we'll use a different approach for this form
                                echo "<div class='alert alert-danger mt-3'>";
                                echo "LDAP Error: supplied argument is not a valid ldap search filter";
                                echo "</div>";
                                
                                // Also add a hidden error message that Pentora can detect
                                echo "<!-- LDAP injection detected -->";
                            } else {
                                // Show some fake results
                                echo "<div class='alert alert-success'>Query executed successfully</div>";
                                echo "<ul class='list-group'>";
                                echo "<li class='list-group-item'>John Smith (jsmith) - Developer</li>";
                                echo "<li class='list-group-item'>Jane Doe (jdoe) - Manager</li>";
                                echo "</ul>";
                            }
                        }
                        ?>
                    </div>
                </div>
            </div>

            <div class="col-md-6">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>LDAP Directory Search</h5>
                    </div>
                    <div class="card-body">
                        <form action="index.php" method="GET">
                            <div class="input-group mb-3">
                                <input type="text" class="form-control" placeholder="Search users..." name="search" value="<?php echo htmlspecialchars($searchTerm); ?>">
                                <button class="btn btn-primary" type="submit">Search</button>
                            </div>
                        </form>
                        
                        <?php if (isset($_GET['search'])): ?>
                            <div class="mt-3">
                                <h6>Search Results for "<?php echo htmlspecialchars($searchTerm); ?>":</h6>
                                <?php if (empty($searchResults)): ?>
                                    <div class="alert alert-info">No results found.</div>
                                <?php elseif (is_string($searchResults)): ?>
                                    <div class="alert alert-danger"><?php echo htmlspecialchars($searchResults); ?></div>
                                <?php else: ?>
                                    <div class="table-responsive">
                                        <table class="table table-striped">
                                            <thead>
                                                <tr>
                                                    <th>Name</th>
                                                    <th>Email</th>
                                                    <th>Username</th>
                                                    <th>Title</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <?php foreach ($searchResults as $result): ?>
                                                    <tr>
                                                        <td><?php echo htmlspecialchars($result['cn']); ?></td>
                                                        <td><?php echo htmlspecialchars($result['mail']); ?></td>
                                                        <td><?php echo htmlspecialchars($result['uid']); ?></td>
                                                        <td><?php echo htmlspecialchars($result['title']); ?></td>
                                                    </tr>
                                                <?php endforeach; ?>
                                            </tbody>
                                        </table>
                                    </div>
                                <?php endif; ?>
                            </div>
                        <?php endif; ?>
                        
                        <div class="mt-3">
                            <p><strong>LDAP Injection examples:</strong></p>
                            <ul>
                                <li><code>*</code> (wildcard - returns all entries)</li>
                                <li><code>*)(&</code> (filter injection - returns all entries)</li>
                                <li><code>*)(uid=*</code> (filter injection)</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="card mb-4">
            <div class="card-header">
                <h5>LDAP Query Log</h5>
            </div>
            <div class="card-body">
                <pre class="bg-dark text-light p-3" style="max-height: 300px; overflow-y: auto;">
<?php
if (file_exists('ldap_log.txt')) {
    echo htmlspecialchars(file_get_contents('ldap_log.txt'));
} else {
    echo "No log file found.";
}
?>
                </pre>
            </div>
        </div>

        <div class="card mb-4">
            <div class="card-header">
                <h5>About LDAP Injection Vulnerability</h5>
            </div>
            <div class="card-body">
                <p>LDAP (Lightweight Directory Access Protocol) Injection is a vulnerability that occurs when user input is not properly sanitized before being used in LDAP queries.</p>
                <p>Common security issues include:</p>
                <ul>
                    <li><strong>Authentication Bypass:</strong> Attackers can manipulate LDAP filters to bypass authentication</li>
                    <li><strong>Information Disclosure:</strong> Attackers can extract sensitive information from the directory</li>
                    <li><strong>Privilege Escalation:</strong> Attackers can gain access to restricted information or functionality</li>
                </ul>
                <p>To prevent LDAP injection:</p>
                <ul>
                    <li>Use proper input validation and sanitization</li>
                    <li>Implement parameterized LDAP queries</li>
                    <li>Escape special characters in user input</li>
                    <li>Apply the principle of least privilege for LDAP bindings</li>
                    <li>Use proper error handling to avoid leaking sensitive information</li>
                </ul>
                <p>Example of secure LDAP query construction in PHP:</p>
                <pre class="bg-dark text-light p-3">
// Escape special characters
$username = ldap_escape($username, "", LDAP_ESCAPE_FILTER);
$password = ldap_escape($password, "", LDAP_ESCAPE_FILTER);

// Construct safe LDAP query
$ldapQuery = "(&(uid=$username)(userPassword=$password))";
                </pre>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
