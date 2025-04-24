<?php
// Initialize the database
$db_file = 'users.db';
$init_db = !file_exists($db_file);

$db = new SQLite3($db_file);

// Create tables if they don't exist
if ($init_db) {
    $db->exec('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT)');
    $db->exec("INSERT INTO users (username, password, email) VALUES 
        ('admin', 'admin123', 'admin@example.com'),
        ('user1', 'password123', 'user1@example.com'),
        ('user2', 'letmein', 'user2@example.com')");
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SQL Injection Vulnerabilities</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>SQL Injection Vulnerabilities</h1>
        <p class="lead">This page contains various SQL injection vulnerabilities for testing Pentora.</p>
        
        <div class="row mt-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>Basic SQL Injection (GET)</h5>
                    </div>
                    <div class="card-body">
                        <p>Search for a user by ID:</p>
                        <form action="search_get.php" method="get" class="mb-3">
                            <div class="input-group">
                                <input type="text" name="id" class="form-control" placeholder="Enter user ID">
                                <button type="submit" class="btn btn-primary">Search</button>
                            </div>
                        </form>
                        <div class="alert alert-info">
                            <strong>Hint:</strong> Try <code>1 OR 1=1</code> to retrieve all users.
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>SQL Injection (POST)</h5>
                    </div>
                    <div class="card-body">
                        <p>Login with username and password:</p>
                        <form action="login.php" method="post">
                            <div class="mb-3">
                                <label for="username" class="form-label">Username</label>
                                <input type="text" name="username" id="username" class="form-control">
                            </div>
                            <div class="mb-3">
                                <label for="password" class="form-label">Password</label>
                                <input type="password" name="password" id="password" class="form-control">
                            </div>
                            <button type="submit" class="btn btn-primary">Login</button>
                        </form>
                        <div class="alert alert-info mt-3">
                            <strong>Hint:</strong> Try <code>admin' --</code> as username to bypass authentication.
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="row mt-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>Blind SQL Injection</h5>
                    </div>
                    <div class="card-body">
                        <p>Check if a username exists:</p>
                        <form action="blind.php" method="get">
                            <div class="input-group">
                                <input type="text" name="username" class="form-control" placeholder="Enter username">
                                <button type="submit" class="btn btn-primary">Check</button>
                            </div>
                        </form>
                        <div class="alert alert-info mt-3">
                            <strong>Hint:</strong> Try <code>admin' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END) = 1 --</code>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>Time-Based SQL Injection</h5>
                    </div>
                    <div class="card-body">
                        <p>Search for a user by email domain:</p>
                        <form action="time.php" method="get">
                            <div class="input-group">
                                <input type="text" name="domain" class="form-control" placeholder="Enter email domain (e.g., example.com)">
                                <button type="submit" class="btn btn-primary">Search</button>
                            </div>
                        </form>
                        <div class="alert alert-info mt-3">
                            <strong>Hint:</strong> Try <code>example.com' AND (SELECT CASE WHEN (1=1) THEN randomblob(100000000) ELSE 1 END) --</code>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="mt-4">
            <a href="../../index.php" class="btn btn-secondary">Back to Home</a>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
