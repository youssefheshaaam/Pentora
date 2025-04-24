<?php
// Start session
session_start();

// Create a simple user database if it doesn't exist
$db_file = 'users.db';
$init_db = !file_exists($db_file);

$db = new SQLite3($db_file);

// Create tables if they don't exist
if ($init_db) {
    $db->exec('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, is_admin INTEGER)');
    $db->exec("INSERT INTO users (username, password, email, is_admin) VALUES 
        ('admin', 'admin123', 'admin@example.com', 1),
        ('user1', 'password123', 'user1@example.com', 0),
        ('user2', 'password456', 'user2@example.com', 0)");
}

// Check if user is logged in
$logged_in = isset($_SESSION['user_id']);
$is_admin = false;
$user_data = null;

if ($logged_in) {
    $stmt = $db->prepare("SELECT * FROM users WHERE id = :id");
    $stmt->bindValue(':id', $_SESSION['user_id'], SQLITE3_INTEGER);
    $result = $stmt->execute();
    $user_data = $result->fetchArray(SQLITE3_ASSOC);
    $is_admin = $user_data && $user_data['is_admin'] == 1;
}

// Handle login
if (isset($_POST['login'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    $stmt = $db->prepare("SELECT * FROM users WHERE username = :username AND password = :password");
    $stmt->bindValue(':username', $username, SQLITE3_TEXT);
    $stmt->bindValue(':password', $password, SQLITE3_TEXT);
    $result = $stmt->execute();
    $user = $result->fetchArray(SQLITE3_ASSOC);
    
    if ($user) {
        $_SESSION['user_id'] = $user['id'];
        header("Location: index.php");
        exit;
    } else {
        $login_error = "Invalid username or password";
    }
}

// Handle logout
if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: index.php");
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CSRF Vulnerabilities</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>CSRF (Cross-Site Request Forgery) Vulnerabilities</h1>
        <p class="lead">This page contains various CSRF vulnerabilities for testing Pentora.</p>
        
        <div class="alert alert-danger">
            <strong>Warning:</strong> These examples demonstrate dangerous vulnerabilities. In a real application, always use CSRF tokens to protect against CSRF attacks.
        </div>
        
        <?php if ($logged_in): ?>
            <div class="alert alert-success">
                <strong>Welcome, <?php echo htmlspecialchars($user_data['username']); ?>!</strong>
                <?php if ($is_admin): ?>
                    <span class="badge bg-danger ms-2">Admin</span>
                <?php endif; ?>
                <a href="index.php?logout=1" class="btn btn-sm btn-outline-dark float-end">Logout</a>
            </div>
        <?php endif; ?>
        
        <div class="row mt-4">
            <?php if (!$logged_in): ?>
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h5>Login</h5>
                        </div>
                        <div class="card-body">
                            <?php if (isset($login_error)): ?>
                                <div class="alert alert-danger"><?php echo $login_error; ?></div>
                            <?php endif; ?>
                            
                            <form action="index.php" method="post">
                                <div class="mb-3">
                                    <label for="username" class="form-label">Username</label>
                                    <input type="text" name="username" id="username" class="form-control" required>
                                </div>
                                <div class="mb-3">
                                    <label for="password" class="form-label">Password</label>
                                    <input type="password" name="password" id="password" class="form-control" required>
                                </div>
                                <button type="submit" name="login" class="btn btn-primary">Login</button>
                            </form>
                            
                            <div class="alert alert-info mt-3">
                                <strong>Available users:</strong><br>
                                Username: admin, Password: admin123<br>
                                Username: user1, Password: password123
                            </div>
                        </div>
                    </div>
                </div>
            <?php else: ?>
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h5>Update Profile</h5>
                        </div>
                        <div class="card-body">
                            <p>Update your profile information:</p>
                            <form action="update_profile.php" method="post">
                                <div class="mb-3">
                                    <label for="email" class="form-label">Email</label>
                                    <input type="email" name="email" id="email" class="form-control" value="<?php echo htmlspecialchars($user_data['email']); ?>" required>
                                </div>
                                <button type="submit" class="btn btn-primary">Update Profile</button>
                            </form>
                            <div class="alert alert-warning mt-3">
                                <strong>Vulnerable to CSRF:</strong> This form does not use CSRF tokens.
                            </div>
                        </div>
                    </div>
                </div>
            <?php endif; ?>
            
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>CSRF Attack Examples</h5>
                    </div>
                    <div class="card-body">
                        <?php if (!$logged_in): ?>
                            <div class="alert alert-warning">
                                Please login first to see the CSRF attack examples.
                            </div>
                        <?php else: ?>
                            <p>Click on the links below to see example CSRF attacks:</p>
                            <ul class="list-group">
                                <li class="list-group-item">
                                    <a href="csrf_email.html" target="_blank">Change Email Attack</a>
                                    <span class="badge bg-danger float-end">Vulnerable</span>
                                </li>
                                <li class="list-group-item">
                                    <a href="csrf_password.html" target="_blank">Change Password Attack</a>
                                    <span class="badge bg-danger float-end">Vulnerable</span>
                                </li>
                                <?php if ($is_admin): ?>
                                    <li class="list-group-item">
                                        <a href="csrf_admin.html" target="_blank">Create New User Attack</a>
                                        <span class="badge bg-danger float-end">Vulnerable</span>
                                    </li>
                                <?php endif; ?>
                            </ul>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
        
        <?php if ($logged_in && $is_admin): ?>
            <div class="row mt-4">
                <div class="col-md-12">
                    <div class="card">
                        <div class="card-header">
                            <h5>Admin Panel</h5>
                        </div>
                        <div class="card-body">
                            <h6>User Management</h6>
                            <table class="table table-striped">
                                <thead>
                                    <tr>
                                        <th>ID</th>
                                        <th>Username</th>
                                        <th>Email</th>
                                        <th>Admin</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php
                                    $results = $db->query("SELECT * FROM users ORDER BY id");
                                    while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
                                        echo "<tr>";
                                        echo "<td>" . $row['id'] . "</td>";
                                        echo "<td>" . htmlspecialchars($row['username']) . "</td>";
                                        echo "<td>" . htmlspecialchars($row['email']) . "</td>";
                                        echo "<td>" . ($row['is_admin'] ? "Yes" : "No") . "</td>";
                                        echo "<td>";
                                        echo "<a href='delete_user.php?id=" . $row['id'] . "' class='btn btn-sm btn-danger'>Delete</a>";
                                        echo "</td>";
                                        echo "</tr>";
                                    }
                                    ?>
                                </tbody>
                            </table>
                            
                            <h6 class="mt-4">Add New User</h6>
                            <form action="add_user.php" method="post">
                                <div class="row">
                                    <div class="col-md-3">
                                        <div class="mb-3">
                                            <label for="new_username" class="form-label">Username</label>
                                            <input type="text" name="username" id="new_username" class="form-control" required>
                                        </div>
                                    </div>
                                    <div class="col-md-3">
                                        <div class="mb-3">
                                            <label for="new_password" class="form-label">Password</label>
                                            <input type="password" name="password" id="new_password" class="form-control" required>
                                        </div>
                                    </div>
                                    <div class="col-md-3">
                                        <div class="mb-3">
                                            <label for="new_email" class="form-label">Email</label>
                                            <input type="email" name="email" id="new_email" class="form-control" required>
                                        </div>
                                    </div>
                                    <div class="col-md-3">
                                        <div class="mb-3">
                                            <label for="new_is_admin" class="form-label">Admin</label>
                                            <select name="is_admin" id="new_is_admin" class="form-select">
                                                <option value="0">No</option>
                                                <option value="1">Yes</option>
                                            </select>
                                        </div>
                                    </div>
                                </div>
                                <button type="submit" class="btn btn-primary">Add User</button>
                            </form>
                            <div class="alert alert-warning mt-3">
                                <strong>Vulnerable to CSRF:</strong> These admin actions do not use CSRF tokens.
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        <?php endif; ?>
        
        <div class="mt-4">
            <a href="../../index.php" class="btn btn-secondary">Back to Home</a>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
