<?php
// Vulnerable SQL injection in login form (POST)
$db = new SQLite3('users.db');

// Get POST parameters
$username = $_POST['username'];
$password = $_POST['password'];

// Vulnerable code - direct string concatenation
$query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";

echo "<h2>Login Attempt</h2>";
echo "<p>Query executed: <code>$query</code></p>";

try {
    $result = $db->query($query);
    $user = $result->fetchArray(SQLITE3_ASSOC);
    
    if ($user) {
        echo "<div style='color: green; font-weight: bold;'>";
        echo "Login successful! Welcome, " . $user['username'] . "!";
        echo "</div>";
        echo "<p>User details:</p>";
        echo "<ul>";
        echo "<li>ID: " . $user['id'] . "</li>";
        echo "<li>Username: " . $user['username'] . "</li>";
        echo "<li>Email: " . $user['email'] . "</li>";
        echo "</ul>";
    } else {
        echo "<div style='color: red; font-weight: bold;'>";
        echo "Login failed! Invalid username or password.";
        echo "</div>";
    }
} catch (Exception $e) {
    echo "<p>Error: " . $e->getMessage() . "</p>";
}

echo "<p><a href='index.php'>Back to SQL Injection Tests</a></p>";
?>
