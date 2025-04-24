<?php
// Vulnerable blind SQL injection
$db = new SQLite3('users.db');

// Get the username parameter
$username = $_GET['username'];

// Vulnerable code - direct string concatenation
$query = "SELECT * FROM users WHERE username = '$username'";

echo "<h2>Username Check</h2>";
echo "<p>Checking if username exists: <strong>$username</strong></p>";
echo "<p>Query executed: <code>$query</code></p>";

try {
    $result = $db->query($query);
    $user = $result->fetchArray(SQLITE3_ASSOC);
    
    if ($user) {
        echo "<div style='color: green; font-weight: bold;'>";
        echo "Username exists in the database.";
        echo "</div>";
    } else {
        echo "<div style='color: red; font-weight: bold;'>";
        echo "Username does not exist in the database.";
        echo "</div>";
    }
} catch (Exception $e) {
    echo "<p>Error: " . $e->getMessage() . "</p>";
}

echo "<p><a href='index.php'>Back to SQL Injection Tests</a></p>";
?>
