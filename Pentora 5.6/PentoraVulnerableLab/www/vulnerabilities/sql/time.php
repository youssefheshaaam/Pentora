<?php
// Vulnerable time-based SQL injection
$db = new SQLite3('users.db');

// Get the domain parameter
$domain = $_GET['domain'];

// Vulnerable code - direct string concatenation
$query = "SELECT * FROM users WHERE email LIKE '%$domain'";

echo "<h2>Email Domain Search</h2>";
echo "<p>Searching for users with email domain: <strong>$domain</strong></p>";
echo "<p>Query executed: <code>$query</code></p>";

try {
    $start_time = microtime(true);
    $results = $db->query($query);
    $end_time = microtime(true);
    $execution_time = ($end_time - $start_time) * 1000; // Convert to milliseconds
    
    echo "<p>Query execution time: <strong>{$execution_time} ms</strong></p>";
    
    if ($results) {
        echo "<table border='1' cellpadding='5'>";
        echo "<tr><th>ID</th><th>Username</th><th>Email</th></tr>";
        
        $found = false;
        while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
            $found = true;
            echo "<tr>";
            echo "<td>" . $row['id'] . "</td>";
            echo "<td>" . $row['username'] . "</td>";
            echo "<td>" . $row['email'] . "</td>";
            echo "</tr>";
        }
        
        echo "</table>";
        
        if (!$found) {
            echo "<p>No users found with email domain: $domain</p>";
        }
    } else {
        echo "<p>Error executing query.</p>";
    }
} catch (Exception $e) {
    echo "<p>Error: " . $e->getMessage() . "</p>";
}

echo "<p><a href='index.php'>Back to SQL Injection Tests</a></p>";
?>
