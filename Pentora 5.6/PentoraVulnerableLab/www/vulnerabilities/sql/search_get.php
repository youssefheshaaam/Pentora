<?php
// Vulnerable SQL query using GET parameter
$db = new SQLite3('users.db');

// Vulnerable code - no input validation or parameterization
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = $id";

echo "<h2>Search Results</h2>";
echo "<p>Query executed: <code>$query</code></p>";

try {
    $results = $db->query($query);
    
    if ($results) {
        echo "<table border='1' cellpadding='5'>";
        echo "<tr><th>ID</th><th>Username</th><th>Password</th><th>Email</th></tr>";
        
        while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
            echo "<tr>";
            echo "<td>" . $row['id'] . "</td>";
            echo "<td>" . $row['username'] . "</td>";
            echo "<td>" . $row['password'] . "</td>";
            echo "<td>" . $row['email'] . "</td>";
            echo "</tr>";
        }
        
        echo "</table>";
    } else {
        echo "<p>No results found or error in query.</p>";
    }
} catch (Exception $e) {
    echo "<p>Error: " . $e->getMessage() . "</p>";
}

echo "<p><a href='index.php'>Back to SQL Injection Tests</a></p>";
?>
