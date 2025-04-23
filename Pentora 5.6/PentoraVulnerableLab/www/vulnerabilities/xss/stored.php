<?php
// Vulnerable stored XSS - saving and displaying user input without sanitization
$db = new SQLite3('comments.db');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = $_POST['name'];
    $comment = $_POST['comment'];
    $date = date('Y-m-d');
    
    // Insert the comment without sanitization
    $stmt = $db->prepare("INSERT INTO comments (name, comment, date) VALUES (?, ?, ?)");
    $stmt->bindValue(1, $name, SQLITE3_TEXT);
    $stmt->bindValue(2, $comment, SQLITE3_TEXT);
    $stmt->bindValue(3, $date, SQLITE3_TEXT);
    $stmt->execute();
}

// Redirect back to the main page
header('Location: index.php');
exit;
?>
