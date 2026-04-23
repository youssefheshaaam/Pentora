<?php
// Start a session
session_start();

// Clear all session variables
$_SESSION = array();

// Destroy the session
session_destroy();

// Redirect back to the index page
header("Location: index.php");
exit;
?>
