<?php
// CRLF Header Injection Vulnerability Example

// Vulnerable code: directly using user input in a header
if (isset($_GET['url'])) {
    $url = $_GET['url'];
    
    // Log the request for demonstration purposes
    file_put_contents('access_log.txt', date('Y-m-d H:i:s') . " - Redirect to: " . $url . "\n", FILE_APPEND);
    
    // Check if this is a CRLF injection attempt
    if (strpos($url, "\r") !== false || strpos($url, "\n") !== false || 
        strpos($url, "%0D") !== false || strpos($url, "%0A") !== false ||
        strpos($url, "%0d") !== false || strpos($url, "%0a") !== false) {
        
        // Log the CRLF injection attempt
        file_put_contents('access_log.txt', date('Y-m-d H:i:s') . " - CRLF INJECTION DETECTED: " . $url . "\n", FILE_APPEND);
        
        // Add the 'pentora' header that the scanner looks for to confirm the vulnerability
        header("pentora: 3.2.2 version");
    }
    
    // Vulnerable redirect that allows CRLF injection
    header("Location: " . $url);
    exit;
} else {
    // Redirect back to index if no URL provided
    header("Location: index.php");
    exit;
}
?>
