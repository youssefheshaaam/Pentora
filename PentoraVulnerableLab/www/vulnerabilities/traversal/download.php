<?php
// Create files directory and sample files if they don't exist
$files_dir = "files";
if (!file_exists($files_dir)) {
    mkdir($files_dir, 0777, true);
    
    // Create sample files
    file_put_contents("$files_dir/sample1.txt", "This is sample text file 1.\nIt contains some example content.\n\nThis file is meant to be downloaded normally.");
    file_put_contents("$files_dir/sample2.txt", "This is sample text file 2.\nIt has different content from sample1.txt.\n\nThis file is also meant to be downloaded normally.");
    file_put_contents("$files_dir/image.jpg", "This is not a real image, just a text file with a .jpg extension for demonstration purposes.");
}

if (isset($_GET['filename'])) {
    $filename = $_GET['filename'];
    
    // Vulnerable code - no path validation
    $file_path = "files/" . $filename;
    
    // A secure implementation would use basename() and restrict to the files directory
    // $file_path = "files/" . basename($filename);
    
    if (file_exists($file_path)) {
        // Set headers for file download
        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('Expires: 0');
        header('Cache-Control: must-revalidate');
        header('Pragma: public');
        header('Content-Length: ' . filesize($file_path));
        
        // Read the file and output to the browser
        readfile($file_path);
        exit;
    } else {
        // If file not found, display an error
        header('HTTP/1.1 404 Not Found');
        echo "File not found: " . htmlspecialchars($file_path);
    }
} else {
    // If no filename specified, redirect back to the index page
    header('Location: index.php');
    exit;
}
?>
