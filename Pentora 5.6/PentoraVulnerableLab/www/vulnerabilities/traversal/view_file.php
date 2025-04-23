<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>View File</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>File Viewer</h1>
        
        <?php
        // Create files directory and sample files if they don't exist
        $files_dir = "files";
        if (!file_exists($files_dir)) {
            mkdir($files_dir, 0777, true);
            
            // Create sample files
            file_put_contents("$files_dir/example.txt", "This is a sample text file.\nIt contains some example content.\n\nThis file is meant to be accessed normally.");
            file_put_contents("$files_dir/secret.txt", "TOP SECRET INFORMATION\n\nThis file should not be accessible through path traversal.\nIf you're reading this, the application is vulnerable!");
        }
        
        if (isset($_GET['file'])) {
            $filename = $_GET['file'];
            
            echo "<div class='alert alert-info'>";
            echo "Attempting to read file: <strong>" . htmlspecialchars($filename) . "</strong>";
            echo "</div>";
            
            // Vulnerable code - no path validation
            $file_path = "files/" . $filename;
            
            // A secure implementation would use basename() and restrict to the files directory
            // $file_path = "files/" . basename($filename);
            
            if (file_exists($file_path)) {
                $content = file_get_contents($file_path);
                
                echo "<div class='card mt-3'>";
                echo "<div class='card-header'>File Content</div>";
                echo "<div class='card-body'>";
                echo "<pre class='bg-light p-3'>" . htmlspecialchars($content) . "</pre>";
                echo "</div>";
                echo "</div>";
            } else {
                echo "<div class='alert alert-danger'>";
                echo "File not found: " . htmlspecialchars($file_path);
                echo "</div>";
            }
        } else {
            echo "<div class='alert alert-warning'>";
            echo "No file specified.";
            echo "</div>";
        }
        ?>
        
        <div class="mt-4">
            <a href="index.php" class="btn btn-primary">Back to Path Traversal Tests</a>
        </div>
    </div>
</body>
</html>
