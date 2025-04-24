<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Blacklist Validation Upload</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>Blacklist Validation Upload</h1>
        
        <?php
        // Vulnerable file upload with incomplete blacklist validation
        if ($_SERVER["REQUEST_METHOD"] == "POST") {
            $target_dir = "uploads/";
            $target_file = $target_dir . basename($_FILES["fileToUpload"]["name"]);
            $upload_status = true;
            $file_extension = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));
            
            // Check if file already exists
            if (file_exists($target_file)) {
                echo "<div class='alert alert-warning'>Sorry, file already exists.</div>";
                $upload_status = false;
            }
            
            // Check file size
            if ($_FILES["fileToUpload"]["size"] > 5000000) { // 5MB
                echo "<div class='alert alert-warning'>Sorry, your file is too large.</div>";
                $upload_status = false;
            }
            
            // Blacklist validation - incomplete and can be bypassed
            $blacklisted_extensions = array("php", "php3", "php4", "exe", "sh", "bat");
            if (in_array($file_extension, $blacklisted_extensions)) {
                echo "<div class='alert alert-danger'>Sorry, " . $file_extension . " files are not allowed.</div>";
                echo "<div class='alert alert-info'>Allowed file types: Any file except " . implode(", ", $blacklisted_extensions) . "</div>";
                $upload_status = false;
            }
            
            // Attempt to upload file
            if ($upload_status) {
                if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
                    echo "<div class='alert alert-success'>The file ". htmlspecialchars(basename($_FILES["fileToUpload"]["name"])). " has been uploaded.</div>";
                    
                    // Display file information
                    echo "<div class='card mt-3'>";
                    echo "<div class='card-header'>File Information</div>";
                    echo "<div class='card-body'>";
                    echo "<p><strong>Filename:</strong> " . htmlspecialchars(basename($_FILES["fileToUpload"]["name"])) . "</p>";
                    echo "<p><strong>File Type:</strong> " . htmlspecialchars($_FILES["fileToUpload"]["type"]) . "</p>";
                    echo "<p><strong>File Size:</strong> " . htmlspecialchars($_FILES["fileToUpload"]["size"]) . " bytes</p>";
                    echo "<p><strong>File Extension:</strong> " . htmlspecialchars($file_extension) . "</p>";
                    echo "<p><strong>File Path:</strong> <a href='" . $target_file . "' target='_blank'>" . htmlspecialchars($target_file) . "</a></p>";
                    echo "</div>";
                    echo "</div>";
                } else {
                    echo "<div class='alert alert-danger'>Sorry, there was an error uploading your file.</div>";
                }
            }
        }
        ?>
        
        <div class="mt-3">
            <a href="index.php" class="btn btn-primary">Back to File Upload Tests</a>
        </div>
    </div>
</body>
</html>
