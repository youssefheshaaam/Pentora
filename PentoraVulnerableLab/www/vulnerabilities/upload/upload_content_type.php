<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Content-Type Validation Upload</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>Content-Type Validation Upload</h1>
        
        <?php
        // Vulnerable file upload with only MIME type validation
        if ($_SERVER["REQUEST_METHOD"] == "POST") {
            $target_dir = "uploads/";
            $target_file = $target_dir . basename($_FILES["fileToUpload"]["name"]);
            $upload_status = true;
            
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
            
            // Content-Type validation - can be bypassed
            $allowed_types = array("image/jpeg", "image/png", "image/gif");
            $file_type = $_FILES["fileToUpload"]["type"];
            
            if (!in_array($file_type, $allowed_types)) {
                echo "<div class='alert alert-danger'>Sorry, only JPG, PNG & GIF files are allowed.</div>";
                echo "<div class='alert alert-info'>Your file has MIME type: " . htmlspecialchars($file_type) . "</div>";
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
