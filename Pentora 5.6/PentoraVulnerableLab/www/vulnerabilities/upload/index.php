<?php
// Create uploads directory if it doesn't exist
$uploads_dir = "uploads";
if (!file_exists($uploads_dir)) {
    mkdir($uploads_dir, 0777, true);
}

// Create a .htaccess file to allow execution of PHP files in the uploads directory
// This is intentionally vulnerable!
$htaccess_file = "$uploads_dir/.htaccess";
if (!file_exists($htaccess_file)) {
    file_put_contents($htaccess_file, "# Allow PHP execution\nAddType application/x-httpd-php .php .php5 .phtml");
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Upload Vulnerabilities</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>File Upload Vulnerabilities</h1>
        <p class="lead">This page contains various file upload vulnerabilities for testing Pentora.</p>
        
        <div class="alert alert-danger">
            <strong>Warning:</strong> These examples demonstrate dangerous vulnerabilities. In a real application, never allow unrestricted file uploads.
        </div>
        
        <div class="row mt-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>Unrestricted File Upload</h5>
                    </div>
                    <div class="card-body">
                        <p>Upload any file without restrictions:</p>
                        <form action="upload_unrestricted.php" method="post" enctype="multipart/form-data" class="mb-3">
                            <div class="mb-3">
                                <label for="fileToUpload1" class="form-label">Select File</label>
                                <input type="file" name="fileToUpload" id="fileToUpload1" class="form-control">
                            </div>
                            <button type="submit" class="btn btn-primary">Upload File</button>
                        </form>
                        <div class="alert alert-info">
                            <strong>Hint:</strong> Try uploading a PHP file with malicious code
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>Client-Side Validation Only</h5>
                    </div>
                    <div class="card-body">
                        <p>Upload with client-side validation (easily bypassed):</p>
                        <form action="upload_client_validation.php" method="post" enctype="multipart/form-data">
                            <div class="mb-3">
                                <label for="fileToUpload2" class="form-label">Select Image</label>
                                <input type="file" name="fileToUpload" id="fileToUpload2" class="form-control" accept="image/*">
                            </div>
                            <button type="submit" class="btn btn-primary">Upload Image</button>
                        </form>
                        <div class="alert alert-info mt-3">
                            <strong>Hint:</strong> Try bypassing the client-side validation by modifying the request
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="row mt-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>Blacklist Validation</h5>
                    </div>
                    <div class="card-body">
                        <p>Upload with blacklist validation (can be bypassed):</p>
                        <form action="upload_blacklist.php" method="post" enctype="multipart/form-data">
                            <div class="mb-3">
                                <label for="fileToUpload3" class="form-label">Select File</label>
                                <input type="file" name="fileToUpload" id="fileToUpload3" class="form-control">
                            </div>
                            <button type="submit" class="btn btn-primary">Upload File</button>
                        </form>
                        <div class="alert alert-info mt-3">
                            <strong>Hint:</strong> Try uploading a file with uncommon extensions like .phtml, .php5, etc.
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>Content-Type Validation</h5>
                    </div>
                    <div class="card-body">
                        <p>Upload with MIME type validation (can be bypassed):</p>
                        <form action="upload_content_type.php" method="post" enctype="multipart/form-data">
                            <div class="mb-3">
                                <label for="fileToUpload4" class="form-label">Select Image</label>
                                <input type="file" name="fileToUpload" id="fileToUpload4" class="form-control">
                            </div>
                            <button type="submit" class="btn btn-primary">Upload Image</button>
                        </form>
                        <div class="alert alert-info mt-3">
                            <strong>Hint:</strong> Try modifying the Content-Type header in the request
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="row mt-4">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header">
                        <h5>Uploaded Files</h5>
                    </div>
                    <div class="card-body">
                        <h6>Files in the uploads directory:</h6>
                        <ul class="list-group">
                            <?php
                            $files = glob("$uploads_dir/*");
                            if (empty($files)) {
                                echo "<li class='list-group-item'>No files uploaded yet.</li>";
                            } else {
                                foreach ($files as $file) {
                                    if (basename($file) !== '.htaccess') {
                                        $file_url = str_replace('\\', '/', $file);
                                        echo "<li class='list-group-item'>";
                                        echo "<a href='$file_url' target='_blank'>" . basename($file) . "</a>";
                                        echo " (" . filesize($file) . " bytes)";
                                        echo "</li>";
                                    }
                                }
                            }
                            ?>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="mt-4">
            <a href="../../index.php" class="btn btn-secondary">Back to Home</a>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
