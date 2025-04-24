<?php
// Directory Buster Vulnerability Example
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Directory Buster - Pentora Vulnerable Lab</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>Directory Buster Vulnerability</h1>
        <div class="alert alert-danger">
            <strong>Warning:</strong> This section demonstrates hidden directories and files that could be discovered by directory busting tools.
        </div>

        <div class="row">
            <div class="col-md-6">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>Public Website</h5>
                    </div>
                    <div class="card-body">
                        <p>This is the public-facing part of the website. However, there are hidden directories and files that are not linked from here.</p>
                        <p>These hidden resources could contain sensitive information or functionality.</p>
                    </div>
                </div>
            </div>

            <div class="col-md-6">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>Directory Busting Information</h5>
                    </div>
                    <div class="card-body">
                        <p>Directory busting is a technique used to discover hidden files and directories on a web server by trying common names.</p>
                        <p>This vulnerability exists when:</p>
                        <ul>
                            <li>Directory listing is enabled</li>
                            <li>Sensitive directories are not properly protected</li>
                            <li>Backup, temporary, or development files are left on the server</li>
                            <li>Hidden administrative interfaces are accessible</li>
                        </ul>
                        
                        <div class="alert alert-info mt-3">
                            <strong>Hint:</strong> Try to find the following hidden resources in this directory:
                            <ul>
                                <li>A hidden admin panel</li>
                                <li>A backup file with credentials</li>
                                <li>A development directory</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
