<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Path Traversal Vulnerabilities</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>Path Traversal Vulnerabilities</h1>
        <p class="lead">This section demonstrates various path traversal vulnerabilities that can be exploited to access files outside the intended directory.</p>
        
        <div class="alert alert-danger">
            <strong>Warning:</strong> These examples demonstrate dangerous vulnerabilities. In a real application, always validate and sanitize file paths.
        </div>
        
        <div class="row mt-4">
            <div class="col-md-6">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>View File</h5>
                    </div>
                    <div class="card-body">
                        <p>Enter a filename to view its contents:</p>
                        <form action="view_file.php" method="get">
                            <div class="mb-3">
                                <label for="file" class="form-label">Filename</label>
                                <input type="text" name="file" id="file" class="form-control" placeholder="example.txt" required>
                                <div class="form-text">Try to access files in the 'files' directory.</div>
                            </div>
                            <button type="submit" class="btn btn-primary">View File</button>
                        </form>
                        <div class="alert alert-warning mt-3">
                            <strong>Vulnerability:</strong> This endpoint is vulnerable to path traversal attacks.
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="col-md-6">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>Download File</h5>
                    </div>
                    <div class="card-body">
                        <p>Select a file to download:</p>
                        <form action="download.php" method="get">
                            <div class="mb-3">
                                <label for="filename" class="form-label">Filename</label>
                                <select name="filename" id="filename" class="form-select">
                                    <option value="sample1.txt">Sample Text File 1</option>
                                    <option value="sample2.txt">Sample Text File 2</option>
                                    <option value="image.jpg">Sample Image</option>
                                </select>
                            </div>
                            <button type="submit" class="btn btn-primary">Download File</button>
                        </form>
                        <div class="alert alert-warning mt-3">
                            <strong>Vulnerability:</strong> This endpoint is vulnerable to path traversal via direct parameter manipulation.
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="row">
            <div class="col-md-6">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>Include Template</h5>
                    </div>
                    <div class="card-body">
                        <p>Select a template to include in the page:</p>
                        <form action="include.php" method="get">
                            <div class="mb-3">
                                <label for="template" class="form-label">Template</label>
                                <select name="template" id="template" class="form-select">
                                    <option value="header">Header Template</option>
                                    <option value="footer">Footer Template</option>
                                    <option value="sidebar">Sidebar Template</option>
                                </select>
                            </div>
                            <button type="submit" class="btn btn-primary">Load Template</button>
                        </form>
                        <div class="alert alert-warning mt-3">
                            <strong>Vulnerability:</strong> This endpoint is vulnerable to local file inclusion.
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="col-md-6">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>Image Viewer</h5>
                    </div>
                    <div class="card-body">
                        <p>View an image from the gallery:</p>
                        <form action="image.php" method="get">
                            <div class="mb-3">
                                <label for="img" class="form-label">Image</label>
                                <select name="img" id="img" class="form-select">
                                    <option value="image1.jpg">Image 1</option>
                                    <option value="image2.jpg">Image 2</option>
                                    <option value="image3.jpg">Image 3</option>
                                </select>
                            </div>
                            <button type="submit" class="btn btn-primary">View Image</button>
                        </form>
                        <div class="alert alert-warning mt-3">
                            <strong>Vulnerability:</strong> This endpoint is vulnerable to path traversal with partial filtering.
                        </div>
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
