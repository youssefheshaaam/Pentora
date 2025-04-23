<?php
// Create images directory and sample images if they don't exist
$images_dir = "images";
if (!file_exists($images_dir)) {
    mkdir($images_dir, 0777, true);
    
    // Create placeholder for sample images (in a real app, these would be actual image files)
    file_put_contents("$images_dir/image1.jpg", "This is a placeholder for image1.jpg");
    file_put_contents("$images_dir/image2.jpg", "This is a placeholder for image2.jpg");
    file_put_contents("$images_dir/image3.jpg", "This is a placeholder for image3.jpg");
}

if (isset($_GET['img'])) {
    $img = $_GET['img'];
    
    // Attempt to prevent path traversal by removing "../" sequences
    // This is still vulnerable because there are other ways to traverse directories
    $img = str_replace("../", "", $img);
    
    // Vulnerable code - incomplete path validation
    $img_path = "images/" . $img;
    
    // A secure implementation would use basename() and restrict to the images directory
    // $img_path = "images/" . basename($img);
    
    if (file_exists($img_path)) {
        // In a real application, we would check the MIME type and serve the image
        // For demonstration purposes, we'll just output the content with appropriate headers
        
        // Get the file extension
        $ext = pathinfo($img_path, PATHINFO_EXTENSION);
        
        // Set the content type based on the extension
        switch (strtolower($ext)) {
            case 'jpg':
            case 'jpeg':
                header('Content-Type: image/jpeg');
                break;
            case 'png':
                header('Content-Type: image/png');
                break;
            case 'gif':
                header('Content-Type: image/gif');
                break;
            default:
                header('Content-Type: application/octet-stream');
        }
        
        // Output the file content
        readfile($img_path);
        exit;
    } else {
        // If image not found, display an error
        header('HTTP/1.1 404 Not Found');
        echo "Image not found: " . htmlspecialchars($img_path);
    }
} else {
    // If no image specified, show a form to select an image
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Image Viewer</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <div class="container mt-5">
            <h1>Image Viewer</h1>
            
            <div class="alert alert-warning">
                <strong>Note:</strong> No image specified. Please select an image to view.
            </div>
            
            <div class="card">
                <div class="card-header">
                    <h5>Select an Image</h5>
                </div>
                <div class="card-body">
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
                </div>
            </div>
            
            <div class="mt-4">
                <a href="index.php" class="btn btn-secondary">Back to Path Traversal Tests</a>
            </div>
        </div>
    </body>
    </html>
    <?php
}
?>
