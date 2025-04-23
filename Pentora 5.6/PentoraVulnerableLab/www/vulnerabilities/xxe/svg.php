<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XXE - SVG Upload</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>XXE - SVG Upload</h1>
        
        <?php
        // Create uploads directory if it doesn't exist
        $uploads_dir = "uploads";
        if (!file_exists($uploads_dir)) {
            mkdir($uploads_dir, 0777, true);
        }
        
        // Vulnerable XXE via SVG upload
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['svgFile'])) {
            $file = $_FILES['svgFile'];
            
            echo "<div class='alert alert-info'>";
            echo "Processing uploaded SVG file: <strong>" . htmlspecialchars($file['name']) . "</strong>";
            echo "</div>";
            
            // Check for errors
            if ($file['error'] !== UPLOAD_ERR_OK) {
                echo "<div class='alert alert-danger'>Upload failed with error code: " . $file['error'] . "</div>";
            } else {
                // Check file type (basic validation)
                $file_info = pathinfo($file['name']);
                $extension = strtolower($file_info['extension']);
                
                if ($extension !== 'svg') {
                    echo "<div class='alert alert-danger'>Only SVG files are allowed.</div>";
                } else {
                    // Save the file
                    $target_file = $uploads_dir . '/' . basename($file['name']);
                    move_uploaded_file($file['tmp_name'], $target_file);
                    
                    // Read the file content
                    $svg_data = file_get_contents($target_file);
                    
                    // Display the input SVG
                    echo "<div class='card mt-3 mb-3'>";
                    echo "<div class='card-header'>Uploaded SVG Content</div>";
                    echo "<div class='card-body'>";
                    echo "<pre class='bg-light p-3'>" . htmlspecialchars($svg_data) . "</pre>";
                    echo "</div>";
                    echo "</div>";
                    
                    // Vulnerable code - XML processing with external entities enabled
                    $dom = new DOMDocument();
                    
                    // Disable entity loading would prevent the vulnerability
                    // $dom->loadXML($svg_data, LIBXML_NOENT | LIBXML_DTDLOAD);
                    
                    // But we're intentionally allowing it for the vulnerable lab
                    libxml_disable_entity_loader(false);
                    
                    try {
                        $result = $dom->loadXML($svg_data, LIBXML_NOENT | LIBXML_DTDLOAD);
                        
                        if ($result) {
                            echo "<div class='alert alert-success'>SVG processed successfully!</div>";
                            
                            // Display the processed SVG
                            echo "<div class='card mt-3'>";
                            echo "<div class='card-header'>Processed SVG</div>";
                            echo "<div class='card-body'>";
                            echo "<pre class='bg-dark text-light p-3'>" . htmlspecialchars($dom->saveXML()) . "</pre>";
                            echo "</div>";
                            echo "</div>";
                            
                            // Display the SVG image
                            echo "<div class='card mt-3'>";
                            echo "<div class='card-header'>SVG Image</div>";
                            echo "<div class='card-body text-center'>";
                            echo "<img src='" . $target_file . "' alt='Uploaded SVG' style='max-width: 100%; max-height: 300px;'>";
                            echo "<p class='mt-2'><a href='" . $target_file . "' target='_blank'>View full image</a></p>";
                            echo "</div>";
                            echo "</div>";
                        } else {
                            echo "<div class='alert alert-danger'>Failed to process SVG.</div>";
                        }
                    } catch (Exception $e) {
                        echo "<div class='alert alert-danger'>Error: " . htmlspecialchars($e->getMessage()) . "</div>";
                    }
                }
            }
        } else {
            echo "<div class='alert alert-warning'>No SVG file uploaded.</div>";
        }
        ?>
        
        <div class="mt-3">
            <a href="index.php" class="btn btn-primary">Back to XXE Tests</a>
        </div>
    </div>
</body>
</html>
