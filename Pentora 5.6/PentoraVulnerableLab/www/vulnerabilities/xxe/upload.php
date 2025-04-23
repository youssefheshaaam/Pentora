<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XXE - XML File Upload</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>XXE - XML File Upload</h1>
        
        <?php
        // Vulnerable XXE via file upload
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['xmlFile'])) {
            $file = $_FILES['xmlFile'];
            
            echo "<div class='alert alert-info'>";
            echo "Processing uploaded XML file: <strong>" . htmlspecialchars($file['name']) . "</strong>";
            echo "</div>";
            
            // Check for errors
            if ($file['error'] !== UPLOAD_ERR_OK) {
                echo "<div class='alert alert-danger'>Upload failed with error code: " . $file['error'] . "</div>";
            } else {
                // Check file type (basic validation)
                $file_info = pathinfo($file['name']);
                $extension = strtolower($file_info['extension']);
                
                if ($extension !== 'xml') {
                    echo "<div class='alert alert-danger'>Only XML files are allowed.</div>";
                } else {
                    // Read the file content
                    $xml_data = file_get_contents($file['tmp_name']);
                    
                    // Display the input XML
                    echo "<div class='card mt-3 mb-3'>";
                    echo "<div class='card-header'>Uploaded XML Content</div>";
                    echo "<div class='card-body'>";
                    echo "<pre class='bg-light p-3'>" . htmlspecialchars($xml_data) . "</pre>";
                    echo "</div>";
                    echo "</div>";
                    
                    // Vulnerable code - XML processing with external entities enabled
                    $dom = new DOMDocument();
                    
                    // Disable entity loading would prevent the vulnerability
                    // $dom->loadXML($xml_data, LIBXML_NOENT | LIBXML_DTDLOAD);
                    
                    // But we're intentionally allowing it for the vulnerable lab
                    libxml_disable_entity_loader(false);
                    
                    try {
                        $result = $dom->loadXML($xml_data, LIBXML_NOENT | LIBXML_DTDLOAD);
                        
                        if ($result) {
                            echo "<div class='alert alert-success'>XML processed successfully!</div>";
                            
                            // Display the processed XML
                            echo "<div class='card mt-3'>";
                            echo "<div class='card-header'>Processed XML</div>";
                            echo "<div class='card-body'>";
                            echo "<pre class='bg-dark text-light p-3'>" . htmlspecialchars($dom->saveXML()) . "</pre>";
                            echo "</div>";
                            echo "</div>";
                        } else {
                            echo "<div class='alert alert-danger'>Failed to process XML.</div>";
                        }
                    } catch (Exception $e) {
                        echo "<div class='alert alert-danger'>Error: " . htmlspecialchars($e->getMessage()) . "</div>";
                    }
                }
            }
        } else {
            echo "<div class='alert alert-warning'>No XML file uploaded.</div>";
        }
        ?>
        
        <div class="mt-3">
            <a href="index.php" class="btn btn-primary">Back to XXE Tests</a>
        </div>
    </div>
</body>
</html>
