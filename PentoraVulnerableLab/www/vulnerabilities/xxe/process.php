<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XXE - Process XML</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>XXE - Process XML</h1>
        
        <?php
        // Vulnerable XXE processing
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['xml'])) {
            $xml_data = $_POST['xml'];
            
            echo "<div class='alert alert-info'>";
            echo "Processing XML data...";
            echo "</div>";
            
            // Display the input XML
            echo "<div class='card mt-3 mb-3'>";
            echo "<div class='card-header'>Input XML</div>";
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
                    
                    // Extract and display user data
                    echo "<div class='card mt-3'>";
                    echo "<div class='card-header'>User Data</div>";
                    echo "<div class='card-body'>";
                    
                    $xpath = new DOMXPath($dom);
                    $username = $xpath->query('//username');
                    $password = $xpath->query('//password');
                    
                    if ($username->length > 0 && $password->length > 0) {
                        echo "<p><strong>Username:</strong> " . htmlspecialchars($username->item(0)->nodeValue) . "</p>";
                        echo "<p><strong>Password:</strong> " . htmlspecialchars($password->item(0)->nodeValue) . "</p>";
                    } else {
                        echo "<p>No user data found or unexpected XML structure.</p>";
                    }
                    
                    echo "</div>";
                    echo "</div>";
                } else {
                    echo "<div class='alert alert-danger'>Failed to process XML.</div>";
                }
            } catch (Exception $e) {
                echo "<div class='alert alert-danger'>Error: " . htmlspecialchars($e->getMessage()) . "</div>";
            }
        } else {
            echo "<div class='alert alert-warning'>No XML data submitted.</div>";
        }
        ?>
        
        <div class="mt-3">
            <a href="index.php" class="btn btn-primary">Back to XXE Tests</a>
        </div>
    </div>
</body>
</html>
