<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XXE - SOAP Request</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>XXE - SOAP Request</h1>
        
        <?php
        // Vulnerable XXE via SOAP request
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['soap'])) {
            $soap_data = $_POST['soap'];
            
            echo "<div class='alert alert-info'>";
            echo "Processing SOAP request...";
            echo "</div>";
            
            // Display the input SOAP
            echo "<div class='card mt-3 mb-3'>";
            echo "<div class='card-header'>Input SOAP Request</div>";
            echo "<div class='card-body'>";
            echo "<pre class='bg-light p-3'>" . htmlspecialchars($soap_data) . "</pre>";
            echo "</div>";
            echo "</div>";
            
            // Vulnerable code - XML processing with external entities enabled
            $dom = new DOMDocument();
            
            // Disable entity loading would prevent the vulnerability
            // $dom->loadXML($soap_data, LIBXML_NOENT | LIBXML_DTDLOAD);
            
            // But we're intentionally allowing it for the vulnerable lab
            libxml_disable_entity_loader(false);
            
            try {
                $result = $dom->loadXML($soap_data, LIBXML_NOENT | LIBXML_DTDLOAD);
                
                if ($result) {
                    echo "<div class='alert alert-success'>SOAP request processed successfully!</div>";
                    
                    // Display the processed SOAP
                    echo "<div class='card mt-3'>";
                    echo "<div class='card-header'>Processed SOAP Request</div>";
                    echo "<div class='card-body'>";
                    echo "<pre class='bg-dark text-light p-3'>" . htmlspecialchars($dom->saveXML()) . "</pre>";
                    echo "</div>";
                    echo "</div>";
                    
                    // Extract and display user ID
                    echo "<div class='card mt-3'>";
                    echo "<div class='card-header'>SOAP Response</div>";
                    echo "<div class='card-body'>";
                    
                    $xpath = new DOMXPath($dom);
                    $xpath->registerNamespace('soap', 'http://schemas.xmlsoap.org/soap/envelope/');
                    $xpath->registerNamespace('u', 'http://example.org/user');
                    
                    $id_nodes = $xpath->query('//u:id');
                    
                    if ($id_nodes->length > 0) {
                        $user_id = $id_nodes->item(0)->nodeValue;
                        
                        // Generate a mock SOAP response
                        echo "<pre class='bg-light p-3'>";
                        echo htmlspecialchars('<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <getUserResponse xmlns="http://example.org/user">
      <user>
        <id>' . $user_id . '</id>
        <username>user' . $user_id . '</username>
        <email>user' . $user_id . '@example.com</email>
        <role>user</role>
      </user>
    </getUserResponse>
  </soap:Body>
</soap:Envelope>');
                        echo "</pre>";
                    } else {
                        echo "<p>Could not find user ID in the request.</p>";
                    }
                    
                    echo "</div>";
                    echo "</div>";
                } else {
                    echo "<div class='alert alert-danger'>Failed to process SOAP request.</div>";
                }
            } catch (Exception $e) {
                echo "<div class='alert alert-danger'>Error: " . htmlspecialchars($e->getMessage()) . "</div>";
            }
        } else {
            echo "<div class='alert alert-warning'>No SOAP request submitted.</div>";
        }
        ?>
        
        <div class="mt-3">
            <a href="index.php" class="btn btn-primary">Back to XXE Tests</a>
        </div>
    </div>
</body>
</html>
