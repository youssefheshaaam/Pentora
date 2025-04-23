<?php
// Function to safely display XML output
function displayXmlOutput($output) {
    echo "<pre class='bg-dark text-light p-3 mt-3'>";
    if (empty($output)) {
        echo "No output or processing failed.";
    } else {
        echo htmlspecialchars($output);
    }
    echo "</pre>";
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XXE Vulnerabilities</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>XXE (XML External Entity) Vulnerabilities</h1>
        <p class="lead">This page contains various XXE vulnerabilities for testing Pentora.</p>
        
        <div class="alert alert-danger">
            <strong>Warning:</strong> These examples demonstrate dangerous vulnerabilities. In a real application, never process XML with external entities enabled.
        </div>
        
        <div class="row mt-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>Basic XXE</h5>
                    </div>
                    <div class="card-body">
                        <p>Process XML with external entities:</p>
                        <form action="process.php" method="post" class="mb-3">
                            <div class="mb-3">
                                <label for="xml1" class="form-label">XML Content</label>
                                <textarea name="xml" id="xml1" class="form-control" rows="8">&lt;?xml version="1.0" encoding="UTF-8"?&gt;
&lt;user&gt;
  &lt;username&gt;admin&lt;/username&gt;
  &lt;password&gt;password123&lt;/password&gt;
&lt;/user&gt;</textarea>
                            </div>
                            <button type="submit" class="btn btn-primary">Process XML</button>
                        </form>
                        <div class="alert alert-info">
                            <strong>Hint:</strong> Try using an external entity to read local files
                            <pre class="mt-2">&lt;!DOCTYPE user [
  &lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt;
]&gt;</pre>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>XXE via File Upload</h5>
                    </div>
                    <div class="card-body">
                        <p>Upload an XML file for processing:</p>
                        <form action="upload.php" method="post" enctype="multipart/form-data">
                            <div class="mb-3">
                                <label for="xmlFile" class="form-label">XML File</label>
                                <input type="file" name="xmlFile" id="xmlFile" class="form-control" accept=".xml">
                            </div>
                            <button type="submit" class="btn btn-primary">Upload & Process</button>
                        </form>
                        <div class="alert alert-info mt-3">
                            <strong>Hint:</strong> Create an XML file with malicious entities
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="row mt-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>XXE via SOAP Request</h5>
                    </div>
                    <div class="card-body">
                        <p>Send a SOAP request with XML entities:</p>
                        <form action="soap.php" method="post">
                            <div class="mb-3">
                                <label for="soap" class="form-label">SOAP Request</label>
                                <textarea name="soap" id="soap" class="form-control" rows="10">&lt;?xml version="1.0" encoding="UTF-8"?&gt;
&lt;soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"&gt;
  &lt;soap:Body&gt;
    &lt;getUser xmlns="http://example.org/user"&gt;
      &lt;id&gt;1&lt;/id&gt;
    &lt;/getUser&gt;
  &lt;/soap:Body&gt;
&lt;/soap:Envelope&gt;</textarea>
                            </div>
                            <button type="submit" class="btn btn-primary">Send Request</button>
                        </form>
                        <div class="alert alert-info mt-3">
                            <strong>Hint:</strong> Add a DOCTYPE with external entities to the SOAP request
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>XXE via SVG Upload</h5>
                    </div>
                    <div class="card-body">
                        <p>Upload an SVG image (XML-based format):</p>
                        <form action="svg.php" method="post" enctype="multipart/form-data">
                            <div class="mb-3">
                                <label for="svgFile" class="form-label">SVG Image</label>
                                <input type="file" name="svgFile" id="svgFile" class="form-control" accept=".svg">
                            </div>
                            <button type="submit" class="btn btn-primary">Upload SVG</button>
                        </form>
                        <div class="alert alert-info mt-3">
                            <strong>Hint:</strong> SVG files are XML-based and can contain XXE payloads
                            <pre class="mt-2">&lt;svg xmlns="http://www.w3.org/2000/svg"&gt;
  &lt;!DOCTYPE foo [ &lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt; ]&gt;
  &lt;text&gt;&xxe;&lt;/text&gt;
&lt;/svg&gt;</pre>
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
