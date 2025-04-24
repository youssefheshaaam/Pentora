<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Include Template</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>Template Inclusion</h1>
        
        <?php
        // Create templates directory and sample templates if they don't exist
        $templates_dir = "templates";
        if (!file_exists($templates_dir)) {
            mkdir($templates_dir, 0777, true);
            
            // Create sample templates
            file_put_contents("$templates_dir/header.php", "<!-- Header Template -->
<div class='p-3 bg-primary text-white mb-4'>
    <h2>Website Header</h2>
    <p>This is the header template that appears at the top of each page.</p>
</div>");
            
            file_put_contents("$templates_dir/footer.php", "<!-- Footer Template -->
<div class='p-3 bg-dark text-white mt-4'>
    <p>&copy; " . date('Y') . " Vulnerable Web Application</p>
    <p>This is the footer template that appears at the bottom of each page.</p>
</div>");
            
            file_put_contents("$templates_dir/sidebar.php", "<!-- Sidebar Template -->
<div class='p-3 bg-light border mb-4'>
    <h4>Sidebar Navigation</h4>
    <ul class='nav flex-column'>
        <li class='nav-item'><a class='nav-link' href='#'>Home</a></li>
        <li class='nav-item'><a class='nav-link' href='#'>About</a></li>
        <li class='nav-item'><a class='nav-link' href='#'>Services</a></li>
        <li class='nav-item'><a class='nav-link' href='#'>Contact</a></li>
    </ul>
</div>");
        }
        
        if (isset($_GET['template'])) {
            $template = $_GET['template'];
            
            echo "<div class='alert alert-info'>";
            echo "Including template: <strong>" . htmlspecialchars($template) . "</strong>";
            echo "</div>";
            
            // Vulnerable code - allows directory traversal and PHP execution
            $template_path = "templates/" . $template . ".php";
            
            // A secure implementation would validate against a whitelist
            // $valid_templates = ['header', 'footer', 'sidebar'];
            // if (in_array($template, $valid_templates)) {
            //     $template_path = "templates/" . $template . ".php";
            // }
            
            echo "<div class='card mt-3 mb-3'>";
            echo "<div class='card-header'>Template Output</div>";
            echo "<div class='card-body'>";
            
            if (file_exists($template_path)) {
                // This is vulnerable to both path traversal and remote/local file inclusion
                include($template_path);
            } else {
                echo "<div class='alert alert-danger'>";
                echo "Template not found: " . htmlspecialchars($template_path);
                echo "</div>";
            }
            
            echo "</div>";
            echo "</div>";
            
            // Display the template source code
            if (file_exists($template_path)) {
                echo "<div class='card mt-3'>";
                echo "<div class='card-header'>Template Source Code</div>";
                echo "<div class='card-body'>";
                echo "<pre class='bg-light p-3'>" . htmlspecialchars(file_get_contents($template_path)) . "</pre>";
                echo "</div>";
                echo "</div>";
            }
        } else {
            echo "<div class='alert alert-warning'>";
            echo "No template specified.";
            echo "</div>";
        }
        ?>
        
        <div class="mt-4">
            <a href="index.php" class="btn btn-primary">Back to Path Traversal Tests</a>
        </div>
    </div>
</body>
</html>
