<?php
// CRLF Email Header Injection Vulnerability Example

$name = isset($_POST['name']) ? $_POST['name'] : '';
$email = isset($_POST['email']) ? $_POST['email'] : '';
$message = isset($_POST['message']) ? $_POST['message'] : '';

$mailSent = false;
$mailHeaders = '';
$mailBody = '';

if (!empty($name) && !empty($email) && !empty($message)) {
    // Vulnerable code: directly using user input in email headers
    $to = "admin@example.com";
    $subject = "Contact Form Submission";
    
    // Vulnerable headers construction
    $mailHeaders = "From: " . $email . "\r\n";
    $mailHeaders .= "Reply-To: " . $email . "\r\n";
    $mailHeaders .= "X-Mailer: PHP/" . phpversion();
    
    $mailBody = "Name: " . $name . "\r\n";
    $mailBody .= "Email: " . $email . "\r\n";
    $mailBody .= "Message: " . $message;
    
    // In a real scenario, mail() would be called here
    // mail($to, $subject, $mailBody, $mailHeaders);
    
    // For demonstration purposes, we'll just simulate sending the email
    $mailSent = true;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Header Injection - Pentora Vulnerable Lab</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <?php if ($mailSent): ?>
            <div class="alert alert-success">
                <strong>Success!</strong> Your message has been sent.
            </div>
            
            <div class="card mb-4">
                <div class="card-header">
                    <h5>Email Details</h5>
                </div>
                <div class="card-body">
                    <h6>Headers:</h6>
                    <pre><?php echo htmlspecialchars($mailHeaders); ?></pre>
                    
                    <h6>Body:</h6>
                    <pre><?php echo htmlspecialchars($mailBody); ?></pre>
                    
                    <div class="alert alert-warning mt-3">
                        <strong>Note:</strong> In a real scenario, if the email address contains CRLF characters (%0D%0A), 
                        an attacker could inject additional headers like "Bcc:" to send the email to unintended recipients.
                    </div>
                </div>
            </div>
        <?php else: ?>
            <div class="alert alert-info">
                <strong>Note:</strong> Please fill out the form on the previous page to test email header injection.
            </div>
        <?php endif; ?>
        
        <a href="index.php" class="btn btn-primary">Back to CRLF Injection Tests</a>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
