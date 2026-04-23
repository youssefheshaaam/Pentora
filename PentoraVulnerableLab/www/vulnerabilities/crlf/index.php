<?php
// CRLF Injection Vulnerability Example
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CRLF Injection - Pentora Vulnerable Lab</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>CRLF Injection</h1>
        <div class="alert alert-danger">
            <strong>Warning:</strong> This page contains intentional CRLF injection vulnerabilities for testing purposes.
        </div>

        <div class="row">
            <div class="col-md-6">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>Header Injection</h5>
                    </div>
                    <div class="card-body">
                        <form action="header_injection.php" method="GET">
                            <div class="mb-3">
                                <label for="redirectUrl" class="form-label">Redirect URL:</label>
                                <input type="text" class="form-control" id="redirectUrl" name="url" placeholder="Enter URL">
                                <div class="form-text">Try: example.com%0D%0ASet-Cookie:+crlf=injection</div>
                            </div>
                            <button type="submit" class="btn btn-primary">Redirect</button>
                        </form>
                    </div>
                </div>
            </div>

            <div class="col-md-6">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>Log Poisoning</h5>
                    </div>
                    <div class="card-body">
                        <form action="log_poisoning.php" method="GET">
                            <div class="mb-3">
                                <label for="username" class="form-label">Username:</label>
                                <input type="text" class="form-control" id="username" name="username" placeholder="Enter username">
                                <div class="form-text">Try: user%0D%0A%0D%0A&lt;script&gt;alert('XSS')&lt;/script&gt;</div>
                            </div>
                            <button type="submit" class="btn btn-primary">Log Activity</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-md-6">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>HTTP Response Splitting</h5>
                    </div>
                    <div class="card-body">
                        <form action="response_splitting.php" method="GET">
                            <div class="mb-3">
                                <label for="language" class="form-label">Language:</label>
                                <input type="text" class="form-control" id="language" name="lang" placeholder="Enter language (e.g., en, fr, es)">
                                <div class="form-text">Try: en%0D%0AContent-Length:+0%0D%0A%0D%0AHTTP/1.1+200+OK%0D%0AContent-Type:+text/html%0D%0A%0D%0A&lt;html&gt;&lt;body&gt;Fake+Content&lt;/body&gt;&lt;/html&gt;</div>
                            </div>
                            <button type="submit" class="btn btn-primary">Set Language</button>
                        </form>
                    </div>
                </div>
            </div>

            <div class="col-md-6">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>Email Header Injection</h5>
                    </div>
                    <div class="card-body">
                        <form action="email_injection.php" method="POST">
                            <div class="mb-3">
                                <label for="name" class="form-label">Your Name:</label>
                                <input type="text" class="form-control" id="name" name="name" placeholder="Enter your name">
                            </div>
                            <div class="mb-3">
                                <label for="email" class="form-label">Your Email:</label>
                                <input type="text" class="form-control" id="email" name="email" placeholder="Enter your email">
                                <div class="form-text">Try: user@example.com%0D%0ABcc:+victim@example.com</div>
                            </div>
                            <div class="mb-3">
                                <label for="message" class="form-label">Message:</label>
                                <textarea class="form-control" id="message" name="message" rows="3" placeholder="Enter your message"></textarea>
                            </div>
                            <button type="submit" class="btn btn-primary">Send Message</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>

        <div class="card mb-4">
            <div class="card-header">
                <h5>About CRLF Injection</h5>
            </div>
            <div class="card-body">
                <p>CRLF (Carriage Return Line Feed) Injection is a vulnerability that occurs when an attacker is able to inject a CRLF sequence (%0D%0A) into an application.</p>
                <p>This can lead to various attacks, including:</p>
                <ul>
                    <li><strong>HTTP Response Splitting:</strong> Manipulating HTTP responses to perform attacks like XSS or phishing</li>
                    <li><strong>Header Injection:</strong> Adding custom headers to HTTP responses</li>
                    <li><strong>Log Poisoning:</strong> Injecting malicious content into log files</li>
                    <li><strong>Email Header Injection:</strong> Manipulating email headers to send emails to unintended recipients</li>
                </ul>
                <p>To prevent CRLF Injection, applications should validate and sanitize user input, especially when it's used in HTTP headers or log files.</p>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
