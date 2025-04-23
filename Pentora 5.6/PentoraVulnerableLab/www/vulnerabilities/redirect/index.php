<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Open Redirect Vulnerabilities</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>Open Redirect Vulnerabilities</h1>
        <p class="lead">This section demonstrates various open redirect vulnerabilities that can be exploited to redirect users to malicious websites.</p>
        
        <div class="alert alert-danger">
            <strong>Warning:</strong> These examples demonstrate dangerous vulnerabilities. In a real application, always validate redirect URLs against a whitelist.
        </div>
        
        <div class="row mt-4">
            <div class="col-md-6">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>Basic Redirect</h5>
                    </div>
                    <div class="card-body">
                        <p>Click on the links below to test basic redirect functionality:</p>
                        <ul class="list-group mb-3">
                            <li class="list-group-item">
                                <a href="redirect.php?url=https://www.google.com">Redirect to Google</a>
                            </li>
                            <li class="list-group-item">
                                <a href="redirect.php?url=https://www.bing.com">Redirect to Bing</a>
                            </li>
                            <li class="list-group-item">
                                <a href="redirect.php?url=https://www.yahoo.com">Redirect to Yahoo</a>
                            </li>
                        </ul>
                        <div class="alert alert-warning">
                            <strong>Vulnerability:</strong> This endpoint performs no validation on the redirect URL.
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="col-md-6">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>Partial Validation Redirect</h5>
                    </div>
                    <div class="card-body">
                        <p>This redirect attempts to validate the URL but is still vulnerable:</p>
                        <ul class="list-group mb-3">
                            <li class="list-group-item">
                                <a href="redirect_partial.php?url=https://www.google.com">Redirect to Google</a>
                            </li>
                            <li class="list-group-item">
                                <a href="redirect_partial.php?url=https://www.bing.com">Redirect to Bing</a>
                            </li>
                            <li class="list-group-item">
                                <a href="redirect_partial.php?url=https://www.yahoo.com">Redirect to Yahoo</a>
                            </li>
                        </ul>
                        <div class="alert alert-warning">
                            <strong>Vulnerability:</strong> This endpoint performs incomplete validation that can be bypassed.
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="row">
            <div class="col-md-6">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>Login Redirect</h5>
                    </div>
                    <div class="card-body">
                        <p>This simulates a login page that redirects to a specified URL after login:</p>
                        <form action="login_redirect.php" method="post">
                            <input type="hidden" name="redirect_to" value="dashboard.php">
                            <div class="mb-3">
                                <label for="username" class="form-label">Username</label>
                                <input type="text" name="username" id="username" class="form-control" value="user" required>
                            </div>
                            <div class="mb-3">
                                <label for="password" class="form-label">Password</label>
                                <input type="password" name="password" id="password" class="form-control" value="password" required>
                            </div>
                            <button type="submit" class="btn btn-primary">Login</button>
                        </form>
                        <div class="alert alert-warning mt-3">
                            <strong>Vulnerability:</strong> The redirect_to parameter can be manipulated to redirect to any URL.
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="col-md-6">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>URL Shortener</h5>
                    </div>
                    <div class="card-body">
                        <p>Enter a URL to create a shortened link:</p>
                        <form action="shortener.php" method="post">
                            <div class="mb-3">
                                <label for="long_url" class="form-label">URL to Shorten</label>
                                <input type="url" name="long_url" id="long_url" class="form-control" placeholder="https://example.com" required>
                            </div>
                            <button type="submit" class="btn btn-primary">Create Short URL</button>
                        </form>
                        <div class="alert alert-warning mt-3">
                            <strong>Vulnerability:</strong> The URL shortener does not validate destination URLs.
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
