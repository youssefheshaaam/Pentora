<?php
// Initialize or get the comments array from the session
session_start();
if (!isset($_SESSION['comments'])) {
    $_SESSION['comments'] = [];
}

// Handle comment submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['comment'])) {
    $name = isset($_POST['name']) ? $_POST['name'] : 'Anonymous';
    $comment = $_POST['comment'];
    
    // Vulnerable: No sanitization of user input
    $_SESSION['comments'][] = [
        'name' => $name,
        'comment' => $comment,
        'time' => date('Y-m-d H:i:s')
    ];
}

// Handle comment deletion (for testing purposes)
if (isset($_GET['clear']) && $_GET['clear'] === 'all') {
    $_SESSION['comments'] = [];
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Persistent XSS - Pentora Vulnerable Lab</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>Persistent XSS Vulnerability</h1>
        <div class="alert alert-danger">
            <strong>Warning:</strong> This page contains intentional persistent XSS vulnerabilities for testing purposes.
        </div>

        <div class="row">
            <div class="col-md-8 offset-md-2">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>Community Comments</h5>
                    </div>
                    <div class="card-body">
                        <form action="" method="POST">
                            <div class="mb-3">
                                <label for="name" class="form-label">Your Name:</label>
                                <input type="text" class="form-control" id="name" name="name" placeholder="Enter your name">
                            </div>
                            <div class="mb-3">
                                <label for="comment" class="form-label">Your Comment:</label>
                                <textarea class="form-control" id="comment" name="comment" rows="3" placeholder="Enter your comment" required></textarea>
                                <div class="form-text">Try: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></div>
                            </div>
                            <button type="submit" class="btn btn-primary">Post Comment</button>
                        </form>

                        <hr>

                        <h6 class="mt-4">Comments:</h6>
                        <?php if (empty($_SESSION['comments'])): ?>
                            <p class="text-muted">No comments yet. Be the first to comment!</p>
                        <?php else: ?>
                            <?php foreach ($_SESSION['comments'] as $comment): ?>
                                <div class="card mb-3">
                                    <div class="card-body">
                                        <h6 class="card-subtitle mb-2 text-muted">
                                            Posted by: <?php echo $comment['name']; ?> at <?php echo $comment['time']; ?>
                                        </h6>
                                        <p class="card-text">
                                            <?php 
                                            // Vulnerable: Directly outputting user input without sanitization
                                            echo $comment['comment']; 
                                            ?>
                                        </p>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                            <a href="?clear=all" class="btn btn-sm btn-danger">Clear All Comments</a>
                        <?php endif; ?>
                    </div>
                </div>

                <div class="card mb-4">
                    <div class="card-header">
                        <h5>User Profile (Another Persistent XSS Example)</h5>
                    </div>
                    <div class="card-body">
                        <?php
                        // Initialize or get the profile data from the session
                        if (!isset($_SESSION['profile'])) {
                            $_SESSION['profile'] = [
                                'username' => '',
                                'bio' => '',
                                'website' => ''
                            ];
                        }

                        // Handle profile update
                        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['bio'])) {
                            $_SESSION['profile'] = [
                                'username' => $_POST['username'] ?? '',
                                'bio' => $_POST['bio'] ?? '',
                                'website' => $_POST['website'] ?? ''
                            ];
                        }
                        ?>

                        <form action="" method="POST">
                            <div class="mb-3">
                                <label for="username" class="form-label">Username:</label>
                                <input type="text" class="form-control" id="username" name="username" 
                                    value="<?php echo $_SESSION['profile']['username']; ?>" placeholder="Enter your username">
                            </div>
                            <div class="mb-3">
                                <label for="bio" class="form-label">Bio:</label>
                                <textarea class="form-control" id="bio" name="bio" rows="3" 
                                    placeholder="Tell us about yourself"><?php echo $_SESSION['profile']['bio']; ?></textarea>
                                <div class="form-text">Try: <code>&lt;img src="x" onerror="alert('XSS')"&gt;</code></div>
                            </div>
                            <div class="mb-3">
                                <label for="website" class="form-label">Website:</label>
                                <input type="text" class="form-control" id="website" name="website" 
                                    value="<?php echo $_SESSION['profile']['website']; ?>" placeholder="Enter your website URL">
                                <div class="form-text">Try: <code>javascript:alert('XSS')</code></div>
                            </div>
                            <button type="submit" class="btn btn-primary">Update Profile</button>
                        </form>

                        <?php if (!empty($_SESSION['profile']['username']) || !empty($_SESSION['profile']['bio']) || !empty($_SESSION['profile']['website'])): ?>
                            <hr>
                            <h6 class="mt-4">Your Profile:</h6>
                            <div class="card">
                                <div class="card-body">
                                    <?php if (!empty($_SESSION['profile']['username'])): ?>
                                        <h5 class="card-title"><?php echo $_SESSION['profile']['username']; ?></h5>
                                    <?php endif; ?>
                                    
                                    <?php if (!empty($_SESSION['profile']['bio'])): ?>
                                        <p class="card-text">
                                            <?php 
                                            // Vulnerable: Directly outputting user input without sanitization
                                            echo $_SESSION['profile']['bio']; 
                                            ?>
                                        </p>
                                    <?php endif; ?>
                                    
                                    <?php if (!empty($_SESSION['profile']['website'])): ?>
                                        <p class="card-text">
                                            Website: <a href="<?php echo $_SESSION['profile']['website']; ?>">
                                                <?php echo $_SESSION['profile']['website']; ?>
                                            </a>
                                        </p>
                                    <?php endif; ?>
                                </div>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>

        <div class="card mb-4">
            <div class="card-header">
                <h5>About Persistent XSS</h5>
            </div>
            <div class="card-body">
                <p>Persistent (or Stored) XSS occurs when malicious scripts are injected into a website's database and later retrieved and displayed to other users.</p>
                <p>Unlike Reflected XSS, which requires a victim to click on a malicious link, Persistent XSS attacks can affect any user who visits the compromised page.</p>
                <p>Common vulnerable areas include:</p>
                <ul>
                    <li>Comment systems</li>
                    <li>User profiles</li>
                    <li>Forum posts</li>
                    <li>Product reviews</li>
                    <li>Any other feature that stores user input and displays it to other users</li>
                </ul>
                <p>To prevent Persistent XSS, always sanitize user input before storing it in a database and encode output when displaying it to users.</p>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
