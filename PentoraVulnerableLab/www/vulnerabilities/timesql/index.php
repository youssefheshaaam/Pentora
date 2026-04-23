<?php
// Time-based SQL Injection Vulnerability Example
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Time-based SQL Injection - Pentora Vulnerable Lab</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>Time-based SQL Injection</h1>
        <div class="alert alert-danger">
            <strong>Warning:</strong> This page contains intentional time-based SQL injection vulnerabilities for testing purposes.
        </div>

        <div class="row">
            <div class="col-md-6">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>User Search (Time-based SQL Injection)</h5>
                    </div>
                    <div class="card-body">
                        <form action="" method="GET">
                            <div class="mb-3">
                                <label for="userId" class="form-label">User ID:</label>
                                <input type="text" class="form-control" id="userId" name="id" placeholder="Enter user ID">
                                <div class="form-text">Try: 1 OR SLEEP(2)</div>
                            </div>
                            <button type="submit" class="btn btn-primary">Search</button>
                        </form>

                        <?php
                        if (isset($_GET['id'])) {
                            $id = $_GET['id'];
                            echo "<div class='mt-4'>";
                            echo "<h6>Query executed:</h6>";
                            echo "<pre>SELECT * FROM users WHERE id = $id</pre>";
                            
                            // Simulate database query execution time
                            $decoded_id = urldecode($id);
                            if (stripos($decoded_id, 'sleep') !== false || 
                                stripos($decoded_id, 'benchmark') !== false || 
                                stripos($decoded_id, 'pg_sleep') !== false || 
                                stripos($decoded_id, 'waitfor') !== false) {
                                $start_time = microtime(true);
                                // Extract sleep time if possible
                                if (preg_match('/sleep\s*\(\s*(\d+)\s*\)/i', $decoded_id, $matches)) {
                                    $sleep_time = intval($matches[1]);
                                    // Cap at 7 seconds to ensure Pentora detects it
                                    $sleep_time = min($sleep_time, 7);
                                    sleep($sleep_time);
                                } else if (preg_match('/pg_sleep\s*\(\s*(\d+)\s*\)/i', $decoded_id, $matches)) {
                                    $sleep_time = intval($matches[1]);
                                    $sleep_time = min($sleep_time, 7);
                                    sleep($sleep_time);
                                } else if (preg_match('/waitfor\s+delay\s+[\'"]0:0:(\d+)[\'"]/', $decoded_id, $matches)) {
                                    $sleep_time = intval($matches[1]);
                                    $sleep_time = min($sleep_time, 7);
                                    sleep($sleep_time);
                                } else {
                                    // Default sleep
                                    sleep(7);
                                }
                                $end_time = microtime(true);
                                echo "<div class='alert alert-warning'>Query took " . round($end_time - $start_time, 2) . " seconds to execute.</div>";
                                echo "<div class='alert alert-success'>Vulnerability successfully exploited! The server delayed its response.</div>";
                            } else {
                                echo "<div class='alert alert-info'>Query executed instantly. No time-based injection detected.</div>";
                                echo "<p>Results would appear here if this were a real database.</p>";
                            }
                            echo "</div>";
                        }
                        ?>
                    </div>
                </div>
            </div>

            <div class="col-md-6">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>Product Search (Blind Time-based SQL Injection)</h5>
                    </div>
                    <div class="card-body">
                        <form action="" method="GET">
                            <div class="mb-3">
                                <label for="productCategory" class="form-label">Product Category:</label>
                                <input type="text" class="form-control" id="productCategory" name="category" placeholder="Enter product category">
                                <div class="form-text">Try: electronics' AND (SELECT CASE WHEN (1=1) THEN SLEEP(2) ELSE 0 END) -- </div>
                            </div>
                            <button type="submit" class="btn btn-primary">Search</button>
                        </form>

                        <?php
                        if (isset($_GET['category'])) {
                            $category = $_GET['category'];
                            echo "<div class='mt-4'>";
                            echo "<h6>Query executed:</h6>";
                            echo "<pre>SELECT * FROM products WHERE category = '$category'</pre>";
                            
                            // Simulate database query execution time
                            $decoded_category = urldecode($category);
                            if (stripos($decoded_category, 'sleep') !== false || 
                                stripos($decoded_category, 'benchmark') !== false || 
                                stripos($decoded_category, 'pg_sleep') !== false || 
                                stripos($decoded_category, 'waitfor') !== false) {
                                $start_time = microtime(true);
                                // Extract sleep time if possible
                                if (preg_match('/sleep\s*\(\s*(\d+)\s*\)/i', $decoded_category, $matches)) {
                                    $sleep_time = intval($matches[1]);
                                    // Cap at 7 seconds to ensure Pentora detects it
                                    $sleep_time = min($sleep_time, 7);
                                    sleep($sleep_time);
                                } else if (preg_match('/pg_sleep\s*\(\s*(\d+)\s*\)/i', $decoded_category, $matches)) {
                                    $sleep_time = intval($matches[1]);
                                    $sleep_time = min($sleep_time, 7);
                                    sleep($sleep_time);
                                } else if (preg_match('/waitfor\s+delay\s+[\'"]0:0:(\d+)[\'"]/', $decoded_category, $matches)) {
                                    $sleep_time = intval($matches[1]);
                                    $sleep_time = min($sleep_time, 7);
                                    sleep($sleep_time);
                                } else {
                                    // Default sleep
                                    sleep(7);
                                }
                                $end_time = microtime(true);
                                echo "<div class='alert alert-warning'>Query took " . round($end_time - $start_time, 2) . " seconds to execute.</div>";
                                echo "<div class='alert alert-success'>Vulnerability successfully exploited! The server delayed its response.</div>";
                            } else {
                                echo "<div class='alert alert-info'>Query executed instantly. No time-based injection detected.</div>";
                                echo "<p>Results would appear here if this were a real database.</p>";
                            }
                            echo "</div>";
                        }
                        ?>
                    </div>
                </div>
            </div>
        </div>

        <div class="card mb-4">
            <div class="card-header">
                <h5>About Time-based SQL Injection</h5>
            </div>
            <div class="card-body">
                <p>Time-based SQL injection is a type of blind SQL injection attack where the attacker can infer if their injection was successful based on the time it takes for the server to respond.</p>
                <p>Common techniques include:</p>
                <ul>
                    <li><code>SLEEP(seconds)</code> - MySQL function that pauses execution</li>
                    <li><code>pg_sleep(seconds)</code> - PostgreSQL function</li>
                    <li><code>WAITFOR DELAY 'time'</code> - SQL Server function</li>
                    <li><code>BENCHMARK(count, expr)</code> - MySQL function that executes an expression multiple times</li>
                </ul>
                <p>These attacks are particularly dangerous because they can be used to extract data from a database even when error messages are suppressed and no results are returned to the user.</p>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
