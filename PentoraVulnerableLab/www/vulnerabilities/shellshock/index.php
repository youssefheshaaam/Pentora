<?php
// Shellshock Vulnerability Example
include_once '../../includes/header.php';

// Initialize variables
$command = isset($_POST['command']) ? $_POST['command'] : 'echo "Hello, World!"';
$userAgent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
$output = '';
$userAgentOutput = '';
$shellshockAttempt = false;

// Function to simulate a CGI script that would be vulnerable to Shellshock
function simulateVulnerableCGI($command) {
    // In a real vulnerable system, this would execute in a bash environment
    // For demonstration purposes, we'll just show what would happen
    
    // Create a simulated environment
    $env = [
        'HTTP_USER_AGENT' => isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '',
        'HTTP_REFERER' => isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '',
        'REMOTE_ADDR' => isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '',
        'REQUEST_METHOD' => isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : '',
        'QUERY_STRING' => isset($_SERVER['QUERY_STRING']) ? $_SERVER['QUERY_STRING'] : '',
    ];
    
    // Log the command for demonstration
    file_put_contents('cgi.log', date('Y-m-d H:i:s') . " - Command: $command\n", FILE_APPEND);
    
    // Check for Shellshock in environment variables
    foreach ($env as $name => $value) {
        if (detectShellshockPayload($value)) {
            // Log the Shellshock attempt
            file_put_contents('cgi.log', date('Y-m-d H:i:s') . " - SHELLSHOCK EXPLOITATION ATTEMPT DETECTED in $name: $value\n", FILE_APPEND);
            
            // Return a 500 error to simulate the vulnerability being exploited
            http_response_code(500);
            
            // Return information about the detected payload
            return "VULNERABILITY DETECTED: Shellshock exploitation attempt in $name header";
        }
    }
    
    // In a real system, this would be vulnerable to Shellshock
    // We'll simulate the command execution for demonstration
    if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
        // Windows
        $output = shell_exec("cmd /c $command 2>&1");
    } else {
        // Unix-like
        $output = shell_exec("$command 2>&1");
    }
    
    return $output;
}

// Function to check if a User-Agent header contains a Shellshock payload
function detectShellshockPayload($userAgent) {
    // Look for the specific pattern that indicates a Shellshock attack attempt
    // The basic pattern is: () { :;}; command
    return (strpos($userAgent, '() {') !== false);
}

// Function to extract and execute command from Shellshock payload
function extractShellshockCommand($header) {
    if (preg_match('/\(\)\s*{\s*:;\s*}\s*;(.+)/', $header, $matches)) {
        $command = trim($matches[1]);
        
        // For demonstration, we'll simulate command execution
        // In a real vulnerable system, this would actually execute
        if (strpos($command, 'echo') !== false) {
            // Extract the string to echo
            if (preg_match('/echo\s*-e\s*\'(.+)\'/', $command, $echo_matches)) {
                // This simulates the behavior that Pentora is looking for
                // It echoes back the random string that Pentora's scanner sends
                $hex_string = $echo_matches[1];
                // Convert hex string back to ASCII
                $result = '';
                $hex_pairs = explode('\\x', substr($hex_string, 0));
                foreach ($hex_pairs as $pair) {
                    if (strlen($pair) >= 2) {
                        $result .= chr(hexdec(substr($pair, 0, 2)));
                    }
                }
                return $result;
            }
            return "Simulated command execution: " . $command;
        }
        return "Simulated command execution: " . $command;
    }
    return null;
}

// Handle command form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['execute'])) {
    $output = simulateVulnerableCGI($command);
}

// Check if User-Agent contains a Shellshock payload
$shellshockAttempt = detectShellshockPayload($userAgent);
if ($shellshockAttempt) {
    $userAgentOutput = extractShellshockCommand($userAgent);
}

// Also check other headers that might contain Shellshock payloads
$referer = isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '';
$cookie = isset($_SERVER['HTTP_COOKIE']) ? $_SERVER['HTTP_COOKIE'] : '';

$refererOutput = '';
$cookieOutput = '';

if (detectShellshockPayload($referer)) {
    $refererOutput = extractShellshockCommand($referer);
}

if (detectShellshockPayload($cookie)) {
    $cookieOutput = extractShellshockCommand($cookie);
}

// Create the log file if it doesn't exist
if (!file_exists('cgi.log')) {
    file_put_contents('cgi.log', date('Y-m-d H:i:s') . " - CGI Log Initialized\n");
}

// Log Shellshock attempts
if ($shellshockAttempt || detectShellshockPayload($referer) || detectShellshockPayload($cookie)) {
    file_put_contents('cgi.log', date('Y-m-d H:i:s') . " - Shellshock attempt detected!\n", FILE_APPEND);
    file_put_contents('cgi.log', date('Y-m-d H:i:s') . " - User-Agent: $userAgent\n", FILE_APPEND);
    file_put_contents('cgi.log', date('Y-m-d H:i:s') . " - Referer: $referer\n", FILE_APPEND);
    file_put_contents('cgi.log', date('Y-m-d H:i:s') . " - Cookie: $cookie\n", FILE_APPEND);
}
?>

<div class="container mt-5">
    <h1>Shellshock (CVE-2014-6271) Vulnerability</h1>
    <div class="alert alert-danger">
        <strong>Warning:</strong> This page simulates the Shellshock vulnerability for educational purposes. In a real vulnerable system, the commands would be executed by a bash shell (versions before 4.3).
    </div>
    
    <div class="row">
        <div class="col-md-6">
            <div class="card mb-4">
                <div class="card-header">
                    <h5>Simulated CGI Script</h5>
                </div>
                <div class="card-body">
                    <p>This simulates a CGI script that would be vulnerable to Shellshock. Enter a command to execute:</p>
                    
                    <form method="post" action="">
                        <div class="mb-3">
                            <label for="command" class="form-label">Command</label>
                            <input type="text" class="form-control" id="command" name="command" value="<?php echo htmlspecialchars($command); ?>">
                        </div>
                        <button type="submit" name="execute" class="btn btn-primary">Execute</button>
                    </form>
                    
                    <?php if ($output): ?>
                        <div class="mt-3">
                            <h6>Command Output:</h6>
                            <pre class="bg-dark text-light p-3"><?php echo htmlspecialchars($output); ?></pre>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
        
        <div class="col-md-6">
            <div class="card mb-4">
                <div class="card-header">
                    <h5>Shellshock Detection</h5>
                </div>
                <div class="card-body">
                    <p>This section shows if a Shellshock attack was detected in the HTTP headers:</p>
                    
                    <?php if ($shellshockAttempt): ?>
                        <div class="alert alert-warning">
                            <strong>Shellshock attempt detected in User-Agent header!</strong>
                        </div>
                        <?php if ($userAgentOutput): ?>
                            <div class="mt-3">
                                <h6>Extracted Command Output:</h6>
                                <pre class="bg-dark text-light p-3"><?php echo htmlspecialchars($userAgentOutput); ?></pre>
                            </div>
                        <?php endif; ?>
                    <?php endif; ?>
                    
                    <?php if (detectShellshockPayload($referer)): ?>
                        <div class="alert alert-warning">
                            <strong>Shellshock attempt detected in Referer header!</strong>
                        </div>
                        <?php if ($refererOutput): ?>
                            <div class="mt-3">
                                <h6>Extracted Command Output:</h6>
                                <pre class="bg-dark text-light p-3"><?php echo htmlspecialchars($refererOutput); ?></pre>
                            </div>
                        <?php endif; ?>
                    <?php endif; ?>
                    
                    <?php if (detectShellshockPayload($cookie)): ?>
                        <div class="alert alert-warning">
                            <strong>Shellshock attempt detected in Cookie header!</strong>
                        </div>
                        <?php if ($cookieOutput): ?>
                            <div class="mt-3">
                                <h6>Extracted Command Output:</h6>
                                <pre class="bg-dark text-light p-3"><?php echo htmlspecialchars($cookieOutput); ?></pre>
                            </div>
                        <?php endif; ?>
                    <?php endif; ?>
                    
                    <?php if (!$shellshockAttempt && !detectShellshockPayload($referer) && !detectShellshockPayload($cookie)): ?>
                        <div class="alert alert-info">
                            No Shellshock attempt detected.
                        </div>
                    <?php endif; ?>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <h5>How to Test for Shellshock</h5>
                </div>
                <div class="card-body">
                    <p>To test for the Shellshock vulnerability, you can use tools like curl with a malicious User-Agent:</p>
                    <pre class="bg-dark text-light p-3">curl -A "() { :;}; echo vulnerable" http://example.com/cgi-bin/script</pre>
                    <p>For Pentora's scanner to detect this vulnerability, it sends specially crafted headers and looks for its payload in the response.</p>
                </div>
            </div>
        </div>
    </div>
</div>

<?php 
// Output any detected Shellshock payload to make it visible to scanners
if ($userAgentOutput) {
    echo "<!-- $userAgentOutput -->";
}
if ($refererOutput) {
    echo "<!-- $refererOutput -->";
}
if ($cookieOutput) {
    echo "<!-- $cookieOutput -->";
}

include_once '../../includes/footer.php'; 
?>
