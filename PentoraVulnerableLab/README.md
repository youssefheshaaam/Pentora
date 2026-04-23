# Pentora Vulnerable Lab

A purposely vulnerable web application designed for testing Pentora's vulnerability scanning capabilities.

## Quick Start

### Windows
```
run_lab.bat
```

### Linux/macOS
```
chmod +x run_lab.sh
./run_lab.sh
```

Then access the lab at: http://localhost:8000

## Implemented Vulnerabilities

The Pentora Vulnerable Lab includes the following vulnerabilities that align with Pentora's scanning capabilities:

### Fully Implemented
1. **SQL Injection** - Various forms of SQL injection vulnerabilities
2. **Time-based SQL Injection** - SQL injection detectable through time delays
3. **XSS (Cross-Site Scripting)** - Reflected XSS vulnerabilities
4. **Persistent XSS** - Stored XSS vulnerabilities
5. **Command Execution** - OS command injection vulnerabilities
6. **File Upload** - Insecure file upload vulnerabilities
7. **XXE (XML External Entity)** - XML external entity vulnerabilities
8. **CSRF (Cross-Site Request Forgery)** - Cross-site request forgery vulnerabilities
9. **Path Traversal** - Directory traversal vulnerabilities
10. **Open Redirect** - Open redirect vulnerabilities
11. **CRLF Injection** - HTTP response splitting vulnerabilities
12. **HTTP Headers** - Insecure HTTP header handling
13. **LDAP Injection** - LDAP injection vulnerabilities
14. **HTTP Methods** - Insecure HTTP method handling
15. **Backup Files** - Accessible backup file vulnerabilities
16. **Content Security Policy (CSP)** - Misconfigured CSP headers
17. **Brute Force Login** - Weak authentication mechanisms
18. **Directory Buster** - Insecure directory listing
19. **Shellshock** - Shellshock vulnerability simulation

## Lab Structure

Each vulnerability type has its own directory under `/vulnerabilities/`, with dedicated endpoints demonstrating different variations of each vulnerability.

## Vulnerability Categories

The vulnerabilities in this lab are categorized based on their impact and attack vector:

### Injection Vulnerabilities
- SQL Injection
- Time-based SQL Injection
- Command Execution
- LDAP Injection
- XXE (XML External Entity)

### Client-Side Vulnerabilities
- XSS (Cross-Site Scripting)
- Persistent XSS
- CSRF (Cross-Site Request Forgery)
- Content Security Policy (CSP)

### Access Control Vulnerabilities
- Path Traversal
- Directory Buster
- Backup Files
- Brute Force Login

### Request Handling Vulnerabilities
- Open Redirect
- CRLF Injection
- HTTP Headers
- HTTP Methods

## Detection Methods

Pentora detects vulnerabilities in this lab through:
1. **Status code differences** between normal and malicious requests
2. **Specific patterns or error messages** in the response content
3. **Time-based detection** for vulnerabilities like time-based SQL injection
4. **Behavioral differences** in how the application handles different inputs
5. **Header analysis** for security header vulnerabilities
6. **Response content analysis** for data leakage and information disclosure

## For Developers

### Adding New Vulnerabilities
To add a new vulnerability type:
1. Create a new directory under `/vulnerabilities/`
2. Implement the vulnerable endpoints
3. Add the vulnerability to the main index.php page
4. Update this README.md file

### Testing with Pentora
This lab is specifically designed to work with Pentora's scanning modules:
- Each vulnerability corresponds to a specific attack module in Pentora
- Different variations of each vulnerability are included to test Pentora's detection capabilities

## Stopping the Lab

To stop the lab:
```
docker stop pentora-lab
```

To remove the container:
```
docker rm pentora-lab
```

## Security Warning

This application is intentionally vulnerable and should NEVER be deployed in a production environment or exposed to the public internet. It is designed solely for testing and educational purposes in a controlled environment.
