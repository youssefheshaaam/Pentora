==================================
Pentora – Advanced Web and Network Security Scanner
==================================

Pentora is a comprehensive automated penetration testing framework designed to identify and address security vulnerabilities across both web applications and network infrastructures. 
With an intuitive graphical interface and modular architecture, Pentora makes advanced security assessments efficient, scalable, and accessible to professionals and non-experts alike.

About Pentora
============
Pentora combines powerful scanning capabilities with an easy-to-use interface, making advanced security testing accessible to both security professionals and developers.

The application requires Python 3.10 or 3.11 and automatically installs all necessary dependencies when using the setup script. Pentora offers full Windows support with its integrated GUI.

Scanning Methodology
============

Pentora employs dynamic analysis techniques to identify security weaknesses in web applications. Rather than examining source code, Pentora interacts with the live application by:

* Crawling the application to discover pages, forms, and endpoints
* Sending specially crafted inputs to test for vulnerabilities
* Analyzing responses for signs of security issues
* Generating detailed reports of discovered vulnerabilities

Key Capabilities
================

* Interactive graphical interface for easy scan configuration and monitoring
* Comprehensive HTML, PDF, and JSON vulnerability reporting
* Customizable attack module selection
* Color-coded terminal output for quick vulnerability identification
* Configurable scan parameters and depth


Security Tests
=================

Pentora can detect a wide range of web application vulnerabilities:

* SQL Injection (error-based, boolean-based, time-based)
* LDAP Injection (error-based, boolean-based)
* Cross-Site Scripting (reflected and stored)
* File Inclusion and Path Traversal
* Command Injection
* XML External Entity (XXE) Injection
* CRLF Injection
* Dangerous File Detection
* Backup File Discovery
* Shellshock Vulnerability
* Directory and File Enumeration
* Open Redirect Vulnerabilities
* HTTP Method Testing
* Content Security Policy Evaluation
* Login Form Brute Force Testing
* Security Header Analysis
* Cross-Site Request Forgery Detection


Pentora handles both GET and POST requests, supports multipart form submissions, and can inject payloads into file uploads. The scanner distinguishes between persistent and reflected vulnerabilities and highlights anomalies like server errors and timeouts.

Security Modules
============

Pentora's security tests are organized into specialized modules:

* backup - Identifies backup files and exposed source code
* brute_login_form - Tests login forms against common credentials
* buster - Performs directory and file enumeration
* cookieflags - Verifies secure cookie implementation
* crlf - Tests for HTTP header injection
* csp - Evaluates Content Security Policy configuration
* csrf - Identifies missing or weak CSRF protections
* exec - Detects command execution vulnerabilities
* file - Finds path traversal and file inclusion issues
* http_header - Analyzes HTTP security headers
* ldap - Discovers LDAP injection vulnerabilities
* methods - Tests for dangerous HTTP method support
* permanentxss - Identifies stored cross-site scripting
* redirect - Detects open redirect vulnerabilities
* shellshock - Tests for Shellshock vulnerability
* sql - Finds SQL injection vulnerabilities
* timesql - Detects time-based SQL injection
* upload - Identifies insecure file upload handling
* xss - Discovers reflected cross-site scripting
* xxe - Tests for XML External Entity vulnerabilities

Modules can be individually selected through the graphical interface to customize each scan.


Project Organization
================

The Pentora project consists of three main components:

* **PentoraCore**: The scanning engine that powers vulnerability detection
  - attack/ - Individual vulnerability detection modules
  - controller/ - Scan orchestration and management
  - data/ - Reference data for vulnerability detection
  - definitions/ - Vulnerability classification system
  - report/ - Report generation and CVSS scoring
  - See PentoraCore/README.md for detailed component information

* **pentora/**: The graphical user interface

* **PentoraVulnerableLab/**: A testing environment with intentional vulnerabilities
  - Contains examples of all detectable vulnerability types
  - Provides a controlled environment for testing and development
  - Includes documentation in PentoraVulnerableLab/README.md



Getting Started
=================

Launch the Pentora application and use the graphical interface to configure and run your security scans. The intuitive interface guides you through:

1. Setting the target URL
2. Configuring scan options and depth
3. Selecting vulnerability modules to test
4. Monitoring scan progress
5. Reviewing discovered vulnerabilities


Contributing
==========

To extend Pentora with new capabilities:

1. **Creating New Vulnerability Modules**:
   - Add a new module file to PentoraCore/attack/ following the naming convention mod_[vulnerability].py
   - Implement detection logic based on the attack module framework
   - Create corresponding vulnerability definitions in PentoraCore/definitions/
   - Update the CVSS scoring system in PentoraCore/report/cvss.py

2. **Testing New Modules**:
   - Use the PentoraVulnerableLab to verify detection accuracy
   - Test against both vulnerable and non-vulnerable targets
   - Ensure proper reporting of discovered issues

3. **Documentation**:
   - Update relevant README files with new capabilities
   - Document detection methods and limitations


Dependencies Explained
======================

Pentora relies on several key Python libraries to provide its comprehensive security scanning capabilities:

**Core Functionality**

* **aiohttp/httpx** - Asynchronous HTTP clients that enable efficient concurrent requests while preventing server overload
* **aiosqlite/sqlalchemy** - Database libraries for storing scan results and maintaining session state between scans
* **beautifulsoup4** - HTML parsing library essential for analyzing web page content and identifying injection points
* **arsenic** - Modified Selenium wrapper that enables headless browser automation for testing JavaScript-heavy applications

**Security Testing**

* **paramiko** - SSH implementation used for testing server configuration and remote command execution
* **cryptography/pyOpenSSL** - Cryptographic libraries for analyzing TLS/SSL implementations and certificate validation
* **mitmproxy** - Man-in-the-middle proxy that enables deep inspection of HTTP traffic for vulnerability detection
* **python-nmap** - Interface to Nmap for network scanning and service enumeration

**Reporting and Interface**

* **mako/markupsafe** - Template engine for generating comprehensive HTML vulnerability reports
* **PyQt5** - GUI framework that powers Pentora's intuitive graphical interface
* **loguru** - Advanced logging system that provides detailed information during scans
* **XlsxWriter** - Library for creating Excel-based reports with vulnerability findings

**Specialized Parsing**

* **prance** - OpenAPI/Swagger specification parser for testing REST API security
* **yaswfp** - Flash file parser for analyzing SWF vulnerabilities
* **tld/tldextract** - Domain parsing libraries for URL analysis and scope management

These dependencies work together to enable Pentora's comprehensive vulnerability scanning while maintaining a balance between thorough testing and preventing target website blocking through rate limiting and request throttling.


Legal Notice
==========

Pentora is designed for legitimate security testing. It performs intensive security assessments that may cause disruption to target systems.

Using Pentora against any system without explicit permission from the system owner is illegal. Users are solely responsible for ensuring compliance with applicable laws.

The developers of Pentora accept no liability for any misuse or damage resulting from the use of this software.
