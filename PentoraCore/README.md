# PentoraCore

PentoraCore is the core engine of the Pentora vulnerability scanner. This directory contains all the components necessary for vulnerability scanning, reporting, and management.

## Directory Structure

### `attack/`
Contains all the vulnerability scanning modules that perform actual security tests.

- **Purpose**: Implements specific vulnerability detection techniques
- **Key Components**:
  - `attack.py`: Base class for all attack modules and core scanning logic
  - `mod_sql.py`: SQL injection detection
  - `mod_xss.py`: Cross-site scripting detection
  - `mod_csrf.py`: Cross-site request forgery detection
  - `mod_file.py`: Path traversal detection
  - `mod_exec.py`: Command execution detection
  - `mod_xxe.py`: XML external entity detection
  - `mod_upload.py`: Unrestricted file upload detection
  - `mod_permanentxss.py`: Stored XSS detection
  - `mod_timesql.py`: Time-based SQL injection detection
  - `mod_ldap.py`: LDAP injection detection
  - `mod_http_headers.py`: HTTP header security issues detection
  - `mod_methods.py`: HTTP methods testing
  - `mod_backup.py`: Backup file detection
  - `mod_csp.py`: Content Security Policy testing
  - `mod_brute_login_form.py`: Login form brute forcing
  - `mod_buster.py`: Directory and file enumeration
  - `mod_crlf.py`: CRLF injection detection
  - `mod_redirect.py`: Open redirect detection
  - `mod_shellshock.py`: Shellshock vulnerability detection

### `controller/`
Manages the flow and execution of the scanning process.

- **Purpose**: Orchestrates the scanning workflow and user interactions
- **Key Components**:
  - Configuration management
  - Scan session control
  - User input processing
  - Attack module coordination

### `data/`
Stores static data files used by the scanning modules.

- **Purpose**: Provides resources needed by attack modules
- **Key Components**:
  - Wordlists for brute force attacks
  - Payload collections for various vulnerability types
  - Signatures for vulnerability detection
  - Common patterns for path traversal, SQL injection, etc.
  - Regular expressions for pattern matching

### `definitions/`
Contains vulnerability definition classes.

- **Purpose**: Defines vulnerability types, severity levels, and remediation advice
- **Key Components**:
  - `base.py`: Base class for all vulnerability definitions
  - Individual definition files for each vulnerability type (e.g., `sql.py`, `xss.py`)
  - Vulnerability classification logic
  - Remediation recommendations
  - Risk assessment guidelines

### `language/`
Handles internationalization and language-specific content.

- **Purpose**: Provides multilingual support for the application
- **Key Components**:
  - `language.py`: Translation and localization functions
  - `vulnerability.py`: Vulnerability severity levels and messaging
  - Text resources for user interfaces and reports

### `main/`
Contains the entry points and core initialization code.

- **Purpose**: Bootstraps the application and provides main execution flow
- **Key Components**:
  - Command-line argument parsing
  - Configuration loading
  - Logging setup
  - Application initialization

### `model/`
Defines data structures and object models.

- **Purpose**: Provides core data structures used throughout the application
- **Key Components**:
  - `PayloadInfo`: Represents attack payloads
  - Data models for scan results, configurations, and other entities

### `mutation/`
Implements payload mutation and transformation techniques.

- **Purpose**: Modifies attack payloads to bypass security filters
- **Key Components**:
  - `json_mutator.py`: JSON payload manipulation functions
    - `find_injectable()`: Identifies injectable points in JSON structures
    - `set_item()`: Modifies values at specific paths in JSON objects
    - `get_item()`: Retrieves values from specific paths in JSON objects

### `net/`
Handles network operations and HTTP communication.

- **Purpose**: Manages all network interactions with target systems
- **Key Components**:
  - `AsyncCrawler`: Web crawling functionality
  - `SqlPersister`: Database storage for scan results
  - HTTP request and response handling
  - Session management
  - Cookie handling
  - Request queueing and rate limiting

### `parsers/`
Contains parsers for different file formats and protocols.

- **Purpose**: Extracts and interprets data from various formats
- **Key Components**:
  - HTML parsing
  - XML parsing
  - JSON parsing
  - `swf.py`: Flash file format parser
  - Other file format parsers

### `report/`
Generates vulnerability reports and handles CVSS scoring.

- **Purpose**: Creates detailed vulnerability reports for users
- **Key Components**:
  - `cvss.py`: CVSS scoring system for vulnerability severity
  - Report generation in various formats (HTML, JSON, etc.)
  - Vulnerability summarization
  - Statistics and metrics calculation

### `report_template/`
Contains templates for generating reports.

- **Purpose**: Defines the structure and appearance of vulnerability reports
- **Key Components**:
  - HTML templates
  - CSS styling
  - JavaScript for interactive reports
  - Template rendering engine

### `utils/`
Provides utility functions used across the application.

- **Purpose**: Offers common functionality needed by multiple components
- **Key Components**:
  - String manipulation
  - File handling
  - Logging utilities
  - Common operations and helpers

## Core Functionality

PentoraCore implements a comprehensive vulnerability scanning engine with these key capabilities:

1. **Web Crawling & Network Discovery**: Discovers pages and endpoints in web applications and network services
2. **Vulnerability Detection**: Tests for common security vulnerabilities across web and network targets
3. **Payload Generation**: Creates attack payloads for testing
4. **Result Analysis**: Analyzes responses to identify vulnerabilities
5. **Reporting**: Generates detailed vulnerability reports with remediation advice
6. **CVSS Scoring**: Assigns severity levels to discovered vulnerabilities

## Development

When extending PentoraCore, follow these guidelines:

1. Add new attack modules in the `attack/` directory
2. Define new vulnerability types in the `definitions/` directory
3. Update the CVSS scoring in `report/cvss.py` for new vulnerability types
4. Add any required data files to the `data/` directory
