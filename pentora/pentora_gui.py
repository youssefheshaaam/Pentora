#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Pentora - GUI-based vulnerability scanner
# Copyright (C) 2025 Pentora Team

import os
import sys
import json
import time
import logging
import datetime
import asyncio
import traceback
import subprocess
import webbrowser
import concurrent.futures
import io
import functools
import warnings
import re
import traceback # Added traceback import
from pathlib import Path
from urllib.parse import urlparse
from time import gmtime, strftime
from datetime import datetime, timedelta
from contextlib import redirect_stdout, redirect_stderr

# Suppress various warnings
warnings.filterwarnings("ignore", category=UserWarning, module="bs4")
warnings.filterwarnings("ignore", category=UserWarning, module="html.parser")
warnings.filterwarnings("ignore", category=DeprecationWarning, module="PyQt5")

# Import PyQt modules
try:
    from PyQt5.QtWidgets import (
        QApplication, QMainWindow, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QLineEdit, QPushButton, QTextEdit, QComboBox, QFileDialog,
        QProgressBar, QMessageBox, QRadioButton, QButtonGroup, QDialog,
        QListWidget, QListWidgetItem, QCheckBox, QScrollArea, QFrame, QSplitter,
        QTreeWidget, QTreeWidgetItem, QMenu, QAction, QGroupBox, QFormLayout, QGridLayout,
        QSpinBox, QDoubleSpinBox, QSlider, QToolBar, QStatusBar, QSizePolicy,
        QSplashScreen, QAbstractItemView, QToolTip, QStackedWidget, QPlainTextEdit
    )
    from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize, QTimer, QUrl, QObject, QEventLoop # Added QEventLoop
    from PyQt5.QtGui import (
        QIcon, QPixmap, QFont, QDesktopServices, QTextCursor, QPainter, 
        QLinearGradient, QBrush, QPen, QColor, QTextCharFormat
    )
    # Try importing QtWebEngineWidgets
    try:
        from PyQt5.QtWebEngineWidgets import QWebEngineView, QWebEnginePage
        HAS_WEBENGINE = True
    except ImportError:
        print("Warning: PyQtWebEngine not found. PDF report generation will be disabled.")
        HAS_WEBENGINE = False

except ImportError:
    print("Error: PyQt5 is required. Please install it using 'pip install PyQt5'")
    sys.exit(1)

# Add parent directory to path to import PentoraCore
parent_dir = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))
if os.path.exists(os.path.join(parent_dir, "PentoraCore")):
    sys.path.append(parent_dir)

# Import Pentora modules
from PentoraCore.controller.pentora import Pentora
from PentoraCore.language.language import _
from PentoraCore.language.vulnerability import CRITICAL_LEVEL, HIGH_LEVEL, MEDIUM_LEVEL, LOW_LEVEL, INFO_LEVEL
from PentoraCore.report.cvss import CVSSCalculator
from PentoraCore.report.reportgenerator import ReportGenerator
from PentoraCore.report import GENERATORS
from PentoraCore.attack.attack import all_modules, common_modules, presets
from PentoraCore import PENTORA_VERSION
from PentoraCore.net import Request
from PentoraCore.net.crawler import AsyncCrawler
from PentoraCore.main.log import logging as pentora_logging
from PentoraCore.net.scope import Scope

# Import Pentora network scanner
from pentora.network_scanner import NetworkScanner

# Dictionary of module descriptions
MODULE_DESCRIPTIONS = {
    "backup": "Searches for backup files and directories that may contain sensitive information such as source code, configuration files, or credentials",
    "brute_login_form": "Performs brute force attacks on login forms using common credentials to identify weak authentication mechanisms",
    "buster": "Discovers hidden files and directories on the web server using a comprehensive wordlist of common filenames and paths",
    "crlf": "Detects Carriage Return Line Feed (CRLF) injection vulnerabilities that can lead to HTTP response splitting, header injection, and XSS attacks",
    "csp": "Analyzes Content Security Policy headers for misconfigurations that could allow script injection or other client-side attacks",
    "csrf": "Checks for Cross-Site Request Forgery (CSRF) vulnerabilities where attackers can trick users into performing unwanted actions on authenticated websites",
    "exec": "Tests for command execution vulnerabilities that allow attackers to run arbitrary system commands on the server, potentially leading to complete system compromise",
    "file": "Detects file-related vulnerabilities including Path Traversal (directory traversal), Local File Inclusion (LFI), and Remote File Inclusion (RFI) that can expose sensitive files or execute malicious code",
    "http_headers": "Analyzes HTTP headers for security issues including information disclosure, missing security headers, and misconfiguration",
    "snmp_public": "Checks if SNMP (Simple Network Management Protocol) is accessible with the default 'public' community string, which can expose sensitive device and network information. This is a classic network-layer vulnerability.",
    "ldap": "Tests for LDAP injection vulnerabilities where user input is improperly sanitized before being used in LDAP queries",
    "methods": "Identifies supported HTTP methods and potential misconfigurations that could allow unauthorized operations like PUT or DELETE",
    "permanentxss": "Detects stored/permanent Cross-Site Scripting vulnerabilities where malicious scripts are saved on the server and executed when other users view the affected page",
    "redirect": "Identifies open redirect vulnerabilities where user-controlled input determines redirect destinations, potentially enabling phishing attacks",
    "shellshock": "Tests for Shellshock vulnerability (CVE-2014-6271) in Bash that allows attackers to execute arbitrary commands through HTTP requests",
    "sql": "Tests for SQL injection vulnerabilities where user input can manipulate database queries, potentially allowing data theft, modification, or deletion",
    "timesql": "Identifies time-based SQL injection vulnerabilities that can be exploited even when no error messages or direct output is visible",
    "upload": "Tests for insecure file upload vulnerabilities that could allow attackers to upload malicious files or bypass content restrictions",
    "xss": "Detects reflected Cross-Site Scripting vulnerabilities where malicious scripts are reflected off the web server in an immediate response",
    "xxe": "Tests for XML External Entity (XXE) injection vulnerabilities that can lead to server-side file disclosure, denial of service, or server-side request forgery"
}

class LogHandler:
    """Handle logs from Pentora and apply appropriate colors and emojis in the GUI"""
    
    def __init__(self, status_signal, vuln_signal, module_signal=None):
        self.status_signal = status_signal
        self.vuln_signal = vuln_signal
        self.module_signal = module_signal
        self.seen_messages = set()  # Track seen messages to prevent duplicates
        self.seen_report_messages = False  # Track report generation messages
        self.current_vulnerability = {}  # Track current vulnerability details
        self.current_module = "Initializing..."
    
    def write(self, message):
        # Skip empty messages
        if not message or not message.strip():
            return message
            
        # Convert message to string if it's not already
        message = str(message).strip()
        
        # Deduplicate messages - skip if we've seen this exact message recently
        message_hash = hash(message)
        if message_hash in self.seen_messages:
            return message
            
        # Add to seen messages (with a max size to prevent memory issues)
        self.seen_messages.add(message_hash)
        if len(self.seen_messages) > 1000:  # Limit the size of the set
            self.seen_messages.clear()
        
        # Format the message based on Pentora's log patterns
        format_info = {"text": message, "format": "normal"}
        is_vulnerability = False
        
  
        # HTTP/GET/POST requests with [+]
        if "[+]" in message and ("GET " in message or "POST " in message or "PUT " in message or "DELETE " in message):
            format_info["text"] = f"🌐 {message}"
            format_info["format"] = "request"  # Specific format for requests
            
        # Module working with [¨]
        elif "[¨]" in message:
            format_info["text"] = f"🔄 {message}"
            format_info["format"] = "module"  # Use module format for these messages
            
        # Launching module messages
        elif "Launching module" in message:
            format_info["text"] = f"🚀 {message}"
            format_info["format"] = "launching"  # Will be given a distinctive color
            
            # Extract module name and update current module
            module_match = re.search(r'Launching module (\w+)', message)
            if module_match:
                module_name = module_match.group(1)
                self.current_module = f"Running: {module_name}"
                # Emit signal if available
                if self.module_signal:
                    self.module_signal.emit(self.current_module)
            
        # Module activities with [*]
        elif "[*]" in message:
            format_info["text"] = f"ℹ️ {message}"
            format_info["format"] = "info"  # Purple in the GUI
            
        # Vulnerability detection - expanded to catch all vulnerability reporting patterns
        elif any(vuln_pattern in message.lower() for vuln_pattern in [
            "injection", "vulnerability", "in the parameter", 
            "found backup file", "found", "detected", "identified", "vulnerable",
            "appears vulnerable", "successfully", "seems vulnerable", "cross site scripting", 
            "sql injection", "xss", "csrf", "file inclusion", "command injection",
            "is not set", "has an invalid value", "missing", "misconfigured",
            "csp is not set", "csp attribute", "csp \""  
        ]) and not message.startswith("backup, brute_login_form"):  # Filter out module list
            # Extract vulnerability type and details
            vuln_type = "Vulnerability"
            vuln_url = ""
            vuln_param = ""
            
            # Determine vulnerability type - expanded to cover more vulnerability types
            # Match the exact message formats used by each vulnerability module
            
            # 1. XXE
            if re.search(r"XXE vulnerability in .+ via injection in the parameter", message, re.IGNORECASE):
                vuln_type = "XML External Entity (XXE)"
            
            # 2. SQL Injection
            elif re.search(r"SQL Injection in .+ via injection in the parameter", message, re.IGNORECASE):
                vuln_type = "SQL Injection"
                
            # 3. Blind SQL
            elif re.search(r"Blind SQL Injection in .+ via injection in the parameter", message, re.IGNORECASE):
                vuln_type = "Blind SQL Injection"
            
            # 4. Command Injection
            elif re.search(r"Command execution in .+ via injection in the parameter", message, re.IGNORECASE):
                vuln_type = "Command Injection"
                
            # 5. LDAP Injection
            elif re.search(r"LDAP Injection in .+ via injection in the parameter", message, re.IGNORECASE):
                vuln_type = "LDAP Injection"
                
            # 6. CRLF Injection
            elif re.search(r"CRLF Injection in .+ via injection in the parameter", message, re.IGNORECASE):
                vuln_type = "CRLF Injection"
                
            # 7-9. XSS vulnerabilities
            elif re.search(r"Stored Cross Site Scripting in .+ via injection in the parameter", message, re.IGNORECASE):
                vuln_type = "Stored Cross-Site Scripting (XSS)"
            elif re.search(r"Reflected Cross Site Scripting in .+ via injection in the parameter", message, re.IGNORECASE):
                vuln_type = "Reflected Cross-Site Scripting (XSS)"
            elif re.search(r"Cross Site Scripting in .+ via injection in the parameter", message, re.IGNORECASE):
                vuln_type = "Cross-Site Scripting (XSS)"
                
            # 10. Path Traversal
            elif re.search(r"Path Traversal in .+ via injection in the parameter", message, re.IGNORECASE):
                vuln_type = "Path Traversal"
                
            # 11. File Inclusion
            elif re.search(r"File Inclusion in .+ via injection in the parameter", message, re.IGNORECASE):
                vuln_type = "File Inclusion"
                
            # 12. CSRF 
            elif re.search(r"CSRF in .+ via", message, re.IGNORECASE):
                vuln_type = "Cross-Site Request Forgery (CSRF)"
                
            # 13. Open Redirect
            elif re.search(r"Open Redirect in .+ via injection in the parameter", message, re.IGNORECASE):
                vuln_type = "Open Redirect"
                
            # 14. Shellshock
            elif "URL seems vulnerable to Shellshock attack" in message:
                vuln_type = "Shellshock Vulnerability"
                
            # 15. Backup File
            elif "Found backup file" in message:
                vuln_type = "Backup File Disclosure"
                
            # 16. File Upload
            elif re.search(r"File Upload Vulnerability in .+ via", message, re.IGNORECASE):
                vuln_type = "File Upload Vulnerability"
                
            # 17. HTTP Methods
            elif re.search(r"Method .+ is enabled and may be used to", message, re.IGNORECASE):
                vuln_type = "HTTP Methods"
                
            # 18. Brute Login
            elif "Found valid credentials" in message:
                vuln_type = "Weak Credentials"
                
            # 19. HTTP Headers
            elif re.search(r"CSP .+ is .+ for", message, re.IGNORECASE):
                vuln_type = "Content Security Policy (CSP)"
            elif "X-Frame-Options is not set" in message:
                vuln_type = "Clickjacking Protection (X-Frame-Options)"
            elif "X-Content-Type-Options is not set" in message:
                vuln_type = "MIME Type Confusion (X-Content-Type-Options)"
            elif "Strict-Transport-Security is not set" in message:
                vuln_type = "HTTPS Security (Strict-Transport-Security)"
            elif "HttpOnly flag" in message:
                vuln_type = "HttpOnly Flag Cookie"
            elif "Secure flag" in message:
                vuln_type = "Secure Flag Cookie"
            
            # Extract URL if present
            url_match = re.search(r'https?://[^\s]+', message)
            if url_match:
                vuln_url = url_match.group(0)
            # For HTTP header vulnerabilities, try to extract the URL from the response object
            elif any(header in message.lower() for header in ["x-frame-options", "x-content-type-options", "strict-transport-security"]):
                # Try to find a URL in the message context
                context_url_match = re.search(r'checking .+ for ([^:]+)', message, re.IGNORECASE)
                if context_url_match:
                    vuln_url = context_url_match.group(1).strip()
                else:
                    # Default to the root URL if we can't extract it
                    vuln_url = "http://localhost:8000"
            
            # Extract parameter if present - improved regex to catch more parameter formats
            param_match = re.search(r'parameter\s+(\w+)|in the parameter\s+(\w+)|parameter[:\s]+(\w+)', message)
            if param_match:
                # Get the first non-None group from the regex match
                param_groups = [g for g in param_match.groups() if g is not None]
                if param_groups:
                    vuln_param = param_groups[0]
            
            # Store current vulnerability details
            self.current_vulnerability = {
                "type": vuln_type,
                "url": vuln_url,
                "param": vuln_param,
                "details": message
            }
            
            # Format vulnerability message for findings panel
            formatted_text = f"🔴 {vuln_type}\n"
            if vuln_url:
                formatted_text += f"URL: {vuln_url}\n"
            if vuln_param:
                formatted_text += f"Parameter: {vuln_param}\n"
            formatted_text += f"Details: {message}"
            
            format_info["text"] = formatted_text
            format_info["format"] = "vulnerability"  # Red in the GUI
            is_vulnerability = True
            
        # Evil request - associate with current vulnerability
        elif "Evil request:" in message:
            # Skip evil request messages entirely as requested by the user
            return message
            
        # Errors
        elif "Error" in message or "ERROR" in message:
            format_info["text"] = f"❌ {message}"
            format_info["format"] = "error"  # Orange in the GUI
            
        # Report generation
        elif "Generating report" in message:
            format_info["text"] = f"📊 {message}"
            format_info["format"] = "crawling"  # Green in the GUI
        elif "report has been generated" in message:
            # Skip if we've already seen a report generation message
            if self.seen_report_messages:
                return message
            self.seen_report_messages = True
            format_info["text"] = f"📊 {message}"
            format_info["format"] = "crawling"  # Green in the GUI
        
        # Skip the redundant "Open with browser" message
        if "Open " in message and ".html" in message and "with a browser" in message:
            return message
            
        # Send the message to the appropriate signal
        if is_vulnerability:
            self.vuln_signal.emit(str(format_info))
            
            # Also send a notification to the main log for context
            notification = {"text": f"🔴 Vulnerability detected! See details in Findings panel.", "format": "notification"}
            self.status_signal.emit(str(notification))
        else:
            self.status_signal.emit(str(format_info))
            
        return message
        
    def __call__(self, record):
        # This method makes LogHandler compatible with Loguru
        message = record["message"]
        self.write(message)
        return message

class OutputCapture(io.TextIOBase):
    """Capture output from stdout/stderr and redirect to the GUI"""
    
    def __init__(self, status_signal, vuln_signal, module_signal):
        super().__init__()
        self.status_signal = status_signal
        self.vuln_signal = vuln_signal
        self.module_signal = module_signal
        self.log_handler = LogHandler(status_signal, vuln_signal, module_signal)
        self.buffer = ""
    
    def write(self, text):
        if text:
            # Add to buffer
            self.buffer += text
            
            # Process complete lines
            if '\n' in self.buffer:
                lines = self.buffer.split('\n')
                # Keep the last part (incomplete line) in the buffer
                self.buffer = lines[-1]
                
                # Process all complete lines
                for line in lines[:-1]:
                    if line.strip():  # Skip empty lines
                        self.log_handler.write(line)
            
            # Also write to original stdout for debugging
            sys.__stdout__.write(text)
            
        return len(text) if text else 0
    
    def flush(self):
        # Process any remaining text in the buffer
        if self.buffer and self.buffer.strip():
            self.log_handler.write(self.buffer)
            self.buffer = ""
        sys.__stdout__.flush()

class StdoutRedirector(QObject):
    """Redirects stdout to the GUI"""
    
    def __init__(self, status_signal, vuln_signal, module_signal):
        super().__init__()
        self.status_signal = status_signal
        self.vuln_signal = vuln_signal
        self.module_signal = module_signal
        self.log_handler = LogHandler(status_signal, vuln_signal, module_signal)
        self.buffer = ""
    
    def write(self, text):
        if text:
            # Add to buffer
            self.buffer += text
            
            # Process complete lines
            if '\n' in self.buffer:
                lines = self.buffer.split('\n')
                # Keep the last part (incomplete line) in the buffer
                self.buffer = lines[-1]
                
                # Process all complete lines
                for line in lines[:-1]:
                    if line.strip():  # Skip empty lines
                        self.log_handler.write(line)
            
            # Also write to original stdout for debugging
            sys.__stdout__.write(text)
            
        return len(text) if text else 0
    
    def flush(self):
        # Process any remaining text in the buffer
        if self.buffer and self.buffer.strip():
            self.log_handler.write(self.buffer)
            self.buffer = ""
        sys.__stdout__.flush()

class ScannerThread(QThread):
    """Thread for running the scanner without blocking the GUI"""
    update_status = pyqtSignal(str)
    update_vuln = pyqtSignal(str)
    update_progress = pyqtSignal(int)
    update_module = pyqtSignal(str)  # New signal for module updates
    scan_complete = pyqtSignal(str)
    scan_error = pyqtSignal(str)
    # New signal for PDF conversion request
    html_ready_for_pdf = pyqtSignal(str, str)

    def __init__(self, url, options):
        super().__init__()
        self.url = url
        self.options = options
        self.report_file = None
        self.stop_requested = False
        self.stop_event = asyncio.Event()  # Single stop_event for all phases
        # Store the originally requested format
        self.requested_report_format = options.get('report_format', 'html')
        # Track progress more accurately
        self.total_modules = 0
        self.completed_modules = 0
        self.crawl_complete = False
        self.pentora = None  # Store reference to the Pentora controller

    async def run_scan(self):
        try:
            # Record start time for elapsed time calculation
            import time
            start_time = time.time()
            
            self.update_status.emit("Initializing scan...")
            self.update_progress.emit(5)
            
            # Reset the stop event at the beginning of the scan
            self.stop_event.clear()
            
            # Parse target URL
            self.target_url = self.url
            parsed_url = urlparse(self.target_url)
            
            # Add http:// if no scheme is provided
            if not parsed_url.scheme:
                self.url = 'http://' + self.url
            
            # Create a custom output capture system
            output_capture = OutputCapture(self.update_status, self.update_vuln, self.update_module)
            
            # Set up our log handler for Loguru
            log_handler = LogHandler(self.update_status, self.update_vuln, self.update_module)
            
            # Add our custom sink to Loguru
            log_id = pentora_logging.add(log_handler, format="{message}")
            
            # Directly replace sys.stdout and sys.stderr
            original_stdout = sys.stdout
            original_stderr = sys.stderr
            sys.stdout = output_capture
            sys.stderr = output_capture
            
            try:
                # Create base request
                self.update_status.emit("Creating base request...")
                base_request = Request(self.url)
                
                # Initialize Pentora with the required scope_request parameter
                self.update_status.emit("Initializing Pentora controller...")
                self.pentora = Pentora(scope_request=base_request, scope=self.options.get('scope', 'folder'))
                
                # Always flush the session to force a fresh scan
                self.update_status.emit("Flushing previous session...")
                await self.pentora.flush_session()
                
                # Set scan depth
                self.update_status.emit("Setting scan parameters...")
                self.pentora.set_max_depth(self.options.get('depth', 2))
                
                # Set timeout
                self.pentora.set_timeout(self.options.get('timeout', 10))
                
                # Set report format - ALWAYS tell PentoraCore to generate HTML if PDF is desired
                # PentoraCore itself only knows html/json.
                core_report_format = 'html' if self.requested_report_format == 'pdf' else self.requested_report_format
                self.update_status.emit(f"Setting core report format to {core_report_format}...")
                self.pentora.set_report_generator_type(core_report_format)
                
                # Set output directory
                output_dir = self.options.get('output_dir', os.path.join(os.getcwd(), 'pentora_reports'))
                os.makedirs(output_dir, exist_ok=True)
                
                # Generate report filename
                report_path = os.path.join(output_dir, f"pentora_report_{urlparse(self.url).netloc.replace(':', '_')}")
                self.update_status.emit(f"Setting output file to {report_path}.{core_report_format}...")
                self.pentora.set_output_file(report_path + "." + core_report_format)
                
                # Initialize the persister
                self.update_progress.emit(10)
                
                self.update_status.emit("Initializing persister...")
                await self.pentora.init_persister()
                
                # Set modules
                selected_modules = self.options.get('modules', 'common')
                self.update_status.emit(f"Setting modules to {selected_modules}...")
                
                # Pass the modules directly to set_modules
                # The Pentora controller expects a string or None, not a list
                self.pentora.set_modules(selected_modules)
                
                # Start the scan
                self.update_progress.emit(15)
                
                # Load existing scan state if available
                self.update_status.emit("Loading scan state...")
                await self.pentora.load_scan_state()
                
                if self.stop_requested:
                    self.update_status.emit("Scan stopped by user.")
                    return
                
                # Define callbacks for progress and status updates
                def progress_callback(percent):
                    self.update_progress.emit(int(percent))
                    
                def status_callback(message):
                    # Apply proper formatting for different message types
                    formatted_message = message
                    
                    # Apply specific formatting based on message content
                    if message.startswith("Running attack module:") or message.startswith("Launching module"):
                        # Extract the module name from the message
                        module_parts = message.split(":")
                        if len(module_parts) > 1:
                            module_name = module_parts[1].strip()
                            self.update_module.emit(module_name)
                            
                        # Format as a specially formatted dictionary
                        formatted_message = {
                            "text": f"🚀 {message}",
                            "format": "module"
                        }
                    elif "crawling" in message.lower() or "crawl" in message.lower():
                        formatted_message = {
                            "text": f"🔍 {message}",
                            "format": "crawling"
                        }
                    elif "vulnerability" in message.lower() or "discovered" in message.lower():
                        formatted_message = {
                            "text": f"🔴 {message}",
                            "format": "vulnerability"
                        }
                    elif "initializing" in message.lower() or "setting" in message.lower():
                        formatted_message = {
                            "text": f"⚙️ {message}",
                            "format": "info"
                        }
                    elif "loading" in message.lower() or "saving" in message.lower():
                        formatted_message = {
                            "text": f"💾 {message}",
                            "format": "info"
                        }
                    elif "stopping" in message.lower() or "stopped" in message.lower():
                        formatted_message = {
                            "text": f"⏹️ {message}",
                            "format": "notification"
                        }
                    elif "report" in message.lower() or "completed" in message.lower():
                        formatted_message = {
                            "text": f"✅ {message}", 
                            "format": "notification"
                        }
                        
                    # Send the formatted message to the GUI
                    self.update_status.emit(str(formatted_message))
                    
                # Crawl the website using callbacks for progress updates
                self.update_status.emit("Crawling website...")
                await self.pentora.browse(
                    self.stop_event, 
                    parallelism=4,
                    progress_callback=progress_callback,
                    status_callback=status_callback
                )
                
                if self.stop_event.is_set():
                    # Clean up and return immediately
                    output_capture.flush()  # Make sure to flush output buffers before exiting
                    return
                
                # Crawling is done, update progress
                self.crawl_complete = True
                self.update_status.emit("Crawl complete. Starting vulnerability scan...")
                self.update_progress.emit(30)
                
                # Run the attack with callbacks
                await self.pentora.attack(
                    self.stop_event,
                    progress_callback=progress_callback,
                    status_callback=status_callback
                )
                
                if self.stop_event.is_set():
                    # Clean up and return immediately without additional messages
                    output_capture.flush()  # Make sure to flush output buffers before exiting
                    return
                
                # Calculate elapsed time for the report
                end_time = time.time()
                elapsed_seconds = int(end_time - start_time)
                self.pentora.elapsed_time = elapsed_seconds
                self.update_status.emit(f"Scan completed in {elapsed_seconds} seconds")

                # Get the path to the report directory/base generated by PentoraCore
                generated_report_base_path = self.pentora.output_file # This might be a directory path

                if self.requested_report_format == 'pdf':
                    # Initialize the HTML path variable
                    actual_html_path = None
                    
                    # Use the generated report base path as our report directory
                    report_dir_path = generated_report_base_path
                    
                    # If it's a directory, find the HTML file inside
                    if os.path.isdir(report_dir_path):
                        try:
                            # Get all HTML files in the directory
                            html_files = [f for f in os.listdir(report_dir_path) if f.lower().endswith('.html')]
                            if html_files:
                                # Sort by modification time (newest first)
                                html_files.sort(key=lambda x: os.path.getmtime(os.path.join(report_dir_path, x)), reverse=True)
                                actual_html_path = os.path.join(report_dir_path, html_files[0])
                                self.update_status.emit(f"Found HTML report file for PDF conversion: {os.path.basename(actual_html_path)}")
                        except Exception as find_err:
                            self.update_status.emit(f"Error finding HTML file: {find_err}")
                            actual_html_path = None
                    else:
                        # If it's not a directory, use it directly as the HTML path
                        actual_html_path = report_dir_path

                    # Check if we found a valid HTML path
                    if actual_html_path and os.path.exists(actual_html_path):
                      if HAS_WEBENGINE:
                        # Add a small delay to allow file writing to complete
                        self.update_status.emit("Waiting briefly before PDF conversion...")
                        import time
                        time.sleep(0.5) # Wait half a second

                        # Re-check existence after delay
                        if not os.path.exists(actual_html_path):
                            self.update_status.emit(f"Error: HTML file disappeared after delay: {actual_html_path}")
                            self.scan_error.emit("Internal error: Report file disappeared.")
                            return # Exit if file vanished

                        # === DEBUGGING: Verify path and content before emitting ===
                        print(f"[DEBUG] ScannerThread: Emitting for PDF conversion:")
                        print(f"[DEBUG]   HTML Path: {actual_html_path}")
                        try:
                            with open(actual_html_path, 'r', encoding='utf-8', errors='ignore') as f_check:
                                first_lines = [next(f_check) for _ in range(5)]
                            print(f"[DEBUG]   HTML Content Start:\n{''.join(first_lines).strip()}")
                        except Exception as read_err:
                            print(f"[DEBUG]   Error reading HTML content start: {read_err}")
                        # === END DEBUGGING ===

                    # Check if we found a valid HTML path
                    if actual_html_path and os.path.exists(actual_html_path):
                        if HAS_WEBENGINE:
                            # Add a small delay to allow file writing to complete
                            self.update_status.emit("Waiting briefly before PDF conversion...")
                            import time
                            time.sleep(0.5) # Wait half a second

                            # Re-check existence after delay
                            if not os.path.exists(actual_html_path):
                                self.update_status.emit(f"Error: HTML file disappeared after delay: {actual_html_path}")
                                self.scan_error.emit("Internal error: Report file disappeared.")
                                return # Exit if file vanished

                            # === DEBUGGING: Verify path and content before emitting ===
                            print(f"[DEBUG] ScannerThread: Emitting for PDF conversion:")
                            print(f"[DEBUG]   HTML Path: {actual_html_path}")
                            try:
                                with open(actual_html_path, 'r', encoding='utf-8', errors='ignore') as f_check:
                                    first_lines = [next(f_check) for _ in range(5)]
                                print(f"[DEBUG]   HTML Content Start:\n{''.join(first_lines).strip()}")
                            except Exception as read_err:
                                print(f"[DEBUG]   Error reading HTML content start: {read_err}")
                            # === END DEBUGGING ===

                            # Generate the final PDF path (place it next to the HTML directory)
                            pdf_filename = os.path.splitext(os.path.basename(actual_html_path))[0] + ".pdf"
                            pdf_report_file = os.path.join(os.path.dirname(report_dir_path), pdf_filename)
                            print(f"[DEBUG]   PDF Path: {pdf_report_file}") # Debug PDF path too
                            os.makedirs(os.path.dirname(pdf_report_file), exist_ok=True)
                            self.update_status.emit(f"HTML report path identified: {actual_html_path}. Requesting PDF conversion to {pdf_report_file}...")
                            self.html_ready_for_pdf.emit(actual_html_path, pdf_report_file) # Emit with the specific HTML file path
                        else:
                            self.update_status.emit("Error: PyQtWebEngine required for PDF. Saving as HTML.")
                            self.scan_complete.emit(actual_html_path) # Fallback with found HTML path
                    else:
                        self.update_status.emit(f"Error: Could not find a valid HTML report file at base path: {generated_report_base_path}")
                        self.scan_error.emit("Internal error during PDF report preparation (HTML file not found).")

                else: # HTML or JSON requested
                    # For HTML, PentoraCore might return the directory path, which is fine for the completion message.
                    # For JSON, it should return the file path.
                    final_report_path = generated_report_base_path
                    self.report_file = final_report_path
                    output_capture.flush()
                    self.scan_complete.emit(self.report_file)

            except asyncio.CancelledError:
                # Catch cancellation here to prevent it from propagating further
                self.update_status.emit("Scan stopped successfully")
                raise  # Re-raise to ensure proper cleanup in the run method
            except Exception as e:
                error_msg = f"Error during scan: {str(e)}"
                pentora_logging.error(error_msg)
                self.scan_error.emit(error_msg)
                traceback.print_exc()
                raise  # Re-raise to ensure proper cleanup in the run method
            finally:
                # Restore original stdout and stderr
                sys.stdout = original_stdout
                sys.stderr = original_stderr
                
                # Remove our custom log handler
                pentora_logging.remove(log_id)  # Remove the custom sink
        except Exception as e:
            import traceback
            trace = traceback.format_exc()
            self.scan_error.emit(f"Error during scan: {str(e)}\n{trace}")
            self.update_progress.emit(0)

    def stop(self):
        """
        Request the scan to stop gracefully.
        
        This method uses a consolidated approach where the controller's stop_scan method 
        is the primary mechanism for stopping scans. The stop_event is used across both 
        the GUI and controller to ensure consistent behavior and prevent redundant
        stop handling.
        """
        self.stop_requested = True
        self.update_status.emit("Stopping scan... (this may take a few seconds)")
        
        # Use controller's stop_scan method exclusively
        if hasattr(self, 'pentora') and self.pentora is not None:
            self.pentora.stop_scan(self.stop_event)
        # Only set the event directly if controller isn't available for some reason
        elif hasattr(self, 'stop_event') and not self.stop_event.is_set():
            self.stop_event.set()
            
        # No need to aggressively cancel tasks - the controller handles graceful shutdown

    def run(self):
        """Run the scan in a separate thread"""
        loop = asyncio.new_event_loop()
        self._loop = loop  # Store reference to the loop
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self.run_scan())
        except asyncio.CancelledError:
            # This is expected when stopping a scan, handle it gracefully
            self.update_status.emit("Scan stopped successfully")
        except Exception as e:
            # Handle other exceptions
            self.update_status.emit(f"Error during scan: {str(e)}")
            traceback.print_exc()
        finally:
            loop.close()


class ModuleSelectionDialog(QDialog):  # Changed from QWidget to QDialog
    """Dialog for selecting attack modules"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Select Attack Modules")
        self.setMinimumSize(800, 600)  # Increased size
        
        # Apply dark theme styling
        self.setStyleSheet("""
            QWidget {
                background-color: #1E1E1E;
                color: #CCCCCC;
            }
            QLabel {
                color: #CCCCCC;
            }
            QListWidget {
                background-color: #252525;
                color: #CCCCCC;
                border: 1px solid #3E3E3E;
                border-radius: 4px;
                padding: 5px;
            }
            QListWidget::item {
                padding: 5px;
                border-bottom: 1px solid #3E3E3E;
            }
            QListWidget::item:selected {
                background-color: #B388FF;
                color: #1E1E1E;
            }
            QCheckBox {
                color: #CCCCCC;
            }
            QCheckBox::indicator {
                width: 16px;
                height: 16px;
            }
            QCheckBox::indicator:checked {
                background-color: #C6FF00;
                border: 1px solid #3E3E3E;
                border-radius: 2px;
            }
            QCheckBox::indicator:unchecked {
                background-color: #252525;
                border: 1px solid #3E3E3E;
                border-radius: 2px;
            }
            QPushButton {
                background-color: #424242;
                color: #CCCCCC;
                border: none;
                border-radius: 4px;
                padding: 6px 12px;
            }
            QPushButton:hover {
                background-color: #616161;
            }
            QPushButton:pressed {
                background-color: #757575;
            }
        """)
        
        self.init_ui()
        
    def init_ui(self):
        """Initialize the user interface"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)  # Add margins for better spacing
        layout.setAlignment(Qt.AlignCenter)  # Center the layout
        
        # Create module list
        self.module_list = QListWidget()
        self.module_list.setMinimumHeight(300)  # Make the list taller
        
        # Add modules to the list with descriptions
        for module_name in sorted(all_modules):
            # Get the description from our dictionary, or use a default if not found
            description = MODULE_DESCRIPTIONS.get(module_name, "No description available")
            item = QListWidgetItem(f"{module_name} - {description}")
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Unchecked)
            # Store the module name as user data for later retrieval
            item.setData(Qt.UserRole, module_name)
            # Set text color explicitly to ensure visibility
            item.setForeground(QBrush(QColor("#CCCCCC")))
            self.module_list.addItem(item)
            
        # Create and style the selection label
        module_label = QLabel("Select attack modules to use:")
        module_label.setStyleSheet("color: #C6FF00; font-weight: bold; font-size: 14px; margin-bottom: 5px;")
        layout.addWidget(module_label)
        layout.addWidget(self.module_list)
        
        # Add buttons
        buttons_layout = QHBoxLayout()
        select_all_button = QPushButton("Select All")
        select_all_button.clicked.connect(self.select_all)
        select_all_button.setStyleSheet("""
            background-color: #424242;
            color: #C6FF00;
            border: 1px solid #B388FF;
            border-radius: 4px;
            padding: 6px 12px;
        """)
        
        select_common_button = QPushButton("Select Common")
        select_common_button.clicked.connect(self.select_common)
        select_common_button.setStyleSheet("""
            background-color: #424242;
            color: #C6FF00;
            border: 1px solid #B388FF;
            border-radius: 4px;
            padding: 6px 12px;
        """)
        
        clear_button = QPushButton("Clear All")
        clear_button.clicked.connect(self.clear_all)
        clear_button.setStyleSheet("""
            background-color: #424242;
            color: #C6FF00;
            border: 1px solid #B388FF;
            border-radius: 4px;
            padding: 6px 12px;
        """)
        
        buttons_layout.addWidget(select_all_button)
        buttons_layout.addWidget(select_common_button)
        buttons_layout.addWidget(clear_button)
        layout.addLayout(buttons_layout)
        
        # Add OK and Cancel buttons
        ok_cancel_layout = QHBoxLayout()
        
        ok_button = QPushButton("OK")
        ok_button.clicked.connect(self.accept)
        ok_cancel_layout.addWidget(ok_button)
        
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        ok_cancel_layout.addWidget(cancel_button)
        
        layout.addLayout(ok_cancel_layout)
        
    def select_all(self):
        """Select all modules"""
        for i in range(self.module_list.count()):
            self.module_list.item(i).setCheckState(Qt.CheckState.Checked)
            
    def select_common(self):
        """Select only common modules"""
        for i in range(self.module_list.count()):
            item = self.module_list.item(i)
            if item.text().split(' - ')[0] in common_modules:
                item.setCheckState(Qt.CheckState.Checked)
            else:
                item.setCheckState(Qt.CheckState.Unchecked)
                
    def clear_all(self):
        """Clear all module selections"""
        for i in range(self.module_list.count()):
            self.module_list.item(i).setCheckState(Qt.CheckState.Unchecked)
            
    def get_selected_modules(self):
        """Get the list of selected modules"""
        selected = []
        for i in range(self.module_list.count()):
            item = self.module_list.item(i)
            if item.checkState() == Qt.CheckState.Checked:
                selected.append(item.text().split(' - ')[0])
        return ",".join(selected) if selected else "common"


class NetworkModuleSelectionDialog(QDialog):
    """Dialog for selecting network scan modules"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Select Network Scan Modules")
        self.setMinimumSize(800, 600)  # Increased size
        
        # Apply dark theme styling
        self.setStyleSheet("""
            QWidget {
                background-color: #1E1E1E;
                color: #CCCCCC;
            }
            QLabel {
                color: #CCCCCC;
            }
            QListWidget {
                background-color: #252525;
                color: #CCCCCC;
                border: 1px solid #3E3E3E;
                border-radius: 4px;
                padding: 5px;
            }
            QListWidget::item {
                padding: 5px;
                border-bottom: 1px solid #3E3E3E;
            }
            QListWidget::item:selected {
                background-color: #B388FF;
                color: #1E1E1E;
            }
            QCheckBox {
                color: #CCCCCC;
            }
            QCheckBox::indicator {
                width: 16px;
                height: 16px;
            }
            QCheckBox::indicator:checked {
                background-color: #C6FF00;
                border: 1px solid #3E3E3E;
                border-radius: 2px;
            }
            QCheckBox::indicator:unchecked {
                background-color: #252525;
                border: 1px solid #3E3E3E;
                border-radius: 2px;
            }
            QPushButton {
                background-color: #424242;
                color: #CCCCCC;
                border: none;
                border-radius: 4px;
                padding: 6px 12px;
            }
            QPushButton:hover {
                background-color: #616161;
            }
            QPushButton:pressed {
                background-color: #757575;
            }
        """)
        
        self.init_ui()
        
    def init_ui(self):
        """Initialize the user interface"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)  # Add margins for better spacing
        layout.setAlignment(Qt.AlignCenter)  # Center the layout
        
        # Get available modules from NetworkScanner
        scanner = NetworkScanner()
        self.available_modules = scanner.get_available_modules()
        
        # Create a list widget for modules
        self.module_list = QListWidget()
        self.module_list.setMinimumHeight(300)  # Make the list taller
        
        # Add modules to the list
        for module in self.available_modules:
            item = QListWidgetItem(f"{module['name']} - {module['description']}")
            item.setData(Qt.UserRole, module['name'])
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Checked)  # Default to checked
            self.module_list.addItem(item)
            
        layout.addWidget(QLabel("Select modules to enable:"))
        layout.addWidget(self.module_list)
        
        # Add buttons for selecting all, common, or none
        buttons_layout = QHBoxLayout()
        
        select_all_button = QPushButton("Select All")
        select_all_button.clicked.connect(self.select_all)
        buttons_layout.addWidget(select_all_button)
        
        select_common_button = QPushButton("Select Common")
        select_common_button.clicked.connect(self.select_common)
        buttons_layout.addWidget(select_common_button)
        
        clear_all_button = QPushButton("Clear All")
        clear_all_button.clicked.connect(self.clear_all)
        buttons_layout.addWidget(clear_all_button)
        
        layout.addLayout(buttons_layout)
        
        # Add OK and Cancel buttons
        ok_cancel_layout = QHBoxLayout()
        
        ok_button = QPushButton("OK")
        ok_button.clicked.connect(self.accept)
        ok_cancel_layout.addWidget(ok_button)
        
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        ok_cancel_layout.addWidget(cancel_button)
        
        layout.addLayout(ok_cancel_layout)
        
    def select_all(self):
        """Select all modules"""
        for i in range(self.module_list.count()):
            item = self.module_list.item(i)
            item.setCheckState(Qt.Checked)
            
    def select_common(self):
        """Select only common modules"""
        common_modules = ["port_scan", "service_detection", "vuln_scan"]
        for i in range(self.module_list.count()):
            item = self.module_list.item(i)
            module_name = item.data(Qt.UserRole)
            if module_name in common_modules:
                item.setCheckState(Qt.Checked)
            else:
                item.setCheckState(Qt.Unchecked)
                
    def clear_all(self):
        """Clear all module selections"""
        for i in range(self.module_list.count()):
            item = self.module_list.item(i)
            item.setCheckState(Qt.Unchecked)
            
    def get_selected_modules(self):
        """Get the list of selected modules"""
        selected_modules = []
        for i in range(self.module_list.count()):
            item = self.module_list.item(i)
            if item.checkState() == Qt.Checked:
                selected_modules.append(item.data(Qt.UserRole))
        return selected_modules


class PentoraMainWindow(QMainWindow):
    """Main window for the Pentora application"""
    
    def __init__(self):
        super().__init__()
        self.scanner_thread = None
        self.init_ui()
        
        # We don't need to set the icon here anymore as it's now set application-wide in main()
        
    def init_ui(self):
        """Initialize the user interface"""
        # Set window properties
        self.setWindowTitle("Pentora - Vulnerability Scanner")
        self.resize(1200, 800)
        
        # Set application style
        self.setStyleSheet("""
            QMainWindow, QDialog {
                background-color: #1E1E1E;
                color: #CCCCCC;
            }
            QLabel {
                color: #CCCCCC;
            }
            QLineEdit, QComboBox, QSpinBox {
                background-color: #303030;
                color: #E0E0E0;
                border: 1px solid #424242;
                border-radius: 4px;
                padding: 5px;
            }
            QLineEdit:focus, QComboBox:focus, QSpinBox:focus {
                border: 1px solid #6C63FF;
            }
            QLineEdit:hover:!focus, QComboBox:hover:!focus, QSpinBox:hover:!focus {
                border: 1px solid #555555;
            }
            QComboBox::drop-down {
                border: 0px;
            }
            QComboBox::down-arrow {
                width: 12px;
                height: 12px;
            }
            QComboBox QAbstractItemView {
                background-color: #333333;
                color: #CCCCCC;
                selection-background-color: #B388FF;
                selection-color: #1E1E1E;
            }
            QTextEdit {
                background-color: #252525;
                color: #CCCCCC;
                border: 1px solid #3E3E3E;
                border-radius: 4px;
                padding: 5px;
                font-family: Menlo, Monaco, monospace;
                font-size: 10pt;
            }
            QPushButton {
                background-color: #424242;
                color: #CCCCCC;
                border: none;
                border-radius: 4px;
                padding: 6px 12px;
            }
            QPushButton:hover {
                background-color: #616161;
            }
            QPushButton:pressed {
                background-color: #757575;
            }
            QPushButton#primary {
                background-color: #C6FF00;
                color: #1E1E1E;
                font-weight: bold;
            }
            QPushButton#primary:hover {
                background-color: #AEEA00;
            }
            QPushButton#primary:pressed {
                background-color: #9CCC65;
            }
            QPushButton#danger {
                background-color: #B388FF;
                color: #1E1E1E;
                font-weight: bold;
            }
            QPushButton#danger:hover {
                background-color: #9575CD;
            }
            QPushButton#danger:pressed {
                background-color: #7E57C2;
            }
            QGroupBox {
                background-color: #252525;
                border: 1px solid #3E3E3E;
                border-radius: 4px;
                margin-top: 1em;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                color: #B388FF;
                font-weight: bold;
            }
            QTabWidget::pane {
                background-color: #252525;
                border: none;
                margin: 0px;
                padding: 0px;
            }
            QTabBar::tab {
                background-color: #252525;
                color: #CCCCCC;
                padding: 8px 12px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background-color: #424242;
                border-bottom: 2px solid #C6FF00;
            }
            QTabBar::tab:hover:!selected {
                background-color: #333333;
            }
            QScrollBar:vertical {
                border: none;
                background: #252525;
                width: 10px;
                margin: 0px;
            }
            QScrollBar::handle:vertical {
                background: #3E3E3E;
                min-height: 20px;
                border-radius: 5px;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                border: none;
                background: none;
                height: 0px;
            }
            QScrollBar:horizontal {
                border: none;
                background: #252525;
                height: 10px;
                margin: 0px;
            }
            QScrollBar::handle:horizontal {
                background: #3E3E3E;
                min-width: 20px;
                border-radius: 5px;
            }
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
                border: none;
                background: none;
                width: 0px;
            }
            QCheckBox {
                color: #CCCCCC;
            }
            QCheckBox::indicator {
                width: 16px;
                height: 16px;
            }
            QCheckBox::indicator:checked {
                background-color: #C6FF00;
                border: 1px solid #3E3E3E;
                border-radius: 2px;
            }
            QCheckBox::indicator:unchecked {
                background-color: #252525;
                border: 1px solid #3E3E3E;
                border-radius: 2px;
            }
            QFrame {
                background-color: #252525;
                border-radius: 4px;
                border: 1px solid #3E3E3E;
            }
        """)
        
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(10)
        
        # Create a simple, elegant header
        header_widget = QWidget()
        header_widget.setStyleSheet("background-color: #252525; border-radius: 6px; padding: 15px;")
        header_layout = QHBoxLayout(header_widget)
        header_layout.setContentsMargins(20, 10, 20, 10)
        header_layout.setSpacing(15)  # Add more space between logo and title
        
        # Logo on the left
        logo_label = QLabel()
        logo_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "resources", "images", "Pentora_logo.png")
        
        if os.path.exists(logo_path):
            logo_pixmap = QPixmap(logo_path)
            if not logo_pixmap.isNull():
                # Much larger size for the logo
                logo_pixmap = logo_pixmap.scaled(180, 70, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                logo_label.setPixmap(logo_pixmap)
                logo_label.setAlignment(Qt.AlignCenter)  # Center the logo in the label
            else:
                logo_label.setText("🛡️")
                logo_label.setStyleSheet("font-size: 36px; color: #4FC3F7;")
        else:
            logo_label.setText("🛡️")
            logo_label.setStyleSheet("font-size: 36px; color: #4FC3F7;")
            
        logo_label.setStyleSheet("background: transparent;")
        header_layout.addWidget(logo_label)
        
        # Title and subtitle in the center
        title_container = QWidget()
        title_layout = QVBoxLayout(title_container)
        title_layout.setContentsMargins(0, 0, 0, 0)
        title_layout.setSpacing(2)
        
        title_label = QLabel("Pentora")
        title_label.setStyleSheet("color: #B388FF; font-size: 28px; font-weight: bold;")
        title_label.setAlignment(Qt.AlignCenter)
        
        subtitle_label = QLabel("Vulnerability Scanner")
        subtitle_label.setStyleSheet("color: #CCCCCC; font-size: 14px;")
        subtitle_label.setAlignment(Qt.AlignCenter)
        
        title_layout.addWidget(title_label)
        title_layout.addWidget(subtitle_label)
        
        # Add widgets to header layout
        header_layout.addWidget(title_container, 1)  # Give the title container stretch
        
        # Add header to main layout
        main_layout.addWidget(header_widget)
        
        # Create tab widget for different sections
        tab_widget = QTabWidget()
        tab_widget.setDocumentMode(True)  # More modern look
        tab_widget.setStyleSheet("""
            QTabWidget::pane {
                background-color: #1E1E1E;
                border: none;
                margin: 0px;
                padding: 0px;
            }
            QTabBar::tab {
                background-color: #252525;
                color: #CCCCCC;
                padding: 8px 12px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background-color: #424242;
                border-bottom: 2px solid #C6FF00;
            }
            QTabBar::tab:hover:!selected {
                background-color: #333333;
            }
        """)
        
        # Create scan tab
        scan_tab = QWidget()
        self.setup_scan_tab(scan_tab)
        tab_widget.addTab(scan_tab, "Web Scan")
        
        # Create network scan tab
        network_scan_tab = QWidget()
        self.setup_network_scan_tab(network_scan_tab)
        tab_widget.addTab(network_scan_tab, "Network Scan")
        
        # Create about tab
        about_tab = QWidget()
        self.setup_about_tab(about_tab)
        tab_widget.addTab(about_tab, "About")
        
        main_layout.addWidget(tab_widget)
        
    def setup_scan_tab(self, tab):
        """Setup the scan tab"""
        scan_layout = QVBoxLayout(tab)
        scan_layout.setContentsMargins(10, 10, 10, 10)
        scan_layout.setSpacing(10)
        
        # URL input section
        url_section = QFrame()
        url_section.setStyleSheet("""
            QFrame {
                background-color: #252525;
                border-radius: 4px;
                border: 1px solid #3E3E3E;
            }
        """)
        url_layout = QHBoxLayout(url_section)
        url_layout.setContentsMargins(10, 10, 10, 10)
        
        url_label = QLabel("Target URL:")
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com")
        
        url_layout.addWidget(url_label)
        url_layout.addWidget(self.url_input)
        
        scan_layout.addWidget(url_section)
        
        # Options section
        options_section = QFrame()
        options_section.setStyleSheet("""
            QFrame {
                background-color: #252525;
                border-radius: 4px;
                border: 1px solid #3E3E3E;
            }
        """)
        options_layout = QGridLayout(options_section)
        options_layout.setContentsMargins(10, 10, 10, 10)
        
        # Scope
        scope_label = QLabel("Scope:")
        options_layout.addWidget(scope_label, 0, 0)
        
        self.scope_combo = QComboBox()
        self.scope_combo.addItem("folder")
        self.scope_combo.addItem("page")
        self.scope_combo.addItem("url")
        self.scope_combo.addItem("domain")
        options_layout.addWidget(self.scope_combo, 0, 1)
        
        # Depth
        depth_label = QLabel("Depth:")
        options_layout.addWidget(depth_label, 0, 2)
        
        self.depth_spin = QSpinBox()
        self.depth_spin.setMinimum(1)
        self.depth_spin.setMaximum(40)  # Increased max depth to match Pentora default
        self.depth_spin.setValue(2)
        options_layout.addWidget(self.depth_spin, 0, 3)
        
        # Timeout
        timeout_label = QLabel("Timeout (sec):")
        options_layout.addWidget(timeout_label, 1, 0)
        
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setMinimum(1)
        self.timeout_spin.setMaximum(300)
        self.timeout_spin.setValue(10)
        options_layout.addWidget(self.timeout_spin, 1, 1)
        
        # Modules
        modules_label = QLabel("Modules:")
        options_layout.addWidget(modules_label, 1, 2)
        
        modules_widget = QWidget()
        modules_layout = QHBoxLayout(modules_widget)
        modules_layout.setContentsMargins(0, 0, 0, 0)
        
        self.modules_combo = QComboBox()
        self.modules_combo.addItem("Common", "common")
        self.modules_combo.addItem("All", "all")
        self.modules_combo.addItem("Custom", "custom")
        self.modules_combo.currentTextChanged.connect(self.on_modules_changed)
        modules_layout.addWidget(self.modules_combo)
        
        self.modules_button = QPushButton("Select...")
        self.modules_button.clicked.connect(self.select_modules)
        modules_layout.addWidget(self.modules_button)
        
        options_layout.addWidget(modules_widget, 1, 3)
        
        # Output directory
        output_dir_label = QLabel("Output Directory:")
        options_layout.addWidget(output_dir_label, 2, 0)
        
        output_dir_widget = QWidget()
        output_dir_layout = QHBoxLayout(output_dir_widget)
        output_dir_layout.setContentsMargins(0, 0, 0, 0)
        
        self.output_dir_input = QLineEdit()
        self.output_dir_input.setText(os.path.join(os.getcwd(), "pentora_reports"))
        output_dir_layout.addWidget(self.output_dir_input)
        
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_output_dir)
        output_dir_layout.addWidget(browse_button)
        
        options_layout.addWidget(output_dir_widget, 2, 1, 1, 3)
        
        # Report format
        report_format_label = QLabel("Report Format:")
        options_layout.addWidget(report_format_label, 3, 0)
        
        self.report_format_combo = QComboBox()
        self.report_format_combo.addItem("html")
        self.report_format_combo.addItem("json")
        self.report_format_combo.addItem("pdf") # Added PDF option
        options_layout.addWidget(self.report_format_combo, 3, 1)
        
        scan_layout.addWidget(options_section)
        
        # Log and findings section - side by side
        log_findings_section = QFrame()
        log_findings_section.setStyleSheet("""
            QFrame {
                background-color: #252525;
                border-radius: 4px;
                border: 1px solid #3E3E3E;
                padding-top: 5px;
            }
        """)
        log_findings_layout = QHBoxLayout(log_findings_section)
        log_findings_layout.setContentsMargins(10, 15, 10, 10)
        log_findings_layout.setSpacing(15)
        
        # Log panel (left side)
        log_panel = QGroupBox()
        log_panel.setStyleSheet("""
            QGroupBox {
                background-color: #252525;
                border: 1px solid #3E3E3E;
                border-radius: 4px;
                margin-top: 30px;
                padding-top: 30px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top center;
                padding: 0 15px;
                color: #B388FF;
                font-weight: bold;
                background-color: #252525;
                font-size: 14px;
                top: 10px;
            }
        """)
        log_panel.setTitle("Scan Log")
        
        log_panel_layout = QVBoxLayout(log_panel)
        log_panel_layout.setContentsMargins(5, 10, 5, 5)
        log_panel_layout.setSpacing(5)
        
        self.status_display = QTextEdit()
        self.status_display.setReadOnly(True)
        self.status_display.setStyleSheet("""
            QTextEdit {
                background-color: #252525;
                color: #CCCCCC;
                border: 1px solid #3E3E3E;
                border-radius: 4px;
                padding: 5px;
                font-family: Menlo, Monaco, monospace;
                font-size: 10pt;
            }
        """)
        self.status_display.setMinimumHeight(300)
        log_panel_layout.addWidget(self.status_display)
        
        # Add clear log button
        clear_log_button = QPushButton("Clear Log")
        clear_log_button.clicked.connect(self.clear_log)
        clear_log_button.setStyleSheet("""
            QPushButton {
                background-color: #424242;
                color: #CCCCCC;
                border: none;
                border-radius: 4px;
                padding: 6px 12px;
            }
            QPushButton:hover {
                background-color: #616161;
            }
            QPushButton:pressed {
                background-color: #757575;
            }
        """)
        clear_log_button.setMaximumWidth(120)
        
        # Add hide logs button
        hide_logs_button = QPushButton("Hide Logs")
        hide_logs_button.clicked.connect(self.toggle_log_visibility)
        hide_logs_button.setStyleSheet("""
            QPushButton {
                background-color: #424242;
                color: #CCCCCC;
                border: none;
                border-radius: 4px;
                padding: 6px 12px;
            }
            QPushButton:hover {
                background-color: #616161;
            }
            QPushButton:pressed {
                background-color: #757575;
            }
        """)
        hide_logs_button.setMaximumWidth(120)
        
        # Create a horizontal layout for the buttons
        log_buttons_layout = QHBoxLayout()
        log_buttons_layout.addWidget(clear_log_button)
        log_buttons_layout.addWidget(hide_logs_button)
        log_buttons_layout.addStretch()
        log_panel_layout.addLayout(log_buttons_layout)
        
        # Findings panel (right side)
        findings_panel = QGroupBox()
        findings_panel.setStyleSheet("""
            QGroupBox {
                background-color: #252525;
                border: 1px solid #3E3E3E;
                border-radius: 4px;
                margin-top: 30px;
                padding-top: 30px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top center;
                padding: 0 15px;
                color: #C6FF00;
                font-weight: bold;
                background-color: #252525;
                font-size: 14px;
                top: 10px;
            }
        """)
        findings_panel.setTitle("Vulnerability Findings")
        
        findings_panel_layout = QVBoxLayout(findings_panel)
        findings_panel_layout.setContentsMargins(5, 10, 5, 5)
        findings_panel_layout.setSpacing(5)
        
        self.findings_display = QTextEdit()
        self.findings_display.setReadOnly(True)
        self.findings_display.setStyleSheet("""
            QTextEdit {
                background-color: #252525;
                color: #CCCCCC;
                border: 1px solid #3E3E3E;
                border-radius: 4px;
                padding: 5px;
                font-family: Menlo, Monaco, monospace;
                font-size: 10pt;
            }
        """)
        self.findings_display.setMinimumHeight(300)
        findings_panel_layout.addWidget(self.findings_display)
        
        # Add clear findings button
        clear_findings_button = QPushButton("Clear Findings")
        clear_findings_button.clicked.connect(self.clear_findings)
        clear_findings_button.setStyleSheet("""
            QPushButton {
                background-color: #424242;
                color: #CCCCCC;
                border: none;
                border-radius: 4px;
                padding: 6px 12px;
            }
            QPushButton:hover {
                background-color: #616161;
            }
            QPushButton:pressed {
                background-color: #757575;
            }
        """)
        clear_findings_button.setMaximumWidth(120)
        findings_panel_layout.addWidget(clear_findings_button, alignment=Qt.AlignmentFlag.AlignRight)
        
        # Add panels to the log_findings_layout with equal width
        log_findings_layout.addWidget(log_panel, 1)
        log_findings_layout.addWidget(findings_panel, 1)
        
        scan_layout.addWidget(log_findings_section)
        
        # Control buttons
        control_section = QWidget()
        control_layout = QHBoxLayout(control_section)
        control_layout.setContentsMargins(0, 0, 0, 0)
        
        self.start_button = QPushButton("Start Scan")
        self.start_button.setObjectName("primary")
        self.start_button.clicked.connect(self.start_scan)
        
        self.stop_button = QPushButton("Stop Scan")
        self.stop_button.setObjectName("danger")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        
        control_layout.addWidget(self.start_button)
        control_layout.addWidget(self.stop_button)
        
        scan_layout.addWidget(control_section)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #3E3E3E;
                border-radius: 4px;
                text-align: center;
                background-color: #252525;
            }
            QProgressBar::chunk {
                background-color: #C6FF00;
            }
        """)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        scan_layout.addWidget(self.progress_bar)
        
        # Current module label
        self.current_module_label = QLabel("Current Module: Initializing...")
        self.current_module_label.setStyleSheet("color: #B388FF; font-weight: bold;")
        scan_layout.addWidget(self.current_module_label)
        
    def setup_network_scan_tab(self, tab):
        """Setup the network scan tab"""
        network_scan_layout = QVBoxLayout(tab)
        network_scan_layout.setContentsMargins(10, 10, 10, 10)
        network_scan_layout.setSpacing(10)
        
        # Network target input section
        network_target_section = QFrame()
        network_target_section.setStyleSheet("""
            QFrame {
                background-color: #252525;
                border-radius: 4px;
                border: 1px solid #3E3E3E;
            }
        """)
        network_target_layout = QHBoxLayout(network_target_section)
        network_target_layout.setContentsMargins(10, 10, 10, 10)
        
        network_target_label = QLabel("Network Target:")
        self.network_target_input = QLineEdit()
        self.network_target_input.setPlaceholderText("192.168.1.1/24")
        
        network_target_layout.addWidget(network_target_label)
        network_target_layout.addWidget(self.network_target_input)
        
        network_scan_layout.addWidget(network_target_section)
        
        # Network options section
        network_options_section = QFrame()
        network_options_section.setStyleSheet("""
            QFrame {
                background-color: #252525;
                border-radius: 4px;
                border: 1px solid #3E3E3E;
            }
        """)
        network_options_layout = QGridLayout(network_options_section)
        network_options_layout.setContentsMargins(10, 10, 10, 10)
        
        # Network port range
        network_port_label = QLabel("Port Range:")
        network_options_layout.addWidget(network_port_label, 0, 0)
        
        self.network_port_input = QLineEdit()
        self.network_port_input.setPlaceholderText("1-1000")
        self.network_port_input.setText("1-1000")
        network_options_layout.addWidget(self.network_port_input, 0, 1)
        
        # Network modules
        network_modules_label = QLabel("Scan Modules:")
        network_options_layout.addWidget(network_modules_label, 1, 0)
        
        network_modules_widget = QWidget()
        network_modules_layout = QHBoxLayout(network_modules_widget)
        network_modules_layout.setContentsMargins(0, 0, 0, 0)
        
        self.network_modules_combo = QComboBox()
        self.network_modules_combo.addItem("All Modules")
        self.network_modules_combo.addItem("Custom Selection")
        network_modules_layout.addWidget(self.network_modules_combo)
        
        self.network_modules_button = QPushButton("Select Modules")
        self.network_modules_button.clicked.connect(self.select_network_modules)
        network_modules_layout.addWidget(self.network_modules_button)
        
        network_options_layout.addWidget(network_modules_widget, 1, 1)
        
        # Network timeout
        network_timeout_label = QLabel("Timeout (sec):")
        network_options_layout.addWidget(network_timeout_label, 2, 0)
        
        self.network_timeout_spin = QSpinBox()
        self.network_timeout_spin.setMinimum(1)
        self.network_timeout_spin.setMaximum(300)
        self.network_timeout_spin.setValue(10)
        network_options_layout.addWidget(self.network_timeout_spin, 2, 1)
        
        # Network report format
        network_report_format_label = QLabel("Report Format:")
        network_options_layout.addWidget(network_report_format_label, 3, 0)
        
        self.network_report_format_combo = QComboBox()
        self.network_report_format_combo.addItem("html")
        self.network_report_format_combo.addItem("json")
        self.network_report_format_combo.addItem("pdf") # Added PDF option
        network_options_layout.addWidget(self.network_report_format_combo, 3, 1)
        
        # Network output directory
        network_output_dir_label = QLabel("Output Directory:")
        network_options_layout.addWidget(network_output_dir_label, 4, 0)
        
        network_output_dir_widget = QWidget()
        network_output_dir_layout = QHBoxLayout(network_output_dir_widget)
        network_output_dir_layout.setContentsMargins(0, 0, 0, 0)
        
        self.network_output_dir_input = QLineEdit()
        self.network_output_dir_input.setText(os.path.join(os.getcwd(), "pentora_reports"))
        network_output_dir_layout.addWidget(self.network_output_dir_input)
        
        network_browse_button = QPushButton("Browse")
        network_browse_button.clicked.connect(self.browse_network_output_dir)
        network_output_dir_layout.addWidget(network_browse_button)
        
        network_options_layout.addWidget(network_output_dir_widget, 4, 1)
        
        network_scan_layout.addWidget(network_options_section)
        
        # Network log and findings section - side by side
        network_log_findings_section = QFrame()
        network_log_findings_section.setStyleSheet("""
            QFrame {
                background-color: #252525;
                border-radius: 4px;
                border: 1px solid #3E3E3E;
                padding-top: 5px;
            }
        """)
        network_log_findings_layout = QHBoxLayout(network_log_findings_section)
        network_log_findings_layout.setContentsMargins(10, 15, 10, 10)
        network_log_findings_layout.setSpacing(15)
        
        # Network log panel (left side)
        network_log_panel = QGroupBox()
        network_log_panel.setStyleSheet("""
            QGroupBox {
                background-color: #252525;
                border: 1px solid #3E3E3E;
                border-radius: 4px;
                margin-top: 30px;
                padding-top: 30px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top center;
                padding: 0 15px;
                color: #B388FF;
                font-weight: bold;
                background-color: #252525;
                font-size: 14px;
                top: 10px;
            }
        """)
        network_log_panel.setTitle("Network Scan Log")  # Set title after styling
        
        network_log_panel_layout = QVBoxLayout(network_log_panel)
        network_log_panel_layout.setContentsMargins(5, 10, 5, 5)
        network_log_panel_layout.setSpacing(5)
        
        self.network_status_display = QTextEdit()
        self.network_status_display.setReadOnly(True)
        self.network_status_display.setStyleSheet("""
            QTextEdit {
                background-color: #252525;
                color: #CCCCCC;
                border: 1px solid #3E3E3E;
                border-radius: 4px;
                padding: 5px;
                font-family: Menlo, Monaco, monospace;
                font-size: 10pt;
            }
        """)
        self.network_status_display.setMinimumHeight(300)
        network_log_panel_layout.addWidget(self.network_status_display)
        
        # Add clear network log button
        clear_network_log_button = QPushButton("Clear Log")
        clear_network_log_button.clicked.connect(self.clear_network_log)
        clear_network_log_button.setStyleSheet("""
            QPushButton {
                background-color: #424242;
                color: #CCCCCC;
                border: none;
                border-radius: 4px;
                padding: 6px 12px;
            }
            QPushButton:hover {
                background-color: #616161;
            }
            QPushButton:pressed {
                background-color: #757575;
            }
        """)
        clear_network_log_button.setMaximumWidth(120)
        
        # Add hide logs button
        hide_network_logs_button = QPushButton("Hide Logs")
        hide_network_logs_button.clicked.connect(self.toggle_network_log_visibility)
        hide_network_logs_button.setStyleSheet("""
            QPushButton {
                background-color: #424242;
                color: #CCCCCC;
                border: none;
                border-radius: 4px;
                padding: 6px 12px;
            }
            QPushButton:hover {
                background-color: #616161;
            }
            QPushButton:pressed {
                background-color: #757575;
            }
        """)
        hide_network_logs_button.setMaximumWidth(120)
        
        # Create a horizontal layout for the buttons
        network_log_buttons_layout = QHBoxLayout()
        network_log_buttons_layout.addWidget(clear_network_log_button)
        network_log_buttons_layout.addWidget(hide_network_logs_button)
        network_log_buttons_layout.addStretch()
        network_log_panel_layout.addLayout(network_log_buttons_layout)
        
        # Network findings panel (right side)
        network_findings_panel = QGroupBox()  # Create without title initially
        network_findings_panel.setStyleSheet("""
            QGroupBox {
                background-color: #252525;
                border: 1px solid #3E3E3E;
                border-radius: 4px;
                margin-top: 30px;
                padding-top: 30px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top center;
                padding: 0 15px;
                color: #C6FF00;
                font-weight: bold;
                background-color: #252525;
                font-size: 14px;
                top: 10px;
            }
        """)
        network_findings_panel.setTitle("Network Vulnerability Findings")  # Set title after styling
        
        network_findings_panel_layout = QVBoxLayout(network_findings_panel)
        network_findings_panel_layout.setContentsMargins(5, 10, 5, 5)
        network_findings_panel_layout.setSpacing(5)
        
        self.network_findings_display = QTextEdit()
        self.network_findings_display.setReadOnly(True)
        self.network_findings_display.setStyleSheet("""
            QTextEdit {
                background-color: #252525;
                color: #CCCCCC;
                border: 1px solid #3E3E3E;
                border-radius: 4px;
                padding: 5px;
                font-family: Menlo, Monaco, monospace;
                font-size: 10pt;
            }
        """)
        self.network_findings_display.setMinimumHeight(300)
        network_findings_panel_layout.addWidget(self.network_findings_display)
        
        # Add clear network findings button
        clear_network_findings_button = QPushButton("Clear Findings")
        clear_network_findings_button.clicked.connect(self.clear_network_findings)
        clear_network_findings_button.setStyleSheet("""
            QPushButton {
                background-color: #424242;
                color: #CCCCCC;
                border: none;
                border-radius: 4px;
                padding: 6px 12px;
            }
            QPushButton:hover {
                background-color: #616161;
            }
            QPushButton:pressed {
                background-color: #757575;
            }
        """)
        clear_network_findings_button.setMaximumWidth(120)
        network_findings_panel_layout.addWidget(clear_network_findings_button, alignment=Qt.AlignmentFlag.AlignRight)
        
        # Add panels to the network_log_findings_layout with equal width
        network_log_findings_layout.addWidget(network_log_panel, 1)
        network_log_findings_layout.addWidget(network_findings_panel, 1)
        
        network_scan_layout.addWidget(network_log_findings_section)
        
        # Network control buttons
        network_control_section = QWidget()
        network_control_layout = QHBoxLayout(network_control_section)
        network_control_layout.setContentsMargins(0, 0, 0, 0)
        
        self.network_start_button = QPushButton("Start Network Scan")
        self.network_start_button.setObjectName("primary")
        self.network_start_button.clicked.connect(self.start_network_scan)
        
        self.network_stop_button = QPushButton("Stop Network Scan")
        self.network_stop_button.setObjectName("danger")
        self.network_stop_button.clicked.connect(self.stop_network_scan)
        self.network_stop_button.setEnabled(False)
        
        network_control_layout.addWidget(self.network_start_button)
        network_control_layout.addWidget(self.network_stop_button)
        
        network_scan_layout.addWidget(network_control_section)
        
        # Network progress bar
        self.network_progress_bar = QProgressBar()
        self.network_progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #3E3E3E;
                border-radius: 4px;
                text-align: center;
                background-color: #252525;
            }
            QProgressBar::chunk {
                background-color: #C6FF00;
            }
        """)
        self.network_progress_bar.setRange(0, 100)
        self.network_progress_bar.setValue(0)
        network_scan_layout.addWidget(self.network_progress_bar)
        
    def setup_about_tab(self, tab):
        """Setup the about tab"""
        # Remove default margins from the tab
        tab.setContentsMargins(0, 0, 0, 0)
        
        about_layout = QVBoxLayout(tab)
        about_layout.setContentsMargins(10, 10, 10, 10)
        about_layout.setSpacing(10)
        
        # Create a scroll area for the about content
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.NoFrame)
        scroll_area.setStyleSheet("background-color: #1E1E1E; border: none;")
        about_layout.addWidget(scroll_area)
        
        # Create a widget to hold the content
        content_widget = QWidget()
        content_widget.setStyleSheet("background-color: #1E1E1E;")
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(15, 15, 15, 15)
        
        # Section fonts
        title_font = QFont()
        title_font.setPointSize(24)
        title_font.setBold(True)
        
        subtitle_font = QFont()
        subtitle_font.setPointSize(16)
        subtitle_font.setBold(True)
        
        # Add Pentora logo
        logo_container = QWidget()
        logo_layout = QHBoxLayout(logo_container)
        logo_path = get_app_icon_path()
        if os.path.exists(logo_path):
            logo_label = QLabel()
            logo_pixmap = QPixmap(logo_path)
            logo_pixmap = logo_pixmap.scaled(200, 200, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            logo_label.setPixmap(logo_pixmap)
            logo_label.setAlignment(Qt.AlignCenter)
            logo_layout.addWidget(logo_label)
            logo_layout.setAlignment(Qt.AlignCenter)
        content_layout.addWidget(logo_container)

        # Overview Section
        overview_text = '''<div style="color:#CCCCCC; font-size:12pt;">
            <h2 style="color:#B388FF; text-align:center;">Pentora - Web & Network Security Scanner</h2>
            <p>Pentora is a graphical user interface for vulnerability scanning, designed to make security testing accessible to everyone. It performs comprehensive tests to identify security vulnerabilities in web applications and network services.</p>
        </div>'''
        overview_label = QLabel()
        overview_label.setTextFormat(Qt.TextFormat.RichText)
        overview_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        overview_label.setWordWrap(True)
        overview_label.setStyleSheet("background-color: #252525; border-radius: 5px; padding: 16px;")
        overview_label.setText(overview_text)
        content_layout.addWidget(overview_label)
        content_layout.addSpacing(20)

        # GUI Guide Section
        gui_title = QLabel("GUI Guide")
        gui_title.setFont(subtitle_font)
        gui_title.setStyleSheet("color: #C6FF00;")
        content_layout.addWidget(gui_title)

        gui_frame = QFrame()
        gui_frame.setFrameShape(QFrame.StyledPanel)
        gui_frame.setStyleSheet("background-color: #252525; border-radius: 5px; border: 1px solid #3E3E3E; padding: 15px;")
        gui_layout = QVBoxLayout(gui_frame)

        # Scanner Controls subsection
        controls_text = QLabel("<b style='color: #C6FF00;'>Scanner Controls</b>")
        controls_text.setTextFormat(Qt.TextFormat.RichText)
        controls_text.setWordWrap(True)
        gui_layout.addWidget(controls_text)

        controls_list = QLabel(
            "<ul>"
            "<li><b>Start Scan Button:</b> Initiates the vulnerability scan with configured settings. It begins by crawling the target website and then runs the selected attack modules.</li>"
            "<li><b>Stop Scan Button:</b> Safely terminates an in-progress scan. The scan will attempt to complete its current operation and generate a report based on findings up to that point.</li>"
            "<li><b>Select Modules Button:</b> Opens a dialog that allows you to choose specific attack modules to run during the scan. This is only available when 'Custom' is selected in the modules dropdown.</li>"
            "</ul>"
        )
        controls_list.setTextFormat(Qt.TextFormat.RichText)
        controls_list.setWordWrap(True)
        controls_list.setStyleSheet("color: #CCCCCC;")
        gui_layout.addWidget(controls_list)
        gui_layout.addSpacing(10)

        # Configuration Options subsection
        config_text = QLabel("<b style='color: #C6FF00;'>Configuration Options</b>")
        config_text.setTextFormat(Qt.TextFormat.RichText)
        config_text.setWordWrap(True)
        gui_layout.addWidget(config_text)

        config_list = QLabel(
            "<ul>"
            "<li><b>URL Input Field:</b> Enter the target website address (e.g., https://example.com). Pentora will automatically add 'http://' if not specified.</li>"
            "<li><b>Scan Scope Dropdown:</b> Determines the scope of the vulnerability scan. Choose from:</li>"
            "<ul style='margin-left: 20px;'>"
            "<li><b>Folder:</b> Scans a specific directory and its subdirectories. Ideal for targeted testing of a particular section of a website.</li>"
            "<li><b>Domain:</b> Scans the entire domain, including all subdomains and associated resources. Best for comprehensive security assessments.</li>"
            "<li><b>Page:</b> Scans a single webpage and its immediate resources. Useful for quick testing of individual pages.</li>"
            "<li><b>URL:</b> Scans a specific URL and its direct resources. Similar to Page but more focused on a single endpoint.</li>"
            "</ul>"
            "<p style='margin-top: 10px; color: #CCCCCC;'>Note: Wider scopes like 'Domain' will scan more pages but may take significantly longer to complete. Choose the appropriate scope based on your testing needs and available time.</p>"
            "<li><b>Scan Depth Selector:</b> Controls how many link levels deep the scanner will crawl. Higher values find more pages but increase scan time.</li>"
            "<li><b>Request Timeout:</b> Sets how long the scanner waits for each page to respond before timing out. Increase this for slower websites.</li>"
            "<li><b>Modules Dropdown:</b> Choose which vulnerability tests to run - All Modules, Common Modules, or a Custom selection.</li>"
            "<li><b>Report Format:</b> Select the output format for scan results (HTML, JSON). HTML is most user-friendly with interactive elements.</li>"
            "<li><b>Output Directory:</b> Specify where to save the scan reports. Use the Browse button to select a directory.</li>"
            "</ul>"
        )
        config_list.setTextFormat(Qt.TextFormat.RichText)
        config_list.setWordWrap(True)
        config_list.setStyleSheet("color: #CCCCCC;")
        gui_layout.addWidget(config_list)
        content_layout.addWidget(gui_frame)
        content_layout.addSpacing(20)

        # Web Attack Modules Section
        web_attack_title = QLabel("Web Attack Modules")
        web_attack_title.setFont(subtitle_font)
        web_attack_title.setStyleSheet("color: #C6FF00;")
        content_layout.addWidget(web_attack_title)

        # SQL Injection Modules subsection
        web_attack_frame = QFrame()
        web_attack_frame.setFrameShape(QFrame.StyledPanel)
        web_attack_frame.setStyleSheet("background-color: #252525; border-radius: 5px; border: 1px solid #3E3E3E; padding: 15px;")
        web_attack_layout = QVBoxLayout(web_attack_frame)

        sql_text = QLabel("<b style='color: #C6FF00;'>SQL Injection Modules</b>")
        sql_text.setTextFormat(Qt.TextFormat.RichText)
        web_attack_layout.addWidget(sql_text)

        sql_list = QLabel(
            "<ul>"
            "<li><b>sql:</b> Tests for classic SQL injection vulnerabilities by sending specially crafted queries to database inputs. Detects both error-based and boolean-based SQL injections.</li>"
            "<li><b>timesql:</b> Performs time-based SQL injection tests that detect vulnerabilities even without visible output. Uses time delays in database responses to determine if injection is possible.</li>"
            "<li><b>ldap:</b> Identifies LDAP injection vulnerabilities by inserting special LDAP query characters and analyzing responses.</li>"
            "</ul>"
        )
        sql_list.setTextFormat(Qt.TextFormat.RichText)
        sql_list.setWordWrap(True)
        sql_list.setStyleSheet("color: #CCCCCC;")
        web_attack_layout.addWidget(sql_list)
        web_attack_layout.addSpacing(10)

        # XSS Modules subsection
        xss_text = QLabel("<b style='color: #C6FF00;'>Cross-Site Scripting (XSS) Modules</b>")
        xss_text.setTextFormat(Qt.TextFormat.RichText)
        web_attack_layout.addWidget(xss_text)

        xss_list = QLabel(
            "<ul>"
            "<li><b>xss:</b> Detects reflected XSS vulnerabilities by injecting script code into parameters and analyzing if the code is returned unfiltered in the response.</li>"
            "<li><b>permanentxss:</b> Identifies stored/persistent XSS vulnerabilities where injected code is saved on the server and affects multiple users.</li>"
            "<li><b>csp:</b> Evaluates Content-Security-Policy headers to identify misconfigured policies that may allow script injection.</li>"
            "<li><b>xxe:</b> Detects XML External Entity (XXE) injection vulnerabilities that can lead to server-side file disclosure or denial of service.</li>"
            "</ul>"
        )
        xss_list.setTextFormat(Qt.TextFormat.RichText)
        xss_list.setWordWrap(True)
        xss_list.setStyleSheet("color: #CCCCCC;")
        web_attack_layout.addWidget(xss_list)
        web_attack_layout.addSpacing(10)

        # File & Command Execution subsection
        file_exec_text = QLabel("<b style='color: #C6FF00;'>File & Command Execution</b>")
        file_exec_text.setTextFormat(Qt.TextFormat.RichText)
        web_attack_layout.addWidget(file_exec_text)

        file_exec_list = QLabel(
            "<ul>"
            "<li><b>file:</b> Detects file-related vulnerabilities including Path Traversal, Local File Inclusion (LFI), and Remote File Inclusion (RFI).</li>"
            "<li><b>exec:</b> Tests for command execution vulnerabilities by sending OS commands embedded in parameters.</li>"
            "<li><b>upload:</b> Checks for insecure file upload functionality by attempting to upload files with malicious content or invalid extensions.</li>"
            "<li><b>shellshock:</b> Scans for the Shellshock vulnerability (CVE-2014-6271) in Bash by sending specially crafted HTTP headers.</li>"
            "</ul>"
        )
        file_exec_list.setTextFormat(Qt.TextFormat.RichText)
        file_exec_list.setWordWrap(True)
        file_exec_list.setStyleSheet("color: #CCCCCC;")
        web_attack_layout.addWidget(file_exec_list)
        web_attack_layout.addSpacing(10)

        # Authentication & Session Issues subsection
        auth_text = QLabel("<b style='color: #C6FF00;'>Authentication & Session Issues</b>")
        auth_text.setTextFormat(Qt.TextFormat.RichText)
        web_attack_layout.addWidget(auth_text)

        auth_list = QLabel(
            "<ul>"
            "<li><b>brute_login_form:</b> Attempts to identify login forms and tests them with common credentials from dictionary lists.</li>"
            "<li><b>csrf:</b> Detects Cross-Site Request Forgery vulnerabilities by analyzing forms and determining if they use unpredictable tokens.</li>"
            "</ul>"
        )
        auth_list.setTextFormat(Qt.TextFormat.RichText)
        auth_list.setWordWrap(True)
        auth_list.setStyleSheet("color: #CCCCCC;")
        web_attack_layout.addWidget(auth_list)
        web_attack_layout.addSpacing(10)

        # Network & Server Discovery subsection
        discovery_text = QLabel("<b style='color: #C6FF00;'>Network & Server Discovery</b>")
        discovery_text.setTextFormat(Qt.TextFormat.RichText)
        web_attack_layout.addWidget(discovery_text)

        discovery_list = QLabel(
            "<ul>"
            "<li><b>backup:</b> Searches for backup files and directories by testing common backup extensions and naming patterns.</li>"
            "<li><b>buster:</b> Performs directory and file brute-forcing to discover hidden content, admin interfaces, and resources.</li>"
            "</ul>"
        )
        discovery_list.setTextFormat(Qt.TextFormat.RichText)
        discovery_list.setWordWrap(True)
        discovery_list.setStyleSheet("color: #CCCCCC;")
        web_attack_layout.addWidget(discovery_list)
        web_attack_layout.addSpacing(10)

        # HTTP Protocol & Redirects subsection
        http_text = QLabel("<b style='color: #C6FF00;'>HTTP Protocol & Redirects</b>")
        http_text.setTextFormat(Qt.TextFormat.RichText)
        web_attack_layout.addWidget(http_text)

        http_list = QLabel(
            "<ul>"
            "<li><b>http_header:</b> Examines HTTP security headers for issues, checking for missing security headers or information disclosure.</li>"
            "<li><b>redirect:</b> Detects open redirect vulnerabilities where user-controlled input determines redirect destinations.</li>"
            "<li><b>crlf:</b> Searches for CRLF injection vulnerabilities that allow attackers to inject HTTP headers.</li>"
            "<li><b>methods:</b> Checks which HTTP methods are supported by the server and if dangerous methods are properly restricted.</li>"
            "</ul>"
        )
        http_list.setTextFormat(Qt.TextFormat.RichText)
        http_list.setWordWrap(True)
        http_list.setStyleSheet("color: #CCCCCC;")
        web_attack_layout.addWidget(http_list)
        content_layout.addWidget(web_attack_frame)
        content_layout.addSpacing(20)

        # Network Scan Modules Section
        network_module_title = QLabel("Network Scan Modules")
        network_module_title.setFont(subtitle_font)
        network_module_title.setStyleSheet("color: #C6FF00;")
        content_layout.addWidget(network_module_title)

        network_module_frame = QFrame()
        network_module_frame.setFrameShape(QFrame.StyledPanel)
        network_module_frame.setStyleSheet("background-color: #252525; border-radius: 5px; border: 1px solid #3E3E3E; padding: 15px;")
        network_module_layout = QVBoxLayout(network_module_frame)

        network_vuln_text = QLabel("<b style='color: #C6FF00;'>Network Vulnerability Scanning</b>")
        network_vuln_text.setTextFormat(Qt.TextFormat.RichText)
        network_module_layout.addWidget(network_vuln_text)

        network_vuln_list = QLabel(
            "<ul>"
            "<li><b>open_ports:</b> Detects open ports and identifies running services on the target system.</li>"
            "<li><b>default_credentials:</b> Checks for default credentials on common services like FTP, SSH, Telnet, MySQL, etc.</li>"
            "<li><b>dos_vulnerabilities:</b> Identifies services that might be vulnerable to Denial of Service (DoS) attacks.</li>"
            "<li><b>no_auth_services:</b> Identifies services running without proper authentication requirements.</li>"
            "<li><b>service_vulnerabilities:</b> Checks for known vulnerabilities in detected services.</li>"
            "<li><b>snmp_public:</b> Checks if SNMP (Simple Network Management Protocol) is accessible with the default 'public' community string. "
            "This test attempts to detect devices that expose sensitive network or device information via SNMP without proper authentication. "
            "SNMP is widely used for network management, and leaving it open with the default community string ('public') is a common misconfiguration that can lead to information disclosure or even exploitation. "
            "The scanner first tries to use Nmap's SNMP scripts, then falls back to a direct SNMP GET request using Python if Nmap is unavailable or inconclusive." 
            "</li>"
            "</ul>"
        )
        network_vuln_list.setTextFormat(Qt.TextFormat.RichText)
        network_vuln_list.setWordWrap(True)
        network_vuln_list.setStyleSheet("color: #CCCCCC;")
        network_module_layout.addWidget(network_vuln_list)
        content_layout.addWidget(network_module_frame)
        content_layout.addSpacing(20)

        # Disclaimer Section
        disclaimer_title = QLabel("Important Disclaimer")
        disclaimer_title.setFont(subtitle_font)
        disclaimer_title.setStyleSheet("color: #B388FF;")
        content_layout.addWidget(disclaimer_title)

        disclaimer_frame = QFrame()
        disclaimer_frame.setFrameShape(QFrame.StyledPanel)
        disclaimer_frame.setStyleSheet("background-color: #252525; border-radius: 5px; border: 1px solid #3E3E3E; padding: 15px;")
        disclaimer_layout = QVBoxLayout(disclaimer_frame)

        disclaimer_text = QLabel(
            "⚠️ <b>This tool is intended for security professionals to test their own systems or systems they have permission to test. "
            "Always obtain proper authorization before scanning any website, web application, or network. "
            "Unauthorized scanning may be illegal and unethical.</b>"
        )
        disclaimer_text.setTextFormat(Qt.TextFormat.RichText)
        disclaimer_text.setWordWrap(True)
        disclaimer_text.setStyleSheet("color: #FF8A80;")
        disclaimer_layout.addWidget(disclaimer_text)
        content_layout.addWidget(disclaimer_frame)

        # Add some padding at the bottom
        content_layout.addSpacing(20)

        # Set the content widget to the scroll area
        scroll_area.setWidget(content_widget)
        
    def browse_output_dir(self):
        """Open a dialog to select the output directory"""
        directory = QFileDialog.getExistingDirectory(
            self, "Select Output Directory", self.output_dir_input.text()
        )
        if directory:
            self.output_dir_input.setText(directory)
            
    def browse_network_output_dir(self):
        """Open a dialog to select the network scan output directory"""
        directory = QFileDialog.getExistingDirectory(
            self, "Select Network Output Directory", self.network_output_dir_input.text()
        )
        if directory:
            self.network_output_dir_input.setText(directory)
            
    def clear_network_log(self):
        """Clear the network scan log"""
        self.network_status_display.clear()
        
    def clear_network_findings(self):
        """Clear the network vulnerability findings"""
        self.network_findings_display.clear()
        
    def update_network_status(self, message):
        """Update the network scan status display with formatted messages"""
        # Ensure we're on the GUI thread
        if QThread.currentThread() != self.thread():
            return

        formatted_text = message
        format_type = "normal" # Default format

        try:
            # Check if the message is an actual dictionary object
            if isinstance(message, dict) and "text" in message and "format" in message:
                formatted_text = message["text"]
                format_type = message["format"]
            # Check if the message is the string representation of our dictionary format
            elif isinstance(message, str) and message.strip().startswith("{") and message.strip().endswith("}"):
                import ast
                try:
                    format_dict = ast.literal_eval(message.strip())
                    if isinstance(format_dict, dict) and "text" in format_dict and "format" in format_dict:
                        formatted_text = format_dict["text"]
                        format_type = format_dict["format"]
                    else:
                        # If literal_eval works but it's not the expected dict, treat as normal string
                        formatted_text = message # Use original message
                        format_type = "normal"
                except (SyntaxError, ValueError):
                    # Not a valid dict string, treat as normal string
                    formatted_text = message # Use original message
                    format_type = "normal"
            # Handle simple strings by detecting keywords (existing logic)
            elif isinstance(message, str):
                # Apply specific formatting based on message content
                if message.startswith("Running attack module:") or message.startswith("Launching module"):
                    # Extract module name for consistency
                    module_name = None # Initialize module_name
                    if message.startswith("Running attack module:"):
                        module_parts = message.split(":")
                        if len(module_parts) > 1:
                            module_name = module_parts[1].strip()
                    else:  # Launching module format
                        module_match = re.search(r'Launching module (\w+)', message)
                        if module_match:
                            module_name = module_match.group(1)

                    # Only update if we extracted a module name
                    if module_name:
                        self.update_current_module(module_name)

                    formatted_text = f"🚀 {message}"
                    format_type = "module"
                elif "scanning" in message.lower() or "discovering" in message.lower():
                    formatted_text = f"🔍 {message}"
                    format_type = "crawling"
                elif "vulnerability" in message.lower() or "discovered" in message.lower():
                    formatted_text = f"🔴 {message}"
                    format_type = "vulnerability"
                elif "initializing" in message.lower() or "starting" in message.lower():
                    formatted_text = f"⚙️ {message}"
                    format_type = "info"
                elif "completed" in message.lower() or "finished" in message.lower():
                    formatted_text = f"✅ {message}"
                    format_type = "notification"
                elif "error" in message.lower() or "failed" in message.lower():
                    formatted_text = f"❌ {message}"
                    format_type = "error"
                else:
                    # Default case for simple strings
                    formatted_text = f"ℹ️ {message}"
                    format_type = "normal"
            else:
                 # Fallback for unexpected message types
                 formatted_text = str(message)
                 format_type = "normal"

        except Exception as e:
            # Log formatting errors and display the original message
            print(f"Error formatting network status message: {e}\nOriginal message: {message}")
            formatted_text = str(message) # Display original message on error
            format_type = "error" # Mark as error

        # Apply colors based on format type
        # Ensure formatted_text is a string before passing
        html_message = self._apply_format_to_message(str(formatted_text), format_type)

        # Append the formatted HTML message
        self.network_status_display.append(html_message)
        
        # Auto-scroll to the bottom
        cursor = self.network_status_display.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.network_status_display.setTextCursor(cursor)
    
    def _apply_format_to_message(self, text, format_type):
        """Apply HTML formatting based on the format type"""
        color_map = {
            "normal": "#FFFFFF",       # White
            "info": "#BB86FC",         # Purple
            "module": "#FFDF2B",       # Bright yellow
            "launching": "#FFC107",    # Amber
            "crawling": "#03DAC6",     # Teal/Green
            "request": "#64FFDA",      # Light teal
            "vulnerability": "#FF5252", # Red
            "error": "#CF6679",        # Error red
            "notification": "#69F0AE"  # Green
        }
        
        color = color_map.get(format_type, "#FFFFFF")
        return f"<span style='color: {color};'>{text}</span>"
        
    def update_network_findings(self, message):
        """Update the network vulnerability findings display"""
        # Ensure we're on the GUI thread
        if QThread.currentThread() != self.thread():
            # If called from another thread, use a signal-slot connection
            # But since we're already connected in the thread, this shouldn't happen
            return
        
        # Format the message - assume all findings are vulnerabilities
        formatted_text = f"🔴 {message}" if not message.startswith("🔴") else message
        html_message = self._apply_format_to_message(formatted_text, "vulnerability")
            
        self.network_findings_display.append(html_message)
        # Auto-scroll to the bottom
        cursor = self.network_findings_display.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.network_findings_display.setTextCursor(cursor)
        
    def update_network_progress(self, value):
        """Update the network scan progress bar"""
        self.network_progress_bar.setValue(value)
        
    def start_network_scan(self):
        """Start a network vulnerability scan using the NetworkScanner"""
        # Get target from input
        target = self.network_target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Input Error", "Please enter a valid network target (e.g., 192.168.1.1/24)")
            return
            
        # Get port range
        port_range = self.network_port_input.text().strip()
        if not port_range:
            port_range = "1-1000"  # Default port range
            
        # Get output directory
        output_dir = self.network_output_dir_input.text().strip()
        if not output_dir:
            QMessageBox.warning(self, "Input Error", "Please specify an output directory for reports")
            return
            
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
            
        # Get report format
        report_format = self.network_report_format_combo.currentText()
            
        # Get selected modules
        if self.network_modules_combo.currentIndex() == 0:
            selected_modules = ["all"]
        else:
            selected_modules = getattr(self, 'selected_network_modules', ["all"])
            
        # Update UI state
        self.network_start_button.setEnabled(False)
        self.network_stop_button.setEnabled(True)
        self.network_progress_bar.setValue(10)
        self.update_network_status(f"Starting network vulnerability scan on target: {target}")
        self.update_network_status(f"Using modules: {', '.join(selected_modules)}")
            
        # Create a thread for the network scan
        self.network_scanner_thread = NetworkScannerThread(
            target, 
            output_dir,
            report_format,
            port_range,
            selected_modules,
            self.update_network_status,
            self.update_network_findings
        )
        self.network_scanner_thread.progress_update.connect(self.update_network_progress)
        self.network_scanner_thread.scan_complete.connect(self.on_network_scan_complete)
        self.network_scanner_thread.html_ready_for_pdf.connect(self.handle_pdf_conversion)
        self.network_scanner_thread.start()
            
    def stop_network_scan(self):
        """Stop the running network scan"""
        if self.network_scanner_thread and self.network_scanner_thread.isRunning():
            self.update_network_status("Stopping network scan...")
            self.network_scanner_thread.stop()
            self.network_scanner_thread.wait()
            self.update_network_status("Network scan stopped")
            
        # Update UI state
        self.network_start_button.setEnabled(True)
        self.network_stop_button.setEnabled(False)
            
    def update_network_progress(self, value):
        """Update the network scan progress bar"""
        self.network_progress_bar.setValue(value)
            
    def on_network_scan_complete(self, report_path=""):
        """Handle network scan completion"""
        self.network_progress_bar.setValue(100)
        self.network_start_button.setEnabled(True)
        self.network_stop_button.setEnabled(False)
        self.update_network_status("Network vulnerability scan completed")
        
        # Offer to open the report if available
        if report_path and os.path.exists(report_path):
            reply = QMessageBox.question(
                self, 
                "Network Scan Complete", 
                f"Network scan completed successfully. Would you like to open the report?",
                QMessageBox.Yes | QMessageBox.No, 
                QMessageBox.Yes
            )
            if reply == QMessageBox.Yes:
                try:
                    # Open the report using the default system application
                    if os.name == 'nt':  # Windows
                        # Make sure we're opening the file, not just the directory
                        if os.path.isfile(report_path):
                            os.startfile(report_path)
                        else:
                            # If report_path is a directory, try to find the HTML or JSON report
                            report_dir = report_path
                            possible_reports = [
                                os.path.join(report_dir, f) for f in os.listdir(report_dir) 
                                if f.endswith('.html') or f.endswith('.json')
                            ]
                            if possible_reports:
                                # Use the most recently modified file
                                newest_report = max(possible_reports, key=os.path.getmtime)
                                os.startfile(newest_report)
                            else:
                                # Fallback to opening the directory
                                os.startfile(report_dir)
                    else:  # Linux/Mac
                        import subprocess
                        import sys
                        # Use 'open' on macOS (darwin) and 'xdg-open' on Linux
                        open_command = 'open' if sys.platform == 'darwin' else 'xdg-open'
                        
                        if os.path.isfile(report_path):
                            subprocess.call([open_command, report_path])
                        else:
                            # If report_path is a directory, try to find the HTML or JSON report
                            report_dir = report_path
                            possible_reports = [
                                os.path.join(report_dir, f) for f in os.listdir(report_dir) 
                                if f.endswith('.html') or f.endswith('.json')
                            ]
                            if possible_reports:
                                # Use the most recently modified file
                                newest_report = max(possible_reports, key=os.path.getmtime)
                                subprocess.call([open_command, newest_report])
                            else:
                                # Fallback to opening the directory
                                subprocess.call([open_command, report_dir])
                except Exception as e:
                    QMessageBox.warning(
                        self, 
                        "Error Opening Report", 
                        f"Could not open the report file: {str(e)}"
                    )
        
    def select_modules(self):
        """Open module selection dialog"""
        # Create a new dialog instance each time
        self.module_dialog = ModuleSelectionDialog(self)
        
        # Initialize module selection based on current selection
        if hasattr(self, 'selected_modules') and self.selected_modules:
            module_list = self.selected_modules.split(',')
            for i in range(self.module_dialog.module_list.count()):
                item = self.module_dialog.module_list.item(i)
                module_name = item.text().split(' - ')[0]
                if module_name in module_list:
                    item.setCheckState(Qt.CheckState.Checked)
        
        # Execute the dialog and get result
        if self.module_dialog.exec():  # Changed from exec_() to exec()
            # Dialog accepted (OK clicked)
            self.selected_modules = self.module_dialog.get_selected_modules()
            
    def on_modules_changed(self):
        """Show or hide module selection based on combo box value"""
        if self.modules_combo.currentText() == "Custom":
            self.modules_button.setVisible(True)
        else:
            self.modules_button.setVisible(False)
            
    def start_scan(self):
        """Start the vulnerability scan"""
        url = self.url_input.text().strip()
        
        if not url:
            QMessageBox.warning(self, "Input Error", "Please enter a URL to scan.")
            return
            
        # Prepare scan options
        options = {
            'scope': self.scope_combo.currentText(),
            'depth': self.depth_spin.value(),
            'timeout': self.timeout_spin.value(),
            'report_format': self.report_format_combo.currentText(),
            'output_dir': self.output_dir_input.text()
        }
        
        # Get modules
        if self.modules_combo.currentText() == "Custom" and hasattr(self, 'module_dialog'):
            options['modules'] = self.module_dialog.get_selected_modules()
        else:
            options['modules'] = self.modules_combo.currentData()
        
        # Update UI
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress_bar.setValue(0)
        self.status_display.clear()
        self.add_status_message("Starting scan...")
        
        # Start scanner thread
        self.scanner_thread = ScannerThread(url, options)
        self.scanner_thread.update_status.connect(self.add_status_message)
        self.scanner_thread.update_vuln.connect(self.add_vuln_message)
        self.scanner_thread.update_progress.connect(self.progress_bar.setValue)
        self.scanner_thread.update_module.connect(self.update_current_module)
        self.scanner_thread.scan_complete.connect(self.scan_completed)
        self.scanner_thread.scan_error.connect(self.scan_error)
        # Connect the new signal for PDF conversion
        self.scanner_thread.html_ready_for_pdf.connect(self.handle_pdf_conversion)
        self.scanner_thread.start()
        
    def stop_scan(self):
        """
        Stop the current scan gracefully.
        
        This method:
        1. Updates the UI to provide immediate visual feedback
        2. Delegates to the scanner thread's stop method
        3. Uses the controller's stop mechanism to ensure clean shutdown
        
        The actual stopping is handled via asyncio event that coordinates
        between the GUI and controller.
        """
        if self.scanner_thread and self.scanner_thread.isRunning():
            # Immediately update UI to provide feedback
            self.stop_button.setEnabled(False)
            self.add_status_message("Stopping scan...")
            
            # Request the scanner thread to stop using controller's mechanism
            self.scanner_thread.stop()
            
            # Re-enable the start button immediately
            self.start_button.setEnabled(True)
            
            # Update progress bar to show that we're in a stopping state
            self.progress_bar.setValue(0)
            
    def scan_completed(self, report_file):
        """Handle scan completion"""
        # Re-enable the start button and disable stop button
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        
        # Show completion message
        self.add_status_message(f"Scan completed. Report saved to: {report_file}")
        
        # Ask if user wants to open the report
        if report_file and os.path.exists(report_file):
            reply = QMessageBox.question(
                self, 
                "Scan Complete", 
                f"Scan completed successfully. Would you like to open the report?",
                QMessageBox.Yes | QMessageBox.No, 
                QMessageBox.Yes
            )
            if reply == QMessageBox.Yes:
                try:
                    # Open the report using the default system application
                    if os.name == 'nt':  # Windows
                        # Make sure we're opening the file, not just the directory
                        if os.path.isfile(report_file):
                            os.startfile(report_file)
                        else:
                            # If report_file is a directory, try to find the HTML or JSON report
                            report_dir = report_file
                            possible_reports = [
                                os.path.join(report_dir, f) for f in os.listdir(report_dir) 
                                if f.endswith('.html') or f.endswith('.json')
                            ]
                            if possible_reports:
                                # Use the most recently modified file
                                newest_report = max(possible_reports, key=os.path.getmtime)
                                os.startfile(newest_report)
                            else:
                                # Fallback to opening the directory
                                os.startfile(report_dir)
                    else:  # Linux/Mac
                        import subprocess
                        import sys
                        # Use 'open' on macOS (darwin) and 'xdg-open' on Linux
                        open_command = 'open' if sys.platform == 'darwin' else 'xdg-open'
                        
                        if os.path.isfile(report_file):
                            subprocess.call([open_command, report_file])
                        else:
                            # If report_file is a directory, try to find the HTML or JSON report
                            report_dir = report_file
                            possible_reports = [
                                os.path.join(report_dir, f) for f in os.listdir(report_dir) 
                                if f.endswith('.html') or f.endswith('.json')
                            ]
                            if possible_reports:
                                # Use the most recently modified file
                                newest_report = max(possible_reports, key=os.path.getmtime)
                                subprocess.call([open_command, newest_report])
                            else:
                                # Fallback to opening the directory
                                subprocess.call([open_command, report_dir])
                except Exception as e:
                    QMessageBox.warning(
                        self, 
                        "Error Opening Report", 
                        f"Could not open the report file: {str(e)}"
                    )
        
    def scan_error(self, error_message):
        """Handle scan errors"""
        # Re-enable the start button and disable stop button
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        
        # Show error dialog
        QMessageBox.critical(self, "Scan Error", f"An error occurred during the scan:\n\n{error_message}")
        
    def add_status_message(self, message):
        """Add a message to the status log"""
        # Extract format information if available
        try:
            # Check if the message is already a dictionary object
            if isinstance(message, dict) and "text" in message and "format" in message:
                message_text = message["text"]
                message_format = message["format"]
            # Check if the message is a dictionary string
            elif isinstance(message, str) and message.startswith("{") and message.endswith("}"):
                import ast
                try:
                    format_dict = ast.literal_eval(message)
                    if isinstance(format_dict, dict) and "text" in format_dict and "format" in format_dict:
                        message_text = format_dict["text"]
                        message_format = format_dict["format"]
                    else:
                        # Invalid format, treat as regular message
                        message_text = message
                        message_format = "standard"
                except (SyntaxError, ValueError):
                    # Not a valid dict string
                    message_text = message
                    message_format = "standard"
            else:
                # Apply color formatting based on keywords in the message
                cursor = self.status_display.textCursor()
                cursor.movePosition(QTextCursor.End)
                
                # Reset to default format first
                text_format = cursor.charFormat()
                
                # Auto-detect message type based on content
                if "Starting scan" in message or "Scan complete" in message:
                    text_format.setForeground(QColor("#B388FF"))  # Purple
                    text_format.setFontWeight(QFont.Bold)
                elif "Initializing" in message or "Creating base" in message or "Setting" in message:
                    text_format.setForeground(QColor("#9C27B0"))  # Purple
                    text_format.setFontWeight(QFont.Bold)
                elif "Crawling" in message or "Starting web" in message:
                    text_format.setForeground(QColor("#4CAF50"))  # Green
                    text_format.setFontWeight(QFont.Bold)
                elif "Loading" in message or "Found" in message:
                    text_format.setForeground(QColor("#009688"))  # Teal
                    text_format.setFontWeight(QFont.Bold)
                elif "Saving" in message or "Report" in message:
                    text_format.setForeground(QColor("#FFC107"))  # Amber
                    text_format.setFontWeight(QFont.Bold)
                elif "Stopping" in message or "Cleaning" in message:
                    text_format.setForeground(QColor("#FF9800"))  # Orange
                    text_format.setFontWeight(QFont.Bold)
                elif "Error" in message or "Failed" in message:
                    text_format.setForeground(QColor("#F44336"))  # Red
                    text_format.setFontWeight(QFont.Bold)
                elif "Scan completed" in message or "Open" in message:
                    text_format.setForeground(QColor("#8BC34A"))  # Light green
                    text_format.setFontWeight(QFont.Bold)
                else:
                    # Default formatting for other messages
                    text_format.setForeground(QColor("#757575"))  # Dark gray
                
                # Apply the format and insert text
                cursor.setCharFormat(text_format)
                cursor.insertText(message)
                cursor.insertText("\n")
                self.status_display.setTextCursor(cursor)
                return
                
            # Create a cursor
            cursor = self.status_display.textCursor()
            cursor.movePosition(QTextCursor.End)
            
            # Set text format based on type
            text_format = cursor.charFormat()
            
            # Reset the format first to default
            text_format.setForeground(QColor("black"))  # Default text color
            text_format.setFontWeight(QFont.Normal)     # Default font weight
            
            # Then apply the specific format
            if message_format == "module":
                text_format.setForeground(QColor("#C6FF00"))  # Neon green/yellow
                text_format.setFontWeight(QFont.Bold)
            elif message_format == "vulnerability":
                text_format.setForeground(QColor("#F44336"))  # Red
                text_format.setFontWeight(QFont.Bold)
            elif message_format == "crawling":
                text_format.setForeground(QColor("#4CAF50"))  # Green
            elif message_format == "error":
                text_format.setForeground(QColor("#FF5722"))  # Orange
                text_format.setFontWeight(QFont.Bold)
            elif message_format == "info":
                text_format.setForeground(QColor("#B388FF"))  # Purple
            elif message_format == "launching":
                text_format.setForeground(QColor("#FF9800"))  # Orange
            elif message_format == "notification":
                text_format.setForeground(QColor("#B388FF"))  # Purple
                text_format.setFontWeight(QFont.Bold)
            elif message_format == "request":
                text_format.setForeground(QColor("#64FFDA"))  # Teal
            # Add more formats as needed
            
            # Apply the format and insert text
            cursor.setCharFormat(text_format)
            cursor.insertText(message_text)
            cursor.insertText("\n")
            
            # Reset the format again for the next message
            text_format = cursor.charFormat()
            text_format.setForeground(QColor("black"))  # Default text color
            text_format.setFontWeight(QFont.Normal)     # Default font weight
            cursor.setCharFormat(text_format)
            
            self.status_display.setTextCursor(cursor)
        except Exception as e:
            # Fallback to simple append in case of error
            self.status_display.append(f"[Error formatting message: {str(e)}]\n{message}")
        
        # Auto-scroll to the latest message
        self.status_display.moveCursor(QTextCursor.End)
        self.status_display.ensureCursorVisible()
        
        # Limit the number of lines to improve performance
        document = self.status_display.document()
        max_lines = 1000
        if document.lineCount() > max_lines:
            cursor = QTextCursor(document)
            cursor.movePosition(QTextCursor.Start)
            cursor.movePosition(QTextCursor.Down, QTextCursor.KeepAnchor, document.lineCount() - max_lines)
            cursor.removeSelectedText()
        
        # Process events to keep UI responsive
        QApplication.processEvents()
        
    def add_vuln_message(self, message):
        """Add a message to the findings log"""
        # Extract format information if available
        try:
            # Check if the message is already a dictionary object
            if isinstance(message, dict) and "text" in message and "format" in message:
                message_text = message["text"]
                message_format = message["format"]
            # Check if the message is a dictionary string
            elif isinstance(message, str) and message.startswith("{") and message.endswith("}"):
                import ast
                try:
                    format_dict = ast.literal_eval(message)
                    if isinstance(format_dict, dict) and "text" in format_dict and "format" in format_dict:
                        message_text = format_dict["text"]
                        message_format = format_dict["format"]
                    else:
                        # Invalid format, treat as regular message
                        message_text = message
                        message_format = "standard"
                except (SyntaxError, ValueError):
                    # Not a valid dict string
                    message_text = message
                    message_format = "standard"
            else:
                # For non-formatted messages, assume they're vulnerabilities
                message_text = f"🔴 {message}" if not message.startswith("🔴") else message
                message_format = "vulnerability"
                
            # Create a cursor
            cursor = self.findings_display.textCursor()
            cursor.movePosition(QTextCursor.End)
            
            # Set text format based on type
            text_format = cursor.charFormat()
            
            # Reset the format first to default
            text_format.setForeground(QColor("black"))  # Default text color
            text_format.setFontWeight(QFont.Normal)     # Default font weight
            
            # Then apply the specific format
            if message_format == "vulnerability":
                text_format.setForeground(QColor("#F44336"))  # Red
                text_format.setFontWeight(QFont.Bold)
            
            # Apply the format and insert text
            cursor.setCharFormat(text_format)
            cursor.insertText(message_text)
            cursor.insertText("\n")
            
            # Add a separator line after each vulnerability
            separator_format = cursor.charFormat()
            separator_format.setForeground(QColor("#BDBDBD"))  # Light gray
            cursor.setCharFormat(separator_format)
            cursor.insertText("─" * 50)  # 50 dash characters
            cursor.insertText("\n\n")  # Add extra line after separator
            
            # Reset the format again for the next message
            text_format = cursor.charFormat()
            text_format.setForeground(QColor("black"))  # Default text color
            text_format.setFontWeight(QFont.Normal)     # Default font weight
            cursor.setCharFormat(text_format)
            
            self.findings_display.setTextCursor(cursor)
        except Exception as e:
            # Fallback to simple append in case of error
            self.findings_display.append(f"[Error formatting message: {str(e)}]\n{message}")
        
        # Auto-scroll to the latest message
        self.findings_display.moveCursor(QTextCursor.End)
        self.findings_display.ensureCursorVisible()
        
        # Limit the number of lines to improve performance
        document = self.findings_display.document()
        max_lines = 1000
        if document.lineCount() > max_lines:
            cursor = QTextCursor(document)
            cursor.movePosition(QTextCursor.Start)
            cursor.movePosition(QTextCursor.Down, QTextCursor.KeepAnchor, document.lineCount() - max_lines)
            cursor.removeSelectedText()
        
        # Process events to keep UI responsive
        QApplication.processEvents()
        
    def clear_log(self):
        """Clear the status log"""
        self.status_display.clear()
        
    def clear_findings(self):
        """Clear the findings log"""
        self.findings_display.clear()

    def toggle_log_visibility(self):
        """Toggle the visibility of the log display"""
        if self.status_display.isVisible():
            self.status_display.hide()
            self.sender().setText("Show Logs")
        else:
            self.status_display.show()
            self.sender().setText("Hide Logs")

    def select_network_modules(self):
        """Open network module selection dialog"""
        dialog = NetworkModuleSelectionDialog(self)
        if dialog.exec():  # Changed from exec_() to exec()
            self.selected_network_modules = dialog.get_selected_modules()
            if not self.selected_network_modules:
                self.selected_network_modules = ["all"]
                self.network_modules_combo.setCurrentIndex(0)
            else:
                self.network_modules_combo.setCurrentIndex(1)

    def update_current_module(self, module_name):
        """Update the current module label"""
        # Skip empty inputs
        if not module_name:
            return
            
        # Check if the input contains the full message or just the module name
        if module_name.startswith("Running attack module:"):
            # Extract the module name from the message
            module_parts = module_name.split(":")
            if len(module_parts) > 1:
                module_name = module_parts[1].strip()
        elif module_name.startswith("Running:"):
            # Handle if already formatted from LogHandler
            module_parts = module_name.split(":")
            if len(module_parts) > 1:
                module_name = module_parts[1].strip()
        elif module_name.startswith("Launching module"):
            # Extract from launching format
            module_match = re.search(r'Launching module (\w+)', module_name)
            if module_match:
                module_name = module_match.group(1)
                
        # Format the module name for display
        formatted_module = f"Current Module: {module_name}"
        
        # Apply visual styling to make the module name stand out
        self.current_module_label.setText(formatted_module)
        
        # Make sure it's also visible in the status log with proper formatting
        formatted_message = {
            "text": f"🚀 Running module: {module_name}",
            "format": "module"
        }
        self.add_status_message(str(formatted_message))

    def toggle_network_log_visibility(self):
        """Toggle the visibility of the network log display"""
        if self.network_status_display.isVisible():
            self.network_status_display.hide()
            self.sender().setText("Show Logs")
        else:
            self.network_status_display.show()
            self.sender().setText("Hide Logs")

    # Slot to handle PDF conversion requests from background threads
    def handle_pdf_conversion(self, html_path, pdf_path):
        """Handle PDF conversion using QWebEngineView"""
        self.add_status_message(f"Converting {html_path} to PDF...")
        
        # Create a QWebEngineView instance
        view = QWebEngineView()
        loop = QEventLoop()
        conversion_success = False # Track success

        # Define the callback function to receive PDF data (bytes)
        def save_pdf_data(pdf_data):
            nonlocal conversion_success
            if pdf_data:
                try:
                    with open(pdf_path, 'wb') as f:
                        f.write(pdf_data)
                    conversion_success = True
                    self.add_status_message(f"Successfully generated PDF: {pdf_path}")
                    # Determine if this was a web or network scan to call the correct completion handler
                    if hasattr(self, 'scanner_thread') and self.scanner_thread and self.sender() == self.scanner_thread:
                        self.scan_completed(pdf_path)
                    elif hasattr(self, 'network_scanner_thread') and self.network_scanner_thread and self.sender() == self.network_scanner_thread:
                        self.on_network_scan_complete(pdf_path)
                    else:
                        self.add_status_message("PDF conversion complete.") # Fallback
                except IOError as e:
                    self.add_status_message(f"Error saving PDF to {pdf_path}: {e}")
                    # Optionally fall back to HTML completion
                    # self.scan_completed(html_path)
            else:
                self.add_status_message(f"Error: PDF generation failed (received empty data).")
                # Optionally fall back to HTML completion
                # self.scan_completed(html_path)

            # Clean up the view object when done, regardless of success
            view.deleteLater()
            loop.quit()

        def on_load_finished(ok):
            if ok:
                # Short delay before printing
                # Pass the callback function as the first argument
                QTimer.singleShot(200, lambda: view.page().printToPdf(save_pdf_data))
            else:
                self.add_status_message(f"Error: Failed to load HTML from {html_path} for PDF conversion.")
                view.deleteLater()
                loop.quit()

        view.loadFinished.connect(on_load_finished)
        view.load(QUrl.fromLocalFile(html_path))

        # Start the event loop to wait for signals
        loop.exec_()


class NetworkScannerThread(QThread):
    """Thread for running the network scanner without blocking the GUI"""
    progress_update = pyqtSignal(int)
    scan_complete = pyqtSignal(str)
    status_update = pyqtSignal(str)
    findings_update = pyqtSignal(str)
    # New signal for PDF conversion request
    html_ready_for_pdf = pyqtSignal(str, str)

    def __init__(self, target, output_dir, report_format, port_range, modules, update_status, update_findings):
        super().__init__()
        self.target = target
        self.output_dir = output_dir
        # Store the originally requested format
        self.requested_report_format = report_format
        self.report_format = report_format # Keep for internal logic if needed, though we override below
        self.port_range = port_range
        self.modules = modules
        self.update_status_callback = update_status
        self.update_findings_callback = update_findings
        self.stop_requested = False
        
        # Connect signals to callbacks
        self.status_update.connect(self.update_status_callback)
        self.findings_update.connect(self.update_findings_callback)

    def update_status(self, message):
        """Thread-safe status update. Emits the raw message."""
        # Emit the raw message directly. Formatting will be handled by the receiver.
        self.status_update.emit(message)

    def update_findings(self, message):
        """Thread-safe findings update. Emits the raw message."""
        # Emit the raw message directly. Formatting will be handled by the receiver.
        self.findings_update.emit(message)

    def run(self):
        """Run the network scan in a separate thread"""
        try:
            # Update status
            self.update_status("Initializing network vulnerability scan...")
            
            # Create a NetworkScanner instance
            from pentora.network_scanner import NetworkScanner
            scanner = NetworkScanner(self.update_status)
            
            # Configure the scanner
            scanner.set_target(self.target)
            scanner.set_ports(self.port_range)
            scanner.set_output_dir(self.output_dir)
            # ALWAYS tell NetworkScanner to generate HTML if PDF is the final goal
            core_report_format = 'html' if self.requested_report_format == 'pdf' else self.requested_report_format
            scanner.set_report_format(core_report_format)
            scanner.enable_modules(self.modules)

            # Set performance optimization parameters
            scanner.set_timeout(3)  # Reduce timeout for faster scanning
            scanner.set_max_threads(100)  # Increase thread count for parallel operations
            scanner.set_verbose(True)  # Enable verbose output for better feedback
            
            # Start the scan
            self.update_status("Starting network vulnerability scan...")
            self.progress_update.emit(10)  # Initial progress
            
            # Run the scan
            report_path = scanner.scan()
            
            # Update progress
            self.progress_update.emit(75)
            
            # Get findings
            findings = scanner.get_findings()
            
            # Update findings display
            vuln_count = 0
            if isinstance(findings, dict) and 'findings' in findings:
                for finding in findings['findings']:
                    self.update_findings(finding)
                    vuln_count += 1
            else:
                # Backward compatibility with older version
                for finding in findings:
                    self.update_findings(finding)
                    vuln_count += 1
            
            # Update status with summary
            if vuln_count > 0:
                self.update_status(f"Network scan found {vuln_count} potential issues")
            
            # Update status
            if report_path:
                self.update_status(f"Network vulnerability scan completed. Report saved to: {report_path}")
            else:
                self.update_status("Network vulnerability scan completed, but no report was generated.")
            
            # Update progress
            self.progress_update.emit(100)
            
            # Emit completion signal with the report path
            self.scan_complete.emit(report_path if report_path else "")

            # Check the *original* requested format for PDF conversion
            if self.requested_report_format == 'pdf':
                # Check if we have a report path
                if report_path:
                    if HAS_WEBENGINE:
                        # Use the report path as our HTML file
                        html_path = report_path
                        
                        # Check if the file exists
                        if os.path.exists(html_path):
                            # Add a small delay to allow file writing to complete
                            self.update_status(f"Waiting briefly before PDF conversion...")
                            import time
                            time.sleep(0.5) # Wait half a second

                            # Re-check existence after delay
                            if not os.path.exists(html_path):
                                self.update_status(f"Error: HTML file disappeared after delay: {html_path}")
                                self.scan_error.emit("Internal error: Report file disappeared.")
                                return # Exit if file vanished

                            # Generate the PDF path in the same directory
                            pdf_path = os.path.splitext(html_path)[0] + ".pdf"
                            os.makedirs(os.path.dirname(pdf_path), exist_ok=True)
                            self.update_status(f"HTML report path identified: {html_path}. Requesting PDF conversion to {pdf_path}...")
                            self.html_ready_for_pdf.emit(html_path, pdf_path)
                        else:
                            self.update_status(f"Error: Could not find HTML report file: {html_path}")
                            self.scan_error.emit("Internal error during PDF report preparation (HTML file not found).")
                    else:
                        self.update_status("Error: PyQtWebEngine required for PDF. Saving as HTML.")
                        self.scan_complete.emit(report_path) # Fallback
                else:
                    self.update_status("Error: No report file generated")
                    self.scan_complete.emit("")
            elif report_path: # Handle HTML/JSON completion normally
                self.scan_complete.emit(report_path)
            else:
                 self.scan_complete.emit("") # Emit empty if no report path

        except Exception as e:
            # Handle exceptions
            self.update_status(f"Error during network scan: {str(e)}")
            self.update_status(traceback.format_exc())
            self.progress_update.emit(0)
            
    def stop(self):
        """Request the scan to stop"""
        self.stop_requested = True


def get_app_icon_path():
    """Get the path to the application icon"""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), 'resources', 'images', 'Pentora_logo.png')

def main():
    """Main function to start the application"""
    app = QApplication(sys.argv)
    
    # Set application-wide properties
    app.setApplicationName("Pentora")
    app.setApplicationDisplayName("Pentora Vulnerability Scanner")
    
    # Set application icon (will be used in taskbar and window decorations)
    icon_path = get_app_icon_path()
    if os.path.exists(icon_path):
        app_icon = QIcon(icon_path)
        app.setWindowIcon(app_icon)
    
    # Create and show main window
    window = PentoraMainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
