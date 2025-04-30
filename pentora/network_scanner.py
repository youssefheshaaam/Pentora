#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Pentora Network Scanner Module
# Copyright (C) 2025 Pentora Team

import os
import time
import socket
import urllib.request
import urllib.parse
import re
import base64
import ftplib
import json
import random
import html
import datetime
import ssl
import csv
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import logging
import traceback
import subprocess
from pathlib import Path
from datetime import datetime as dt

import concurrent

# Optional imports - make them conditional to ensure the scanner runs even if some libraries are missing
try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    paramiko = None
    HAS_PARAMIKO = False

try:
    import requests
    import urllib3
    from urllib3.exceptions import InsecureRequestWarning
    urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    requests = None
    HAS_REQUESTS = False

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    dns = None
    HAS_DNS = False

try:
    import pymongo
    HAS_MONGODB = True
except ImportError:
    pymongo = None
    HAS_MONGODB = False

try:
    import pymysql
    HAS_MYSQL = True
except ImportError:
    pymysql = None
    HAS_MYSQL = False

try:
    import redis
    HAS_REDIS = True
except ImportError:
    redis = None
    HAS_REDIS = False

try:
    import elasticsearch
    HAS_ELASTICSEARCH = True
except ImportError:
    elasticsearch = None
    HAS_ELASTICSEARCH = False

try:
    import pymemcache.client.base
    HAS_MEMCACHED = True
except ImportError:
    pymemcache = None
    HAS_MEMCACHED = False

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('pentora.network_scanner')

# Common ports and services dictionary
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB"
}

class NetworkScanner:
    """
    A comprehensive network scanner for detecting various vulnerabilities.
    
    The scanner can detect the following vulnerabilities:
    1. Open Ports: Scans for open ports on the target system and identifies the running services.
    2. Default Credentials: Checks common services for potential default credential usage.
    3. Denial of Service (DoS): Identifies services that might be vulnerable to DoS attacks.
    4. HTTP Directory Listing: Detects web servers with directory listing enabled.
    5. Exposed Services with No Authentication: Identifies services that may be running without proper authentication.
    """
    def __init__(self, status_callback=None):
        """
        Initialize the network scanner.
        
        Args:
            status_callback: Optional callback function to report status updates
        """
        self.target = None
        self.port_range = "1-1000"  # Default port range
        self.output_dir = None
        self.report_format = "html"
        self.enabled_modules = ["open_ports"]  # Default module
        self.status_callback = status_callback
        self.scan_result = None
        self.vulnerabilities = []
        self.findings = []
        self.scan_start_time = None
        self.scan_end_time = None
        self.timeout = 5  # Default timeout in seconds
        self.max_threads = 50  # Default max threads for parallel scanning
        self.verbose = False  # Verbose output flag
        
        # Set default credentials for testing
        self.default_credentials = {
            "ftp": [("anonymous", ""), ("admin", "admin"), ("ftp", "ftp")],
            "ssh": [("root", "root"), ("admin", "admin"), ("user", "password")],
            "telnet": [("admin", "admin"), ("root", "root"), ("user", "password")],
            "mysql": [("root", ""), ("root", "root"), ("admin", "admin")],
            "mongodb": [("admin", "admin"), ("root", "root")],
            "redis": [("", "")],  # Redis typically doesn't use username
            "elasticsearch": [("elastic", "changeme")],
            "http": [("admin", "admin"), ("user", "password"), ("root", "root")]
        }
        
        # Initialize vulnerability database
        self.vulnerability_db = {
            "open_ports": [],
            "default_credentials": [],
            "dos_vulnerabilities": [],
            "directory_listing": [],
            "no_auth_services": [],
            "service_vulnerabilities": []
        }
        
    def set_target(self, target):
        """
        Set the target for scanning.
        
        Args:
            target: Target IP, hostname, or network range (e.g., 192.168.1.1/24)
        """
        self.target = target
        if self.status_callback:
            self.status_callback(f"Target set to {target}")
            
    def set_ports(self, ports):
        """
        Set the port range to scan.
        
        Args:
            ports: Port range (e.g., "1-1000", "22,80,443")
        """
        self.port_range = ports
        if self.status_callback:
            self.status_callback(f"Port range set to {ports}")
            
    def set_output_dir(self, output_dir):
        """
        Set the output directory for reports.
        
        Args:
            output_dir: Directory to save reports
        """
        self.output_dir = output_dir
        # Create the directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        if self.status_callback:
            self.status_callback(f"Output directory set to {output_dir}")
            
    def set_report_format(self, report_format):
        """
        Set the report format.
        
        Args:
            report_format: Format of the report (html, json)
        """
        if report_format not in ["html", "json"]:
            report_format = "html"  # Default to HTML if invalid format
        self.report_format = report_format
        if self.status_callback:
            self.status_callback(f"Report format set to {report_format}")
            
    def enable_modules(self, modules):
        """
        Enable specific scanning modules.
        
        Args:
            modules: List of module names to enable
        """
        valid_modules = ["open_ports", "default_credentials", "dos_vulnerabilities", 
                         "directory_listing", "no_auth_services", "service_vulnerabilities", "all"]
        
        if "all" in modules:
            self.enabled_modules = valid_modules[:-1]  # All except 'all' itself
        else:
            self.enabled_modules = [m for m in modules if m in valid_modules]
            
        if not self.enabled_modules:
            self.enabled_modules = ["open_ports"]  # Default to basic port scan
            
        if self.status_callback:
            self.status_callback(f"Enabled modules: {', '.join(self.enabled_modules)}")
            
    def set_enabled_modules(self, modules):
        """
        Alias for enable_modules for backward compatibility.
        
        Args:
            modules: List of module names to enable
        """
        self.enable_modules(modules)
        
    def get_available_modules(self):
        """Get a list of available modules for network scanning."""
        modules = [
            {
                "name": "open_ports",
                "description": "Detects open ports and identifies running services"
            },
            {
                "name": "default_credentials",
                "description": "Checks for default credentials on common services"
            },
            {
                "name": "dos_vulnerabilities",
                "description": "Identifies services vulnerable to Denial of Service attacks"
            },
            {
                "name": "directory_listing",
                "description": "Detects web servers with directory listing enabled"
            },
            {
                "name": "no_auth_services",
                "description": "Identifies services with no authentication required"
            },
            {
                "name": "service_vulnerabilities",
                "description": "Checks for known vulnerabilities in detected services"
            }
        ]
        return modules
        
    def scan(self, target=None, output_dir=None, report_format=None):
        """
        Perform a network vulnerability scan.
        
        Args:
            target: Target IP or network range (e.g., 192.168.1.1/24)
            output_dir: Directory to save the report
            report_format: Format of the report (html, json)
            
        Returns:
            Path to the generated report
        """
        if target:
            self.target = target
        if output_dir:
            self.output_dir = output_dir
        if report_format:
            self.report_format = report_format
            
        if not self.target:
            if self.status_callback:
                self.status_callback("No target specified. Please set a target using set_target() or provide one to the scan method.")
            return None
            
        if not self.output_dir:
            self.output_dir = os.path.join(os.getcwd(), "pentora_reports")
            os.makedirs(self.output_dir, exist_ok=True)
            
        # Reset previous scan results
        self.vulnerabilities = []
        self.findings = []
        self.vulnerability_db = {
            "open_ports": [],
            "default_credentials": [],
            "dos_vulnerabilities": [],
            "directory_listing": [],
            "no_auth_services": [],
            "service_vulnerabilities": []
        }
        
        # Record scan start time
        self.scan_start_time = time.time()
        
        # Log scan start
        logger.info(f"Starting scan of {self.target} with modules: {', '.join(self.enabled_modules)}")
        if self.status_callback:
            self.status_callback(f"Starting scan of {self.target} with modules: {', '.join(self.enabled_modules)}")
            
        # Run the scan
        self.run_scan()
        
        # Generate the report
        if self.output_dir:
            # Create the output directory if it doesn't exist
            Path(self.output_dir).mkdir(parents=True, exist_ok=True)
            
            # Generate a timestamp for the report filename
            timestamp = dt.now().strftime("%Y%m%d_%H%M%S")
            
            # Generate the report filename
            if '/' in self.target:
                target_str = self.target.replace('/', '_')
            else:
                target_str = self.target
                
            report_filename = f"network_scan_{target_str}_{timestamp}.{self.report_format}"
            report_path = str(Path(self.output_dir) / report_filename)
            
            # Write the report
            with open(report_path, 'w', encoding='utf-8') as f:
                if self.report_format == 'json':
                    json.dump(self.get_findings(), f, indent=4)
                elif self.report_format == 'html':
                    f.write(self._generate_html_report())
                    
            if self.status_callback:
                self.status_callback("<font color='#00CC00'>Report saved to {0}</font>".format(report_path))
                
            return report_path
        return None
        
    def run_scan(self):
        """
        Run the network scan with the configured settings.
        
        Returns:
            Dictionary with scan results and vulnerabilities
        """
        if not self.target:
            if self.status_callback:
                self.status_callback("Error: No target specified")
            return {"error": "No target specified"}
            
        try:
            self.vulnerabilities = []
            self.findings = []
            
            # Update status
            if self.status_callback:
                self.status_callback(f"<font color='#FF6600'>Starting network scan on {self.target}...</font>")
                
            # Run the enabled modules
            if "open_ports" in self.enabled_modules:
                if self.status_callback:
                    self.status_callback("<font color='#FF6600'>🚀 Launching port scan module...</font>")
                self._run_port_scan()
                
            if "default_credentials" in self.enabled_modules:
                if self.status_callback:
                    self.status_callback("<font color='#FF6600'>🔑 Launching default credentials check module...</font>")
                self._check_default_credentials()
                
            if "dos_vulnerabilities" in self.enabled_modules:
                if self.status_callback:
                    self.status_callback("<font color='#FF6600'>🚀 Launching DoS vulnerabilities check module...</font>")
                self._check_dos_vulnerabilities()
                
            if "directory_listing" in self.enabled_modules:
                if self.status_callback:
                    self.status_callback("<font color='#FF6600'>🚀 Launching directory listing check module...</font>")
                self._check_directory_listing()
                
            if "no_auth_services" in self.enabled_modules:
                if self.status_callback:
                    self.status_callback("🚀 Launching no authentication services check module...")
                self._check_no_auth_services()
                
            if "service_vulnerabilities" in self.enabled_modules:
                # The service_vulnerabilities check is now integrated into _run_port_scan via nmap script parsing
                # if self.status_callback:
                #     self.status_callback("<font color='#FF6600'>🔍 Launching service vulnerabilities check module...</font>")
                # self._check_service_vulnerabilities() # Removed call
                
            # Check for service vulnerabilities (Now handled within _run_port_scan)
            # The nmap script results are added to self.vulnerabilities with module='service_vulnerabilities' inside _run_port_scan
             if self.open_ports and "service_vulnerabilities" in self.enabled_modules: # Keep condition for summary reporting
                if self.status_callback:
                    self.status_callback("<font color='#3366FF'>🔍 Checking for service vulnerabilities...</font>")
                
                vuln_count = 0
                for port_info in self.open_ports:
                    # Check for vulnerabilities based on service and version
                    service_vulns = self._check_service_vulnerabilities(port_info)
                    
                    if service_vulns:
                        vuln_count += len(service_vulns)
                        for vuln in service_vulns:
                            self.vulnerabilities.append(vuln)
                            self.findings.append(f"Vulnerability found: {vuln['name']} - {vuln['description']}")
                            
                            if self.status_callback:
                                severity_color = "#FF0000" if vuln['severity'] == "Critical" else "#FF9900" if vuln['severity'] == "High" else "#FFCC00" if vuln['severity'] == "Medium" else "#3366FF"
                                self.status_callback(f"<font color='{severity_color}'>⚠️ {vuln['severity']} vulnerability: {vuln['name']} - {vuln['description']}</font>")
                
                if self.status_callback:
                    self.status_callback(f"<font color='#00CC00'>✅ Service vulnerability check complete. Found {vuln_count} vulnerabilities.</font>")
            
            # Run other enabled modules
            for module in self.enabled_modules:
                if module == "open_ports" or module == "service_vulnerabilities":
                    # Already handled above
                    continue
                    
                # Add other module implementations here
                if self.status_callback:
                    self.status_callback(f"Running module: {module}")
                    
                # Example: if module == "some_other_module":
                #     self._run_some_other_module()
            
            # Prepare results
            results = {
                "target": self.target,
                "scan_time": dt.now().isoformat(),
                "enabled_modules": self.enabled_modules,
                "vulnerabilities": self.vulnerabilities,
                "report_path": None
            }
            
            return results
            
        except Exception as e:
            error_msg = f"Error during scan: {str(e)}"
            logging.error(error_msg)
            logging.debug(traceback.format_exc())
            if self.status_callback:
                self.status_callback(error_msg)
            return {"error": error_msg}
            
    def _run_port_scan(self):
        """Run a port scan on the target."""
        if self.status_callback:
            self.status_callback("Running port scan...")
            
        target_ip = self.target
        if "://" in target_ip:
            target_ip = target_ip.split("://")[1].split("/")[0].split(":")[0]
            
        try:
            target_ip = socket.gethostbyname(target_ip)
            if self.status_callback:
                self.status_callback(f"Resolved {self.target} to {target_ip}")
        except:
            # If we can't resolve it, just use the original
            pass
            
        # Initialize results
        self.open_ports = []
        
        # Check if nmap is available
        use_nmap = False
        try:
            # First check if nmap is in PATH
            import subprocess
            try:
                # Run nmap version check
                subprocess.run(["nmap", "-V"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=2)
                
                # If we get here, nmap is installed and in PATH
                if self.status_callback:
                    self.status_callback(f"<font color='#00CC00'>✅ Nmap detected in system PATH</font>")
                
                # Now check if python-nmap is available
                import nmap
                nm = nmap.PortScanner()
                use_nmap = True
                if self.status_callback:
                    self.status_callback(f"<font color='#00CC00'>✅ Using python-nmap for scanning. This will provide better results.</font>")
            except (subprocess.SubprocessError, FileNotFoundError):
                if self.status_callback:
                    self.status_callback("<font color='#FF9900'>⚠️ Nmap executable not found in PATH. Make sure it's installed and in your system PATH.</font>")
                raise ImportError("Nmap executable not found")
        except ImportError as e:
            if self.status_callback:
                self.status_callback(f"<font color='#FF9900'>⚠️ Warning: {str(e)}. Falling back to socket-based scanning.</font>")
                self.status_callback("<font color='#FF9900'>ℹ️ Install python-nmap for better results: pip install python-nmap</font>")
        
        # Parse port range
        try:
            if "-" in self.port_range:
                # Range of ports
                start_port, end_port = map(int, self.port_range.split("-"))
                ports_to_scan = range(start_port, end_port + 1)
            else:
                try:
                    # Single port
                    int(self.port_range)
                    ports_to_scan = [int(self.port_range)]
                except ValueError:
                    # Invalid port specification, use default
                    ports_to_scan = range(1, 1001)  # Default to 1-1000
                    if self.status_callback:
                        self.status_callback(f"<font color='#FF9900'>Warning: Invalid port specification. Using default range 1-1000.</font>")
        except:
            # Default to common ports if there's any issue
            ports_to_scan = range(1, 1001)
            if self.status_callback:
                self.status_callback("<font color='#FF9900'>Warning: Error parsing port range. Using default range 1-1000.</font>")
        
        if use_nmap:
            # Use nmap for scanning
            if self.status_callback:
                self.status_callback(f"<font color='#3366FF'>🔍 Starting nmap scan on {target_ip} with port range {self.port_range}...</font>")
            
            try:
                # Convert ports_to_scan to a string format that nmap expects
                if isinstance(ports_to_scan, range):
                    ports_str = f"{ports_to_scan.start}-{ports_to_scan.stop-1}"
                else:
                    ports_str = ",".join(map(str, ports_to_scan))
                
                # Construct the nmap command
                nmap_command = [
                    "nmap",
                    "-sS",  # SYN Scan (requires privileges) - Consider -sT if issues arise
                    "-sV",  # Version Detection
                    "-v",   # Verbose output for real-time progress
                    "-T4",  # Aggressive timing
                    "--script=default,safe,vuln", # Run vulnerability scripts
                    "--min-rate", "5000", # Fast scan rate
                    "--max-retries", "1", # Fewer retries
                    "-p", ports_str, # Port range
                    target_ip
                ]

                if self.status_callback:
                    self.status_callback(f"<font color='#999999'>Debug: Running nmap command: {' '.join(nmap_command)}</font>")
                    self.status_callback("<font color='#3366FF'>ℹ️ Nmap scan started. Reading output in real-time...</font>")

                # Run nmap using subprocess and capture output line by line
                process = subprocess.Popen(nmap_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace')

                current_port = None
                current_service = "unknown"
                current_product = ""
                current_version = ""

                # Process nmap output line by line
                for line in iter(process.stdout.readline, ''):
                    line = line.strip()
                    if not line:
                        continue

                    # --- Real-time Logging ---
                    # Log most lines, potentially filtering less important ones if too noisy
                    if self.verbose or "Nmap scan report for" in line or "Discovered open port" in line or "PORT" in line or "|" in line or "Host is up" in line:
                         if self.status_callback:
                             # Simple HTML escaping for safety
                             log_line = line.replace("&", "&").replace("<", "<").replace(">", ">")
                             # Color coding based on keywords
                             color = "#999999" # Default grey for debug/info
                             if "Discovered open port" in line or "/tcp" in line and " open " in line:
                                 color = "#00CC00" # Green for open ports
                             elif "VULNERABLE" in line or "State: VULNERABLE" in line:
                                 color = "#FF0000" # Red for vulnerable scripts
                             elif "WARNING" in line:
                                 color = "#FF9900" # Orange for warnings
                             elif line.startswith("|") or line.startswith("|_"): # Script output
                                 color = "#6699FF" # Blue for script details

                             self.status_callback(f"<font color='{color}'>Nmap: {log_line}</font>")
                    # --- End Real-time Logging ---


                    # --- Parsing Logic ---
                    # Example parsing (needs refinement based on actual nmap -v output)
                    if "Discovered open port" in line or ("/tcp" in line and " open " in line):
                        parts = line.split()
                        try:
                            port_protocol = parts[0] # e.g., 80/tcp
                            port = int(port_protocol.split('/')[0])
                            state = parts[1] # e.g., open
                            service = parts[2] # e.g., http

                            if state == 'open':
                                current_port = port
                                current_service = service
                                current_product = "" # Reset product/version for new port
                                current_version = ""

                                # Try to extract version info if available on the same line
                                if len(parts) > 3:
                                     version_info_str = " ".join(parts[3:])
                                     # Basic parsing - nmap version output can be complex
                                     # This is a simplified approach
                                     current_product = version_info_str.split(" ")[0] if version_info_str else ""
                                     current_version = " ".join(version_info_str.split(" ")[1:]) if len(version_info_str.split(" ")) > 1 else ""


                                # Add initial open port info (might be updated by script results)
                                port_data = {
                                    'ip': target_ip,
                                    'port': current_port,
                                    'service': current_service,
                                    'product': current_product,
                                    'version': current_version
                                }
                                # Avoid duplicates if already added
                                if not any(p['port'] == current_port for p in self.open_ports):
                                    self.open_ports.append(port_data)
                                    self.findings.append(f"Open port {current_port}: {current_service} {current_product} {current_version}".strip())
                                    self.vulnerabilities.append({
                                        "id": f"OPEN-PORT-{current_port}",
                                        "name": f"Open Port {current_port}/{current_service}",
                                        "description": f"Port {current_port} is open and running {current_service} {current_product} {current_version}".strip(),
                                        "severity": "Info",
                                        "ip": target_ip,
                                        "port": current_port,
                                        "service": current_service,
                                        "product": current_product,
                                        "version": current_version,
                                        "module": "open_ports"
                                    })

                        except (IndexError, ValueError):
                            # Ignore lines that don't match the expected format
                            pass

                    # Parse script output (lines starting with | or \_)
                    elif (line.startswith("|") or line.startswith("\\_")) and current_port is not None:
                        script_line = line.strip()
                        # Attempt to identify script name and output
                        script_id = "unknown_script"
                        script_output = script_line
                        if ":" in script_line:
                            parts = script_line.split(":", 1)
                            script_id = parts[0].strip("|\\_ ")
                            script_output = parts[1].strip()

                        # Filter for scripts that likely indicate a vulnerability
                        is_vuln_script = 'vuln' in script_id or 'exploit' in script_id
                        is_finding = any(kw in script_output.lower() for kw in ['vulnerable', 'risk factor:', 'state:'])

                        if is_vuln_script or is_finding:
                             # Try to determine severity (heuristic)
                             severity = "Info"
                             if "critical" in script_output.lower() or "high" in script_output.lower():
                                 severity = "High"
                             elif "medium" in script_output.lower():
                                 severity = "Medium"
                             elif "low" in script_output.lower():
                                 severity = "Low"

                             description = f"Nmap script '{script_id}' output: {script_output}"

                             # Add finding and vulnerability
                             finding_text = f"Nmap script '{script_id}' finding on {target_ip}:{current_port}: {script_output}"
                             if finding_text not in self.findings: # Avoid duplicates
                                 self.findings.append(finding_text)
                                 self.vulnerabilities.append({
                                     "id": f"NMAP-{script_id.upper()}-{current_port}", # Make ID more unique
                                     "name": f"Nmap Script Finding: {script_id}",
                                     "description": description,
                                     "severity": severity,
                                     "ip": target_ip,
                                     "port": current_port,
                                     "service": current_service, # Use last known service for this port
                                     "product": current_product,
                                     "version": current_version,
                                     "module": "service_vulnerabilities",
                                     "details": script_output
                                 })

                    # Reset current_port if we encounter a line indicating a move away from port details
                    elif line.startswith("Service detection performed.") or line.startswith("Nmap scan report for"):
                         current_port = None
                         current_service = "unknown"
                         current_product = ""
                         current_version = ""
                    # --- End Parsing Logic ---


                # Wait for the process to finish and get the return code
                process.stdout.close()
                return_code = process.wait()

                if return_code != 0:
                    if self.status_callback:
                        self.status_callback(f"<font color='#FF9900'>⚠️ Nmap process finished with non-zero exit code: {return_code}. Results might be incomplete.</font>")

                # Summary after nmap finishes
                if self.status_callback:
                    self.status_callback(f"<font color='#00CC00'>✅ Nmap scan finished. Found {len(self.open_ports)} open ports.</font>")


                # --- This block replaces the original python-nmap result processing ---
                # The parsing logic above should populate self.open_ports and self.vulnerabilities directly.
                # We no longer need to iterate through nm[target_ip]['tcp'] etc.

                # Debug output (optional)
                # if self.verbose and self.status_callback:
                    # The subprocess approach handles the scan directly.
                    # If the subprocess fails initially (e.g., nmap not found), the exception handling below will trigger the fallback.
                    pass # Placeholder, the code above replaces the python-nmap block

            except FileNotFoundError:
                 if self.status_callback:
                    self.status_callback("<font color='#FF0000'>❌ Error: 'nmap' command not found. Make sure Nmap is installed and in your system's PATH.</font>")
                    self.status_callback("<font color='#FF9900'>⚠️ Falling back to socket-based scanning.</font>")
                 use_nmap = False # Fallback needed
            except Exception as e:
                 if self.status_callback:
                    self.status_callback(f"<font color='#FF0000'>❌ Error running nmap via subprocess: {str(e)}</font>")
                    self.status_callback("<font color='#FF9900'>⚠️ Falling back to socket-based scanning.</font>")
                 use_nmap = False # Fallback needed

        if not use_nmap:
            # Use socket-based scanning as fallback
            if self.status_callback:
                self.status_callback("<font color='#3366FF'>🔍 Starting socket-based port scan...</font>")
            
            # Create a thread pool
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                # Submit all port scanning tasks
                future_to_port = {executor.submit(self._check_port, target_ip, port): port for port in ports_to_scan}
                
                # Process results as they complete
                for future in concurrent.futures.as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        is_open, service = future.result()
                        if is_open:
                            if self.status_callback:
                                self.status_callback(f"<font color='#00CC00'>✅ Port {port} is open: {service}</font>")
                            
                            # Add to open ports list
                            self.open_ports.append({
                                'ip': target_ip,
                                'port': port,
                                'service': service,
                                'product': '',
                                'version': ''
                            })
                            
                            # Add to findings
                            self.findings.append(f"Open port {port}: {service}")
                            
                            # Add to vulnerabilities for consistency
                            self.vulnerabilities.append({
                                "id": f"OPEN-PORT-{port}",
                                "name": f"Open Port {port}/{service}",
                                "description": f"Port {port} is open and running {service}",
                                "severity": "Info",
                                "ip": target_ip,
                                "port": port,
                                "service": service,
                                "product": "",
                                "version": "",
                                "module": "open_ports"
                            })
                    except Exception as e:
                        if self.verbose and self.status_callback:
                            self.status_callback(f"<font color='#999999'>Error checking port {port}: {str(e)}</font>")
            
            # Summary
            if self.status_callback:
                self.status_callback(f"<font color='#00CC00'>✅ Port scan complete. Found {len(self.open_ports)} open ports.</font>")
    
    def _check_port(self, ip, port):
        """Check if a specific port is open using sockets."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Quick timeout for faster scanning
        result = sock.connect_ex((ip, port))
        sock.close()
        
        is_open = (result == 0)
        service = COMMON_PORTS.get(port, "unknown")
        
        return is_open, service

    def _check_default_credentials(self):
        """Check for default credentials on common services."""
        if self.status_callback:
            self.status_callback("<font color='#FF6600'>Checking for default credentials on detected services...</font>")
        
        # Skip if no open ports were found
        if not hasattr(self, 'open_ports') or not self.open_ports:
            if self.status_callback:
                self.status_callback("<font color='#FF9900'>No open ports found, skipping default credentials check.</font>")
            return
        
        # Common default credentials for various services
        default_creds = {
            'ftp': [
                {'username': 'anonymous', 'password': ''},
                {'username': 'anonymous', 'password': 'anonymous'},
                {'username': 'anonymous', 'password': 'test'},
                {'username': 'ftp', 'password': 'ftp'},
                {'username': 'user', 'password': 'user'},
                {'username': 'admin', 'password': 'admin'},
                {'username': 'admin', 'password': 'password'},
                {'username': 'test', 'password': 'test'}
            ],
            'ssh': [
                {'username': 'root', 'password': 'root'},
                {'username': 'root', 'password': 'password'},
                {'username': 'root', 'password': 'admin'},
                {'username': 'root', 'password': 'toor'},
                {'username': 'admin', 'password': 'admin'},
                {'username': 'admin', 'password': 'password'},
                {'username': 'user', 'password': 'user'},
                {'username': 'user', 'password': 'password'},
                {'username': 'test', 'password': 'test'},
                {'username': 'ubuntu', 'password': 'ubuntu'},
                {'username': 'pi', 'password': 'raspberry'}
            ],
            'telnet': [
                {'username': 'root', 'password': 'root'},
                {'username': 'root', 'password': ''},
                {'username': 'root', 'password': 'password'},
                {'username': 'root', 'password': 'admin'},
                {'username': 'root', 'password': 'toor'},
                {'username': 'admin', 'password': 'admin'},
                {'username': 'admin', 'password': ''},
                {'username': 'admin', 'password': 'password'},
                {'username': 'user', 'password': 'user'},
                {'username': 'user', 'password': 'password'},
                {'username': 'guest', 'password': 'guest'},
                {'username': 'test', 'password': 'test'}
            ],
            'http': [  # For basic auth
                {'username': 'admin', 'password': 'admin'},
                {'username': 'admin', 'password': 'password'},
                {'username': 'admin', 'password': ''},
                {'username': 'root', 'password': 'root'},
                {'username': 'root', 'password': 'password'},
                {'username': 'user', 'password': 'user'},
                {'username': 'guest', 'password': 'guest'},
                {'username': 'test', 'password': 'test'}
            ],
            'mysql': [
                {'username': 'root', 'password': ''},
                {'username': 'root', 'password': 'root'},
                {'username': 'root', 'password': 'password'},
                {'username': 'admin', 'password': 'admin'},
                {'username': 'mysql', 'password': 'mysql'},
                {'username': 'test', 'password': 'test'}
            ],
            'postgresql': [
                {'username': 'postgres', 'password': 'postgres'},
                {'username': 'postgres', 'password': ''},
                {'username': 'admin', 'password': 'admin'}
            ],
            'vnc': [
                {'username': '', 'password': ''},
                {'username': 'admin', 'password': 'admin'},
                {'username': 'root', 'password': 'password'}
            ],
            'rdp': [
                {'username': 'administrator', 'password': 'administrator'},
                {'username': 'admin', 'password': 'admin'},
                {'username': 'user', 'password': 'password'}
            ]
        }
        
        # Check each open port for default credentials
        for port_info in self.open_ports:
            service = port_info.get('service', '').lower()
            port = port_info.get('port')
            ip = port_info.get('ip')
            
            if not service or service == 'unknown':
                continue
                
            # Map service to credential check type
            check_type = None
            if service in ('ftp', 'ssh', 'telnet', 'mysql', 'postgresql'):
                check_type = service
            elif service in ('http', 'https'):
                check_type = 'http'
            elif service == 'ms-wbt-server' or port == 3389:
                check_type = 'rdp'
            elif service == 'vnc' or port == 5900:
                check_type = 'vnc'
            
            if check_type and check_type in default_creds:
                if self.status_callback:
                    self.status_callback(f"<font color='#3366FF'>🔍 Checking default credentials for {service} on {ip}:{port}...</font>")
                
                # Try each set of credentials
                for creds in default_creds[check_type]:
                    username = creds['username']
                    password = creds['password']
                    
                    # Skip if stop requested
                    if hasattr(self, 'stop_requested') and self.stop_requested:
                        return
                    
                    # Attempt to authenticate
                    auth_success = False
                    try:
                        if check_type == 'ftp':
                            auth_success = self._check_ftp_auth(ip, port, username, password)
                        elif check_type == 'ssh':
                            auth_success = self._check_ssh_auth(ip, port, username, password)
                        elif check_type == 'telnet':
                            auth_success = self._check_telnet_auth(ip, port, username, password)
                        elif check_type == 'http':
                            auth_success = self._check_http_basic_auth(ip, port, username, password, service == 'https')
                        elif check_type == 'mysql':
                            auth_success = self._check_mysql_auth(ip, port, username, password)
                        # TODO: Add checks for other services like PostgreSQL, VNC, RDP if libraries are available
                        
                        if auth_success:
                            # Record the vulnerability
                            vuln = {
                                "id": "DEFAULT-CREDS",
                                "name": f"Default Credentials on {service.upper()}",
                                "description": f"Default credentials ({username}:{password}) work on {service} service",
                                "severity": "High",
                                "cvss_score": 7.5,
                                "remediation": "Change default credentials and implement strong password policy",
                                "references": ["https://www.owasp.org/index.php/Testing_for_Default_Credentials_(OTG-AUTHN-002)"],
                                "ip": ip,
                                "port": port,
                                "service": service,
                                "username": username,
                                "password": password,
                                "module": "default_credentials"
                            }
                            
                            self.vulnerabilities.append(vuln)
                            
                            # Add to findings
                            finding_text = f"Default credentials ({username}:{password}) found on {ip}:{port} - {service}"
                            self.findings.append(finding_text)
                            
                            if self.status_callback:
                                self.status_callback(f"<font color='#FF0000'>⚠️ {finding_text}</font>")
                            
                            # No need to try other credentials for this service
                            break
                    except Exception as e:
                        if self.verbose:
                            if self.status_callback:
                                self.status_callback(f"<font color='#999999'>Error checking {service} auth on {ip}:{port}: {str(e)}</font>")
        
        # Summary
        if self.status_callback:
            vuln_count = sum(1 for v in self.vulnerabilities if v.get('module') == 'default_credentials')
            if vuln_count > 0:
                self.status_callback(f"<font color='#FF6600'>Default credentials check complete. Found {vuln_count} services with default credentials.</font>")
            else:
                self.status_callback("<font color='#00CC00'>Default credentials check complete. No default credentials found.</font>")
    
    def _check_ftp_auth(self, ip, port, username, password):
        """Check if FTP credentials work."""
        try:
            import ftplib
            ftp = ftplib.FTP()
            ftp.connect(ip, port, timeout=self.timeout)
            ftp.login(username, password)
            ftp.quit()
            return True
        except:
            return False
    
    def _check_ssh_auth(self, ip, port, username, password):
        """Check if SSH credentials work."""
        try:
            import paramiko
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, port=port, username=username, password=password, timeout=self.timeout)
            ssh.close()
            return True
        except:
            return False
    
    def _check_http_basic_auth(self, ip, port, username, password, use_https=False):
        """Check if HTTP Basic Auth credentials work."""
        try:
            import requests
            from requests.auth import HTTPBasicAuth
            from requests.packages.urllib3.exceptions import InsecureRequestWarning # type: ignore
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            
            protocol = 'https' if use_https else 'http'
            url = f"{protocol}://{ip}:{port}/"
            
            response = requests.get(
                url, 
                auth=HTTPBasicAuth(username, password),
                timeout=self.timeout,
                verify=False
            )
            
            # If we get a 200 OK and not a 401 Unauthorized, credentials likely worked
            return response.status_code == 200
        except:
            return False

    def _check_telnet_auth(self, ip, port, username, password):
        """Check if Telnet credentials work."""
        try:
            import telnetlib
            tn = telnetlib.Telnet(ip, port, timeout=self.timeout)
            
            # Wait for login prompt (adjust patterns as needed)
            tn.read_until(b"login: ", timeout=2)
            tn.write(username.encode('ascii') + b"\n")
            
            # Wait for password prompt
            tn.read_until(b"Password: ", timeout=2)
            tn.write(password.encode('ascii') + b"\n")
            
            # Check for successful login indicator (e.g., shell prompt like $, #, >)
            # This is highly dependent on the target system
            index, _, _ = tn.expect([b"#", b"$", b">", b"Login incorrect"], timeout=3)
            
            tn.close()
            
            # If index is 0, 1, or 2, it's likely a successful login prompt
            # If index is 3, it's "Login incorrect"
            # If index is -1, it timed out or didn't match
            return index in [0, 1, 2]
            
        except:
            # Any exception likely means failure (connection refused, timeout, etc.)
            return False
            
    def _check_mysql_auth(self, ip, port, username, password):
        """Check if MySQL credentials work."""
        try:
            import pymysql
            connection = pymysql.connect(
                host=ip,
                port=port,
                user=username,
                password=password,
                connect_timeout=self.timeout
            )
            connection.close()
            return True
        except:
            return False

    def _check_directory_listing(self):
        """Check for web servers with directory listing enabled."""
        if self.status_callback:
            self.status_callback("<font color='#FF6600'>Checking for directory listing...</font>")
            
        # Perform network-wide checks for directory listing
        if self.status_callback:
            self.status_callback("<font color='#FF6600'>📂 Performing network-wide directory listing checks...</font>")
            
        target_ip = self.target
        if "://" in target_ip:
            target_ip = target_ip.split("://")[1].split("/")[0].split(":")[0]
            
        try:
            target_ip = socket.gethostbyname(target_ip)
        except:
            # If we can't resolve it, just use the original
            pass
            
        # Common web server ports
        web_ports = [80, 443, 8080, 8443, 8000, 8008, 8888, 8081]
        
        # Expanded directory and common file paths to check
        directories_and_files = [
            '/',
            '/images/', '/img/', '/pics/',
            '/static/', '/assets/', '/includes/', '/inc/',
            '/uploads/', '/files/', '/download/', '/downloads/',
            '/data/', '/db/',
            '/backup/', '/bak/', '/old/',
            '/temp/', '/tmp/',
            '/css/', '/js/', '/scripts/', '/lib/', '/libs/',
            '/admin/', '/administrator/', '/login/', '/user/', '/users/',
            '/config/', '/conf/', '/etc/',
            '/logs/', '/log/',
            '/cgi-bin/',
            '/vendor/', # Common in PHP projects
            '/node_modules/', # Common in Node.js projects
            '/.git/', '/.svn/', '/.hg/', # Version control metadata
            '/.env', '/config.js', '/settings.py', '/wp-config.php', # Common config files
            '/robots.txt', '/sitemap.xml',
            '/backup.zip', '/backup.tar.gz', '/db.sql', # Common backup files
            '/error_log', '/access_log', # Common log files
        ]
        
        # Expanded patterns that indicate directory listing
        dir_listing_patterns = [
            '<title>Index of /',
            'Directory Listing for',
            '<h1>Index of /',
            'Parent Directory</a>',
            '- Directory listing for',
            'Directory: /',
            '<h2>Directory listing for',
            '<title>Listing of /',
            'Directory List /',
            'listing directory /',
            '<pre><a href="?C=N;O=D">Name</a>', # Apache detailed listing
            'folder.gif' # Common icon in listings
        ]
        
        # Files that indicate sensitive info exposure if directly accessible
        sensitive_files_to_check = [
             '.env', '.env.bak', '.env.save', '.env.old',
             'config.json', 'config.yaml', 'config.yml', 'settings.py', 'settings.local.py',
             'wp-config.php', 'wp-config.php.bak', 'configuration.php',
             'web.config',
             'id_rsa', 'id_dsa', '.ssh/id_rsa', # Private keys
             '.bash_history', '.history',
             'access.log', 'error.log', 'app.log',
             'backup.sql', 'database.sql', 'dump.sql',
             '.git/config', '.svn/wc.db'
        ]

        found_listing_urls = set() # Keep track of URLs confirmed to have listing

        for port in web_ports:
            protocols = ['http']
            if port in [443, 8443]: # Add other potential HTTPS ports if needed
                protocols.append('https') # Test both http and https for these ports

            for protocol in protocols:
                for path_item in directories_and_files:
                    # Skip HTTPS test if SSL context fails or cert is invalid? Maybe not for scanning.
                    # Consider adding SSL context handling if needed: ssl._create_unverified_context()

                    try:
                        # Ensure path starts with / if it's a directory-like path
                        if not path_item.startswith('/') and path_item.endswith('/'):
                             path_item = '/' + path_item
                        elif not path_item.startswith('/'):
                             # Assume it might be a file in the root if no leading /
                             path_item = '/' + path_item

                        url = f"{protocol}://{target_ip}:{port}{path_item}"
                        
                        if self.status_callback:
                            self.status_callback(f"    <font color='#999999'>ℹ️ Testing {url} for listing/access...</font>")
                        
                        # Try to access the path
                        request = urllib.request.Request(url, method='GET') # Explicitly GET
                        request.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36') # More common UA
                        
                        # Handle potential SSL errors for HTTPS
                        context = ssl._create_unverified_context() if protocol == 'https' else None

                        try:
                            with urllib.request.urlopen(request, timeout=self.timeout, context=context) as response:
                                if response.getcode() == 200:
                                    # Read only a portion initially to check for listing patterns
                                    content_sample = response.read(10240).decode('utf-8', errors='ignore') # Read first 10KB
                                    
                                    is_listing = any(pattern in content_sample for pattern in dir_listing_patterns)
                                    
                                    if is_listing:
                                        if url not in found_listing_urls:
                                            if self.status_callback:
                                                self.status_callback(f"    <font color='#FF9900'>⚠️ Potential Directory Listing found at {url}</font>")
                                            
                                            self.findings.append(f"Potential Directory Listing enabled at {url}")
                                            self.vulnerabilities.append({
                                                "name": "Potential Directory Listing Enabled",
                                                "description": f"Directory listing seems enabled at {url}. Manual verification recommended.",
                                                "severity": "Medium",
                                                "ip": target_ip,
                                                "port": port,
                                                "url": url,
                                                "module": "directory_listing"
                                            })
                                            found_listing_urls.add(url)

                                            # If listing found, try accessing sensitive files within that dir
                                            if path_item.endswith('/'): # Only if it's a directory path
                                                for sensitive_file in sensitive_files_to_check:
                                                    sensitive_url = url.rstrip('/') + '/' + sensitive_file.lstrip('/')
                                                    self._check_sensitive_file_access(sensitive_url, target_ip, port, context)

                                    # Check if the accessed path itself is a sensitive file
                                    elif any(path_item.endswith(sf) for sf in sensitive_files_to_check):
                                         if self.status_callback:
                                            self.status_callback(f"    <font color='#FF0000'>⚠️ Sensitive File Accessible: {url}</font>")
                                         self.findings.append(f"Sensitive file potentially accessible at {url}")
                                         self.vulnerabilities.append({
                                            "name": "Sensitive File Accessible",
                                            "description": f"Potentially sensitive file accessible at {url}. Content should be reviewed.",
                                            "severity": "High",
                                            "ip": target_ip,
                                            "port": port,
                                            "url": url,
                                            "module": "directory_listing" # Grouping under this module for now
                                        })

                        except urllib.error.HTTPError as e:
                            # Ignore 404 Not Found, 403 Forbidden is interesting but not listing/access
                            if e.code not in [404]:
                                if self.verbose and self.status_callback:
                                     self.status_callback(f"    <font color='#AAAAAA'>ℹ️ HTTP Error {e.code} for {url}</font>")
                            pass
                        except Exception as e:
                            # Ignore connection errors, timeouts etc.
                            if self.verbose and self.status_callback:
                                self.status_callback(f"    <font color='#AAAAAA'>ℹ️ Error accessing {url}: {str(e)}</font>")
                            pass
                        
                    except Exception as e:
                        if self.verbose and self.status_callback:
                            self.status_callback(f"    <font color='#AAAAAA'>ℹ️ General error for path {path_item} on {protocol}://{target_ip}:{port}: {str(e)}</font>")
                        pass
                        
        if self.status_callback:
            vuln_count = sum(1 for v in self.vulnerabilities if v.get('module') == 'directory_listing')
            if vuln_count > 0:
                 self.status_callback(f"<font color='#FF6600'>Directory listing/sensitive file check complete. Found {vuln_count} potential issues.</font>")
            else:
                 self.status_callback("<font color='#00CC00'>Directory listing/sensitive file check complete. No obvious issues found.</font>")

    def _check_sensitive_file_access(self, url, target_ip, port, ssl_context):
        """Helper function to check access to a specific sensitive file URL."""
        try:
            request = urllib.request.Request(url, method='GET')
            request.add_header('User-Agent', 'Mozilla/5.0')
            
            with urllib.request.urlopen(request, timeout=self.timeout, context=ssl_context) as response:
                if response.getcode() == 200:
                    # Check if content is non-empty and not a standard error/redirect page
                    content_sample = response.read(512).decode('utf-8', errors='ignore')
                    if content_sample and '<html' not in content_sample.lower() and 'not found' not in content_sample.lower():
                        if self.status_callback:
                            self.status_callback(f"    <font color='#FF0000'>⚠️ Sensitive File Accessible: {url}</font>")
                        self.findings.append(f"Sensitive file potentially accessible at {url}")
                        self.vulnerabilities.append({
                            "name": "Sensitive File Accessible",
                            "description": f"Potentially sensitive file accessible at {url}. Content should be reviewed.",
                            "severity": "High",
                            "ip": target_ip,
                            "port": port,
                            "url": url,
                            "module": "directory_listing" # Grouping here
                        })
        except urllib.error.HTTPError as e:
            # Ignore 404, 403
            pass
        except Exception as e:
            # Ignore other errors
            pass

    def _check_dos_vulnerabilities(self):
        """Check for potential DoS vulnerabilities."""
        if self.status_callback:
            self.status_callback("<font color='#FF6600'>Checking for DoS vulnerabilities...</font>")
            
        # Network-wide DoS vulnerability checks (not dependent on open ports)
        if self.status_callback:
            self.status_callback("<font color='#FF6600'>🛡️ Testing network-wide DoS resilience...</font>")
        
        # 1. ICMP Flood vulnerability test
        if self.status_callback:
            self.status_callback("<font color='#3366FF'>  👉 Testing for ICMP flood vulnerability...</font>")
        
        icmp_vulnerable = False
        try:
            # Extract just the hostname/IP from the target
            target_ip = socket.gethostbyname(self.target)
            
            # Send a moderate number of ICMP echo requests in quick succession
            # Increased count for better stress testing, but still cautious
            success_count = 0
            total_count = 20 # Increased from 5
            response_times = []
            
            for i in range(total_count):
                try:
                    start_time = time.time()
                    # Create a raw socket for ICMP
                    if os.name == "nt":  # Windows
                        # On Windows, we can use ping command
                        ping_cmd = f"ping -n 1 -w 1000 {target_ip}"
                        ping_response = subprocess.run(ping_cmd.split(), capture_output=True, text=True, timeout=1)
                        end_time = time.time()
                        if ping_response.returncode == 0:  # Success
                            success_count += 1
                            response_time_ms = (end_time - start_time) * 1000
                            response_times.append(response_time_ms)
                            if self.status_callback:
                                self.status_callback(f"    <font color='#999999'>ℹ️ ICMP response time: {response_time_ms:.2f}ms</font>")
                    else:  # Unix-like
                        # On Unix-like systems, we can use ping command
                        ping_cmd = f"ping -c 1 -W 1 {target_ip}"
                        ping_response = subprocess.run(ping_cmd.split(), capture_output=True, text=True, timeout=1)
                        end_time = time.time()
                        if ping_response.returncode == 0:  # Success
                            success_count += 1
                            response_time_ms = (end_time - start_time) * 1000
                            response_times.append(response_time_ms)
                            if self.status_callback:
                                self.status_callback(f"    <font color='#999999'>ℹ️ ICMP response time: {response_time_ms:.2f}ms</font>")
                except:
                    pass
                
                # Shorter pause between pings for slightly more intensity
                time.sleep(0.05) # Reduced from 0.1
                
            # Check if the target responded consistently
            if success_count > 0:
                # Calculate response ratio
                response_ratio = success_count / total_count
                
                # Check for high packet loss
                if response_ratio < 0.8:  # If less than 80% successful (more than 20% loss)
                    icmp_vulnerable = True
                    finding_text = f"Target may be vulnerable to ICMP flood attacks (High packet loss: {total_count - success_count}/{total_count} lost)"
                    self.findings.append(finding_text)
                    self.vulnerabilities.append({
                        "name": "Potential ICMP Flood Vulnerability (Packet Loss)",
                        "description": f"Target shows high packet loss ({total_count - success_count}/{total_count}) under moderate ICMP load.",
                        "severity": "Medium",
                        "ip": target_ip,
                        "module": "dos_vulnerabilities"
                    })
                    if self.status_callback:
                        self.status_callback(f"  <font color='#FF0000'>⚠️ Potential ICMP vulnerability! High packet loss observed ({total_count - success_count}/{total_count})</font>")

                # Check for high response time variability (standard deviation)
                if len(response_times) > 5: # Need enough samples
                    import statistics
                    stdev = statistics.stdev(response_times)
                    mean_rt = statistics.mean(response_times)
                    if stdev > mean_rt * 0.5 and stdev > 50: # If std dev is > 50% of mean and > 50ms
                         icmp_vulnerable = True
                         finding_text = f"Target shows high ICMP response time variability (Mean: {mean_rt:.2f}ms, StDev: {stdev:.2f}ms)"
                         self.findings.append(finding_text)
                         self.vulnerabilities.append({
                             "name": "Potential ICMP Flood Vulnerability (Latency Variability)",
                             "description": f"Target shows high ICMP response time variability (Mean: {mean_rt:.2f}ms, StDev: {stdev:.2f}ms) under moderate load.",
                             "severity": "Low", # Lower severity than packet loss
                             "ip": target_ip,
                             "module": "dos_vulnerabilities"
                         })
                         if self.status_callback:
                             self.status_callback(f"  <font color='#FF9900'>⚠️ Potential ICMP vulnerability! High response time variability observed (StDev: {stdev:.2f}ms)</font>")
            else:
                # No responses at all could indicate ICMP is blocked (security feature) or system is down
                if self.status_callback:
                    self.status_callback(f"  <font color='#999999'>ℹ️ No ICMP responses received - ICMP may be blocked (security feature)</font>")
        except Exception as e:
            if self.status_callback:
                self.status_callback(f"  <font color='#999999'>ℹ️ Error testing ICMP flood vulnerability: {str(e)}</font>")
                
        # 2. TCP SYN Flood vulnerability test
        if self.status_callback:
            self.status_callback("<font color='#3366FF'>  👉 Testing for TCP SYN flood vulnerability...</font>")
        
        syn_vulnerable = False
        try:
            # Extract just the hostname/IP from the target
            target_ip = self.target
            if "://" in target_ip:
                target_ip = target_ip.split("://")[1].split("/")[0].split(":")[0]
                
            # Check if a specific port was specified in the target
            target_port = None
            if "://" in self.target and ":" in self.target.split("://")[1]:
                port_part = self.target.split("://")[1].split("/")[0].split(":")[1]
                if port_part.isdigit():
                    target_port = int(port_part)
            
            # Test TCP SYN handling with more half-open connections
            # Increased count for better stress testing, but still cautious
            syn_success = 0
            syn_total = 30 # Increased from 5
            connection_times = []
            
            # If a specific port was in the target, test that, otherwise test more common ports
            test_ports = [80, 443, 8080, 21, 22, 23, 25, 110, 143, 445, 3389] # Added more common ports
            if target_port:
                test_ports = [target_port]
            
            ports_tested_count = 0
            for port in test_ports:
                for i in range(syn_total):
                    ports_tested_count += 1
                    try:
                        # Create a socket
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.5) # Short timeout
                        
                        # Start connection but don't complete the handshake
                        start_time = time.time()
                        result = s.connect_ex((target_ip, port))
                        
                        # Don't send ACK, just close abruptly
                        s.close()
                        
                        end_time = time.time()
                        conn_time_ms = (end_time - start_time) * 1000
                        
                        # If we could connect (result == 0 means port is open and responded)
                        if result == 0:
                            syn_success += 1
                            connection_times.append(conn_time_ms)
                            if self.status_callback:
                                self.status_callback(f"    <font color='#999999'>ℹ️ SYN-ACK received from port {port} in {conn_time_ms:.2f}ms</font>")
                        # Optional: Log if connection timed out or was refused
                        # else:
                        #     if self.verbose and self.status_callback:
                        #         self.status_callback(f"    <font color='#AAAAAA'>ℹ️ No SYN-ACK from port {port} (result: {result})</font>")
                    
                    except socket.error as se:
                        # Log socket errors if verbose
                        # if self.verbose and self.status_callback:
                        #     self.status_callback(f"    <font color='#AAAAAA'>ℹ️ Socket error for port {port}: {se}</font>")
                        pass # Ignore errors like connection refused
                    except Exception as e:
                        # Log other errors if verbose
                        # if self.verbose and self.status_callback:
                        #     self.status_callback(f"    <font color='#AAAAAA'>ℹ️ Error testing SYN for port {port}: {e}</font>")
                        pass
                    
                    # Small delay between SYN packets
                    time.sleep(0.02)
            
            # Analyze results
            if syn_success > 0:
                success_ratio = syn_success / ports_tested_count
                
                # Check if the success ratio is high (e.g., > 50%)
                # This indicates many ports are open or the system isn't dropping SYN packets under this load
                if success_ratio > 0.5:
                    syn_vulnerable = True
                    finding_text = f"Target responded to a high ratio ({success_ratio*100:.1f}%) of TCP SYN packets, suggesting potential SYN flood susceptibility."
                    self.findings.append(finding_text)
                    self.vulnerabilities.append({
                        "name": "Potential TCP SYN Flood Susceptibility",
                        "description": f"Target responded to {success_ratio*100:.1f}% of TCP SYN packets across multiple ports under moderate load.",
                        "severity": "Low",
                        "ip": target_ip,
                        "module": "dos_vulnerabilities"
                    })
                    if self.status_callback:
                        self.status_callback(f"  <font color='#FF9900'>⚠️ Potential SYN Flood Susceptibility: High SYN response ratio ({success_ratio*100:.1f}%)</font>")
                
                # Check connection time variability if enough samples
                if len(connection_times) > 10:
                    import statistics
                    stdev = statistics.stdev(connection_times)
                    mean_ct = statistics.mean(connection_times)
                    if stdev > mean_ct * 0.6 and stdev > 75: # High variability
                         syn_vulnerable = True
                         finding_text = f"Target shows high TCP SYN connection time variability (Mean: {mean_ct:.2f}ms, StDev: {stdev:.2f}ms)"
                         self.findings.append(finding_text)
                         self.vulnerabilities.append({
                             "name": "Potential TCP SYN Flood Vulnerability (Latency Variability)",
                             "description": f"Target shows high TCP SYN connection time variability (Mean: {mean_ct:.2f}ms, StDev: {stdev:.2f}ms) under moderate load.",
                             "severity": "Low",
                             "ip": target_ip,
                             "module": "dos_vulnerabilities"
                         })
                         if self.status_callback:
                             self.status_callback(f"  <font color='#FF9900'>⚠️ Potential SYN Flood Vulnerability: High connection time variability (StDev: {stdev:.2f}ms)</font>")
        except Exception as e:
            if self.status_callback:
                self.status_callback(f"  <font color='#999999'>ℹ️ Error testing TCP SYN flood vulnerability: {str(e)}</font>")
        
        # 3. HTTP Slowloris attack vulnerability
        if self.status_callback:
            self.status_callback("<font color='#3366FF'>  👉 Testing for Slowloris vulnerability...</font>")
            
        slowloris_vulnerable = False
        try:
            # Extract the scheme, hostname/IP, port, and path from the target
            target_ip = self.target
            target_port = 80
            is_https = False
            target_path = "/"
            
            if "://" in target_ip:
                scheme = target_ip.split("://")[0]
                is_https = scheme.lower() == "https"
                if is_https:
                    target_port = 443
                
                host_part = target_ip.split("://")[1].split("/")[0]
                if ":" in host_part:
                    target_ip = host_part.split(":")[0]
                    target_port = int(host_part.split(":")[1])
                else:
                    target_ip = host_part
                
                if "/" in target_ip.split("://")[1]:
                    target_path = "/" + "/".join(target_ip.split("://")[1].split("/")[1:])
            
            # Create more connections to the server for Slowloris test
            sockets = []
            max_sockets = 50  # Increased from 10
            established_sockets = 0
            
            if self.status_callback:
                self.status_callback(f"    <font color='#999999'>ℹ️ Attempting {max_sockets} partial HTTP connections to {target_ip}:{target_port}...</font>")
            
            for i in range(max_sockets):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(2) # Shorter timeout for connection attempt
                    s.connect((target_ip, target_port))
                    
                    # Send partial HTTP request header
                    partial_header = f"GET {target_path} HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: Pentora-Slowloris-Test\r\nX-Random-{i}: {random.randint(1000,9999)}\r\n"
                    s.send(partial_header.encode())
                    
                    # Keep socket open
                    sockets.append(s)
                    established_sockets += 1
                    
                    # Small delay
                    time.sleep(0.05)
                    
                except socket.error as se:
                    # If connection refused or timed out early, stop trying
                    if self.status_callback:
                         self.status_callback(f"    <font color='#AAAAAA'>ℹ️ Slowloris connection {i+1} failed: {se}. Stopping attempts.</font>")
                    break
                except Exception as e:
                    if self.status_callback:
                         self.status_callback(f"    <font color='#AAAAAA'>ℹ️ Slowloris connection {i+1} error: {e}. Stopping attempts.</font>")
                    break

            # Check how many connections were successfully established
            if established_sockets > max_sockets * 0.75: # If > 75% connections established
                slowloris_vulnerable = True
                finding_text = f"Web server at {target_ip}:{target_port} allowed {established_sockets}/{max_sockets} simultaneous partial HTTP connections, indicating potential Slowloris vulnerability."
                self.findings.append(finding_text)
                self.vulnerabilities.append({
                    "name": "Potential Slowloris Vulnerability",
                    "description": f"Web server at {target_ip}:{target_port} accepted {established_sockets}/{max_sockets} simultaneous incomplete connections.",
                    "severity": "Medium",
                    "ip": target_ip,
                    "port": target_port,
                    "module": "dos_vulnerabilities"
                })
                if self.status_callback:
                    self.status_callback(f"  <font color='#FF0000'>⚠️ Potential Slowloris vulnerability! Server accepted {established_sockets}/{max_sockets} partial connections.</font>")
            elif established_sockets > 0:
                 if self.status_callback:
                    self.status_callback(f"  <font color='#00CC00'>✅ Server accepted {established_sockets}/{max_sockets} partial connections (may have some protection).</font>")
            else:
                 if self.status_callback:
                    self.status_callback(f"  <font color='#00CC00'>✅ Server did not accept partial connections (likely protected against Slowloris).</font>")
            
            # Keep sockets open for a moment to simulate holding resources
            if established_sockets > 0:
                time.sleep(2) 
                
            # Close all sockets
            for s in sockets:
                try:
                    s.close()
                except:
                    pass
        except Exception as e:
            if self.status_callback:
                self.status_callback(f"  <font color='#999999'>ℹ️ Error testing Slowloris vulnerability: {str(e)}</font>")

        # 4. Basic UDP Flood Check (New)
        if self.status_callback:
            self.status_callback("<font color='#3366FF'>  👉 Testing basic UDP flood potential...</font>")
        
        udp_vulnerable = False
        try:
            target_ip = socket.gethostbyname(self.target) # Resolve again just in case
            udp_port = 53 # Test against DNS port
            udp_packets_to_send = 50 # Send a burst of UDP packets
            
            if self.status_callback:
                self.status_callback(f"    <font color='#999999'>ℹ️ Sending {udp_packets_to_send} UDP packets to {target_ip}:{udp_port}...</font>")
                
            error_count = 0
            for i in range(udp_packets_to_send):
                try:
                    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    udp_sock.sendto(b"Pentora UDP Test Packet", (target_ip, udp_port))
                    udp_sock.close()
                    time.sleep(0.01) # Small delay
                except socket.error as se:
                    # Count errors like 'Connection refused' or buffer errors
                    error_count += 1
                    # if self.verbose and self.status_callback:
                    #     self.status_callback(f"    <font color='#AAAAAA'>ℹ️ UDP send error {i+1}: {se}</font>")
                except Exception as e:
                    error_count += 1
                    # if self.verbose and self.status_callback:
                    #     self.status_callback(f"    <font color='#AAAAAA'>ℹ️ UDP send error {i+1}: {e}</font>")

            # If a significant number of errors occurred during sending, it might indicate stress
            if error_count > udp_packets_to_send * 0.2: # If > 20% errors
                udp_vulnerable = True
                finding_text = f"High error rate ({error_count}/{udp_packets_to_send}) sending UDP packets to {target_ip}:{udp_port}, potentially indicating UDP flood sensitivity."
                self.findings.append(finding_text)
                self.vulnerabilities.append({
                    "name": "Potential UDP Flood Sensitivity",
                    "description": f"High error rate ({error_count}/{udp_packets_to_send}) sending UDP packets to port {udp_port} under moderate load.",
                    "severity": "Low",
                    "ip": target_ip,
                    "port": udp_port,
                    "module": "dos_vulnerabilities"
                })
                if self.status_callback:
                    self.status_callback(f"  <font color='#FF9900'>⚠️ Potential UDP Flood Sensitivity: High send error rate ({error_count}/{udp_packets_to_send}) to port {udp_port}.</font>")
            else:
                 if self.status_callback:
                    self.status_callback(f"  <font color='#00CC00'>✅ Low error rate sending UDP packets to port {udp_port}.</font>")

        except Exception as e:
             if self.verbose and self.status_callback:
                self.status_callback(f"  <font color='#999999'>ℹ️ Error testing UDP flood potential: {str(e)}</font>")

        # Add overall findings for network-wide testing
        if icmp_vulnerable or syn_vulnerable or slowloris_vulnerable or udp_vulnerable:
            if self.status_callback:
                self.status_callback("  <font color='#FF6600'>⚠️ Target shows potential susceptibility to various DoS vectors under moderate testing.</font>")
        else:
            if self.status_callback:
                self.status_callback("  <font color='#00CC00'>✅ No obvious network-level DoS vulnerabilities detected with current tests.</font>")
        
        if self.status_callback:
            self.status_callback("<font color='#FF6600'>DoS vulnerabilities check complete.</font>")
            
    def _check_no_auth_services(self):
        """Check for services with no authentication."""
        if self.status_callback:
            self.status_callback("<font color='#FF6600'>Checking for services with no authentication...</font>")
            
        # Perform network-wide checks for services with no authentication
        if self.status_callback:
            self.status_callback("<font color='#FF6600'>🔒 Performing network-wide authentication checks...</font>")
            
        target_ip = self.target
        if "://" in target_ip:
            target_ip = target_ip.split("://")[1].split("/")[0].split(":")[0]
            
        try:
            target_ip = socket.gethostbyname(target_ip)
        except:
            # If we can't resolve it, just use the original
            pass
        
        # 1. Check for open MongoDB instances (default port 27017)
        if self.status_callback:
            self.status_callback("<font color='#3366FF'>  👉 Testing for no-auth MongoDB...</font>")
            
        mongo_ports = [27017, 27018, 27019]
        for port in mongo_ports:
            try:
                s = socket.socket()
                s.settimeout(2)
                result = s.connect_ex((target_ip, port))
                s.close()
                if result == 0:
                    if self.status_callback:
                        self.status_callback(f"    <font color='#999999'>ℹ️ Found potential MongoDB on port {port}</font>")
                    
                    # Try to connect to MongoDB without auth
                    if pymongo is not None:
                        try:
                            # Connect without authentication
                            conn_str = f"mongodb://{target_ip}:{port}/?connectTimeoutMS=2000&serverSelectionTimeoutMS=2000"
                            client = pymongo.MongoClient(conn_str)
                            
                            # Try to list databases
                            dbs = client.list_database_names()
                            
                            if dbs:
                                if self.status_callback:
                                    self.status_callback(f"    <font color='#FF0000'>⚠️ Vulnerable! MongoDB on port {port} has no authentication</font>")
                                
                                self.findings.append(f"MongoDB on port {port} has no authentication")
                                self.vulnerabilities.append({
                                    "name": "MongoDB No Authentication",
                                    "description": f"MongoDB server on {target_ip}:{port} allows connections without authentication",
                                    "severity": "High",
                                    "ip": target_ip,
                                    "port": port,
                                    "module": "no_auth_services"
                                })
                                
                                # Close connection
                                client.close()
                        except:
                            # Either auth is required or some other error
                            pass
                    else:
                        if self.status_callback:
                            self.status_callback(f"    <font color='#999999'>ℹ️ pymongo module not available, cannot test MongoDB authentication</font>")
                s.close()
            except:
                pass
                
        # 2. Check for exposed Elasticsearch instances
        if self.status_callback:
            self.status_callback("<font color='#3366FF'>  👉 Testing for no-auth Elasticsearch...</font>")
            
        elastic_ports = [9200, 9300]
        for port in elastic_ports:
            try:
                # Check if port is open
                s = socket.socket()
                s.settimeout(2)
                result = s.connect_ex((target_ip, port))
                s.close()
                
                if result == 0:
                    if self.status_callback:
                        self.status_callback(f"    <font color='#999999'>ℹ️ Found potential Elasticsearch on port {port}</font>")
                    
                    # Try to access Elasticsearch info endpoint without auth
                    try:
                        url = f"http://{target_ip}:{port}/"
                        request = urllib.request.Request(url)
                        request.add_header('User-Agent', 'Mozilla/5.0')
                        
                        with urllib.request.urlopen(request, timeout=3) as response:
                            if response.getcode() == 200:
                                content = response.read().decode('utf-8', errors='ignore')
                                
                                if '"cluster_name"' in content or '"version"' in content:
                                    if self.status_callback:
                                        self.status_callback(f"    <font color='#FF0000'>⚠️ Vulnerable! Elasticsearch on port {port} has no authentication</font>")
                                    
                                    self.findings.append(f"Elasticsearch on port {port} has no authentication")
                                    self.vulnerabilities.append({
                                        "name": "Elasticsearch No Authentication",
                                        "description": f"Elasticsearch server on {target_ip}:{port} allows connections without authentication",
                                        "severity": "High",
                                        "ip": target_ip,
                                        "port": port,
                                        "module": "no_auth_services"
                                    })
                    except:
                        # Either auth is required or some other error
                        pass
            except:
                pass
                
        # 3. Check for exposed admin interfaces on common web ports
        if self.status_callback:
            self.status_callback("<font color='#3366FF'>  👉 Testing for exposed admin interfaces...</font>")
        
        web_ports = [80, 443, 8080, 8443, 8000, 8008, 8888, 8081]
        admin_paths = [
            '/admin',
            '/administrator',
            '/wp-admin',
            '/admin-console',
            '/manager/html',
            '/admin.php',
            '/adminlogin',
            '/admincp',
            '/system',
            '/dashboard',
            '/control'
        ]
        
        for port in web_ports:
            protocols = ['http']
            if port in [443, 8443]:
                protocols = ['https']
                
            for protocol in protocols:
                for path in admin_paths:
                    try:
                        url = f"{protocol}://{target_ip}:{port}{path}"
                        
                        if self.status_callback:
                            self.status_callback(f"    <font color='#999999'>ℹ️ Testing {url}</font>")
                        
                        request = urllib.request.Request(url)
                        request.add_header('User-Agent', 'Mozilla/5.0')
                        
                        try:
                            with urllib.request.urlopen(request, timeout=3) as response:
                                code = response.getcode()
                                
                                # If we got a 200 OK response, check if it's a login page
                                if code == 200:
                                    content = response.read().decode('utf-8', errors='ignore')
                                    
                                    # Words that might indicate a login page without a login form
                                    admin_indicators = [
                                        'admin', 'dashboard', 'control panel', 'management', 
                                        'backend', 'administration', 'console', 'system'
                                    ]
                                    
                                    # Form indicators
                                    form_indicators = [
                                        '<form', 'login', 'username', 'password', 'signin', 'log in'
                                    ]
                                    
                                    # Check if it's an admin page without a login form
                                    content_lower = content.lower()
                                    if (any(indicator in content_lower for indicator in admin_indicators) and 
                                        not any(indicator in content_lower for indicator in form_indicators)):
                                        
                                        if self.status_callback:
                                            self.status_callback(f"    <font color='#FF0000'>⚠️ Vulnerable! Admin interface at {url} may be accessible without authentication</font>")
                                        
                                        self.findings.append(f"Admin interface at {url} may be accessible without authentication")
                                        self.vulnerabilities.append({
                                            "name": "Exposed Admin Interface",
                                            "description": f"Admin interface at {url} may be accessible without proper authentication",
                                            "severity": "High",
                                            "ip": target_ip,
                                            "port": port,
                                            "module": "no_auth_services"
                                        })
                        except:
                            # This is expected for most URLs that don't exist
                            pass
                    except:
                        # This is expected for ports that aren't open
                        pass

        # 4. Check for Anonymous FTP (Port 21)
        if self.status_callback:
            self.status_callback("<font color='#3366FF'>  👉 Testing for Anonymous FTP...</font>")
        try:
            ftp_port = 21
            s = socket.socket()
            s.settimeout(2)
            result = s.connect_ex((target_ip, ftp_port))
            s.close()
            if result == 0:
                 if self.status_callback:
                     self.status_callback(f"    <font color='#999999'>ℹ️ Found potential FTP on port {ftp_port}. Testing anonymous login...</font>")
                 if self._check_ftp_auth(target_ip, ftp_port, 'anonymous', ''):
                     if self.status_callback:
                         self.status_callback(f"    <font color='#FF0000'>⚠️ Vulnerable! Anonymous FTP login allowed on port {ftp_port}</font>")
                     self.findings.append(f"Anonymous FTP login allowed on {target_ip}:{ftp_port}")
                     self.vulnerabilities.append({
                         "name": "Anonymous FTP Login Allowed",
                         "description": f"FTP server on {target_ip}:{ftp_port} allows anonymous login.",
                         "severity": "Medium",
                         "ip": target_ip,
                         "port": ftp_port,
                         "module": "no_auth_services"
                     })
        except Exception as e:
             if self.verbose and self.status_callback:
                 self.status_callback(f"    <font color='#AAAAAA'>ℹ️ Error checking anonymous FTP: {e}</font>")
             pass

        # 5. Check for open Redis instances (default port 6379)
        if self.status_callback:
            self.status_callback("<font color='#3366FF'>  👉 Testing for no-auth Redis...</font>")
        redis_port = 6379
        try:
            s = socket.socket()
            s.settimeout(2)
            result = s.connect_ex((target_ip, redis_port))
            s.close()
            if result == 0:
                if self.status_callback:
                    self.status_callback(f"    <font color='#999999'>ℹ️ Found potential Redis on port {redis_port}. Testing connection...</font>")
                if HAS_REDIS:
                    try:
                        r = redis.Redis(host=target_ip, port=redis_port, socket_connect_timeout=2, password=None)
                        r.ping() # Try a simple command
                        # If ping succeeds without auth, it's likely open
                        if self.status_callback:
                            self.status_callback(f"    <font color='#FF0000'>⚠️ Vulnerable! Redis on port {redis_port} has no authentication</font>")
                        self.findings.append(f"Redis on port {redis_port} has no authentication")
                        self.vulnerabilities.append({
                            "name": "Redis No Authentication",
                            "description": f"Redis server on {target_ip}:{redis_port} allows connections without authentication.",
                            "severity": "High",
                            "ip": target_ip,
                            "port": redis_port,
                            "module": "no_auth_services"
                        })
                        r.close()
                    except redis.exceptions.AuthenticationError:
                        # Auth required, which is good
                         if self.status_callback:
                            self.status_callback(f"    <font color='#00CC00'>✅ Redis on port {redis_port} requires authentication.</font>")
                    except Exception as e:
                         # Other connection errors
                         if self.verbose and self.status_callback:
                             self.status_callback(f"    <font color='#AAAAAA'>ℹ️ Could not confirm Redis auth status on port {redis_port}: {e}</font>")
                else:
                    if self.status_callback:
                        self.status_callback(f"    <font color='#999999'>ℹ️ redis module not available, cannot test Redis authentication</font>")
        except Exception as e:
             if self.verbose and self.status_callback:
                 self.status_callback(f"    <font color='#AAAAAA'>ℹ️ Error checking Redis port {redis_port}: {e}</font>")
             pass

        # 6. Check for open Memcached instances (default port 11211)
        if self.status_callback:
            self.status_callback("<font color='#3366FF'>  👉 Testing for no-auth Memcached...</font>")
        memcached_port = 11211
        try:
            s = socket.socket()
            s.settimeout(2)
            result = s.connect_ex((target_ip, memcached_port))
            s.close()
            if result == 0:
                if self.status_callback:
                    self.status_callback(f"    <font color='#999999'>ℹ️ Found potential Memcached on port {memcached_port}. Testing connection...</font>")
                if HAS_MEMCACHED:
                    try:
                        client = pymemcache.client.base.Client((target_ip, memcached_port), connect_timeout=2, timeout=2)
                        stats = client.stats() # Try to get stats
                        # If stats command works without auth, it's open
                        if stats:
                             if self.status_callback:
                                self.status_callback(f"    <font color='#FF0000'>⚠️ Vulnerable! Memcached on port {memcached_port} has no authentication</font>")
                             self.findings.append(f"Memcached on port {memcached_port} has no authentication")
                             self.vulnerabilities.append({
                                 "name": "Memcached No Authentication",
                                 "description": f"Memcached server on {target_ip}:{memcached_port} allows connections without authentication.",
                                 "severity": "Medium", # Often less critical than DBs unless storing sensitive data
                                 "ip": target_ip,
                                 "port": memcached_port,
                                 "module": "no_auth_services"
                             })
                        client.close()
                    except Exception as e:
                         # Assume auth might be needed or other error
                         if self.verbose and self.status_callback:
                             self.status_callback(f"    <font color='#AAAAAA'>ℹ️ Could not confirm Memcached auth status on port {memcached_port}: {e}</font>")
                else:
                    if self.status_callback:
                        self.status_callback(f"    <font color='#999999'>ℹ️ pymemcache module not available, cannot test Memcached authentication</font>")
        except Exception as e:
             if self.verbose and self.status_callback:
                 self.status_callback(f"    <font color='#AAAAAA'>ℹ️ Error checking Memcached port {memcached_port}: {e}</font>")
             pass

        # Summary for no-auth checks
        if self.status_callback:
            vuln_count = sum(1 for v in self.vulnerabilities if v.get('module') == 'no_auth_services')
            if vuln_count > 0:
                 self.status_callback(f"<font color='#FF6600'>No-authentication service check complete. Found {vuln_count} potential issues.</font>")
            else:
                 self.status_callback("<font color='#00CC00'>No-authentication service check complete. No obvious issues found.</font>")

    # Removed the _check_service_vulnerabilities method as its functionality
    # is now integrated into the nmap script parsing within _run_port_scan.

    def get_findings(self):
        """
        Get the findings from the scan.
        
        Returns:
            Dictionary with vulnerabilities and findings
        """
        return {
            "vulnerabilities": self.vulnerabilities,
            "findings": self.findings
        }

    def set_timeout(self, timeout):
        """
        Set the timeout for network operations.
        
        Args:
            timeout: Timeout in seconds
        """
        self.timeout = timeout
        if self.status_callback:
            self.status_callback(f"Timeout set to {timeout} seconds")
    
    def set_max_threads(self, max_threads):
        """
        Set the maximum number of threads for parallel scanning.
        
        Args:
            max_threads: Maximum number of threads
        """
        self.max_threads = max_threads
        if self.status_callback:
            self.status_callback(f"Maximum threads set to {max_threads}")
    
    def set_verbose(self, verbose):
        """
        Set the verbose output flag.
        
        Args:
            verbose: True to enable verbose output, False otherwise
        """
        self.verbose = verbose
        if self.status_callback:
            self.status_callback(f"Verbose output {'enabled' if verbose else 'disabled'}")

    def _generate_csv_report(self, report_path=None):
        """Generate a CSV report."""
        if report_path:
            with open(report_path, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["Vulnerability", "Description", "Severity", "IP", "Port", "Module"])
                for vuln in self.vulnerabilities:
                    writer.writerow([
                        vuln["name"],
                        vuln["description"],
                        vuln["severity"],
                        vuln["ip"],
                        vuln["port"],
                        vuln["module"]
                    ])
        else:
            output = "Vulnerability,Description,Severity,IP,Port,Module\n"
            for vuln in self.vulnerabilities:
                output += f"{vuln['name']},{vuln['description']},{vuln['severity']},{vuln['ip']},{vuln['port']},{vuln['module']}\n"
            return output

    def _generate_html_report(self, report_path=None):
        """Generate an HTML report with modern styling."""
        # Group vulnerabilities by category
        categorized_vulns = {}
        for vuln in self.vulnerabilities:
            category = vuln["name"]
            if category not in categorized_vulns:
                categorized_vulns[category] = []
            categorized_vulns[category].append(vuln)
        
        # Filter out categories with zero findings
        categorized_vulns = {k: v for k, v in categorized_vulns.items() if len(v) > 0}
        
        # Define the HTML template with modern styling
        html_template = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Pentora Network Scanner Report</title>
            <style>
                :root {{
                    --primary-color: #2c3e50;
                    --secondary-color: #3498db;
                    --success-color: #2ecc71;
                    --warning-color: #f1c40f;
                    --danger-color: #e74c3c;
                    --light-gray: #ecf0f1;
                    --dark-gray: #7f8c8d;
                }}
                
                * {{
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                }}
                
                body {{
                    background-color: #f5f6fa;
                    color: var(--primary-color);
                    line-height: 1.6;
                    padding: 20px;
                }}
                
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    padding: 30px;
                    border-radius: 10px;
                    box-shadow: 0 0 20px rgba(0,0,0,0.1);
                }}
                
                .header {{
                    text-align: center;
                    margin-bottom: 40px;
                    padding-bottom: 20px;
                    border-bottom: 2px solid var(--light-gray);
                }}
                
                .header h1 {{
                    color: var(--primary-color);
                    font-size: 2.5em;
                    margin-bottom: 10px;
                }}
                
                .header h2 {{
                    color: var(--dark-gray);
                    font-size: 1.2em;
                    font-weight: normal;
                }}
                
                .scan-info {{
                    background: var(--light-gray);
                    padding: 20px;
                    border-radius: 8px;
                    margin-bottom: 30px;
                }}
                
                .scan-info h2 {{
                    color: var(--primary-color);
                    margin-bottom: 15px;
                }}
                
                .vulnerabilities {{
                    margin-bottom: 30px;
                }}
                
                .vulnerability-category {{
                    background: white;
                    border: 1px solid var(--light-gray);
                    border-radius: 8px;
                    margin-bottom: 20px;
                    overflow: hidden;
                }}
                
                .category-header {{
                    background: var(--primary-color);
                    color: white;
                    padding: 15px 20px;
                    font-size: 1.2em;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }}
                
                .category-content {{
                    padding: 20px;
                }}
                
                .vulnerability-item {{
                    background: var(--light-gray);
                    padding: 15px;
                    border-radius: 6px;
                    margin-bottom: 10px;
                }}
                
                .severity {{
                    display: inline-block;
                    padding: 4px 8px;
                    border-radius: 4px;
                    font-size: 0.9em;
                    font-weight: bold;
                    margin-right: 10px;
                }}
                
                .severity-high {{
                    background: var(--danger-color);
                    color: white;
                }}
                
                .severity-medium {{
                    background: var(--warning-color);
                    color: var(--primary-color);
                }}
                
                .severity-low {{
                    background: var(--success-color);
                    color: white;
                }}
                
                .findings {{
                    background: white;
                    border: 1px solid var(--light-gray);
                    border-radius: 8px;
                    padding: 20px;
                }}
                
                .findings h2 {{
                    color: var(--primary-color);
                    margin-bottom: 15px;
                }}
                
                .findings ul {{
                    list-style-type: none;
                }}
                
                .findings li {{
                    padding: 10px;
                    border-bottom: 1px solid var(--light-gray);
                }}
                
                .findings li:last-child {{
                    border-bottom: none;
                }}
                
                @media (max-width: 768px) {{
                    .container {{
                        padding: 15px;
                    }}
                    
                    .header h1 {{
                        font-size: 2em;
                    }}
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Pentora Network Scanner Report</h1>
                </div>
                
                <div class="scan-info">
                    <h2>Scan Information</h2>
                    <p><strong>Target:</strong> {target}</p>
                    <p><strong>Scan Time:</strong> {scan_time}</p>
                    <p><strong>Enabled Modules:</strong> {enabled_modules}</p>
                </div>
                
                <div class="vulnerabilities">
                    <h2>Vulnerabilities</h2>
                    {vulnerabilities_content}
                </div>
                
                <div class="findings">
                    <h2>Additional Findings</h2>
                    {findings_content}
                </div>
            </div>
        </body>
        </html>
        """
        
        # Generate vulnerabilities content
        vulnerabilities_content = ""
        if categorized_vulns:
            for category, vulns in categorized_vulns.items():
                vulnerabilities_content += f"""
                <div class="vulnerability-category">
                    <div class="category-header">
                        <span>{category}</span>
                        <span>{len(vulns)} found</span>
                    </div>
                    <div class="category-content">
                """
                for vuln in vulns:
                    severity_class = "severity-" + vuln["severity"].lower()
                    vulnerabilities_content += f"""
                    <div class="vulnerability-item">
                        <span class="severity {severity_class}">{vuln["severity"]}</span>
                        <span>{vuln["description"]}</span>
                    </div>
                    """
                vulnerabilities_content += """
                    </div>
                </div>
                """
        else:
            vulnerabilities_content = "<p>No vulnerabilities found</p>"
        
        # Generate findings content
        findings_content = ""
        if self.findings:
            findings_content += "<ul>"
            for finding in self.findings:
                findings_content += f"<li>{finding}</li>"
            findings_content += "</ul>"
        else:
            findings_content = "<p>No additional findings</p>"
        
        # Format the template with the data
        html_content = html_template.format(
            target=self.target,
            scan_time=dt.now().strftime("%Y-%m-%d %H:%M:%S"),
            enabled_modules=', '.join(self.enabled_modules),
            vulnerabilities_content=vulnerabilities_content,
            findings_content=findings_content
        )
        
        if report_path:
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
        else:
            return html_content

    def _check_service_vulnerabilities(self, port_info):
        """Check for known vulnerabilities based on service and version information."""
        vulnerabilities = []
        
        ip = port_info.get('ip', '')
        port = port_info.get('port', 0)
        service = port_info.get('service', '').lower()
        product = port_info.get('product', '').lower()
        version = port_info.get('version', '').lower()
        
        # Common vulnerability patterns
        if service == 'http' or service == 'https':
            # Check for vulnerable web servers
            if 'apache' in product:
                if version.startswith('2.4.') and int(version.split('.')[2]) < 50:
                    vulnerabilities.append({
                        "id": "CVE-2021-41773",
                        "name": f"Apache HTTP Server Path Traversal",
                        "description": f"Apache HTTP Server {version} is vulnerable to path traversal (CVE-2021-41773)",
                        "severity": "Critical",
                        "ip": ip,
                        "port": port,
                        "service": service,
                        "product": product,
                        "version": version,
                        "module": "service_vulnerabilities",
                        "cvss_score": 9.8,
                        "remediation": "Upgrade to Apache 2.4.51 or later",
                        "references": ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41773"]
                    })
            elif 'nginx' in product:
                if version.startswith('1.') and int(version.split('.')[1]) < 20:
                    vulnerabilities.append({
                        "id": "CVE-2021-23017",
                        "name": f"Nginx Resolver DoS",
                        "description": f"Nginx {version} resolver is vulnerable to DoS (CVE-2021-23017)",
                        "severity": "High",
                        "ip": ip,
                        "port": port,
                        "service": service,
                        "product": product,
                        "version": version,
                        "module": "service_vulnerabilities",
                        "cvss_score": 7.5,
                        "remediation": "Upgrade to Nginx 1.20.2, 1.19.10, or 1.18.0 or later",
                        "references": ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23017"]
                    })
            elif 'iis' in product:
                if version.startswith('7.') or version.startswith('6.'):
                    vulnerabilities.append({
                        "id": "VULN-IIS-OLD",
                        "name": f"Outdated IIS Version ({version})",
                        "description": f"IIS {version} is outdated and may contain known vulnerabilities. Consider upgrading to the latest version.",
                        "severity": "Medium",
                        "ip": ip,
                        "port": port,
                        "service": service,
                        "product": product,
                        "version": version,
                        "module": "service_vulnerabilities"
                    })
            
            # Check for potentially vulnerable web applications
            if 'tomcat' in product:
                vulnerabilities.append({
                    "id": "VULN-TOMCAT-EXPOSED",
                    "name": "Apache Tomcat Exposed",
                    "description": "Apache Tomcat is exposed. Check for default credentials and ensure it's properly secured.",
                    "severity": "Medium",
                    "ip": ip,
                    "port": port,
                    "service": service,
                    "product": product,
                    "version": version,
                    "module": "service_vulnerabilities"
                })
            elif 'jenkins' in product:
                vulnerabilities.append({
                    "id": "VULN-JENKINS-EXPOSED",
                    "name": "Jenkins Exposed",
                    "description": "Jenkins is exposed. Check for proper authentication and ensure it's properly secured.",
                    "severity": "Medium",
                    "ip": ip,
                    "port": port,
                    "service": service,
                    "product": product,
                    "version": version,
                    "module": "service_vulnerabilities"
                })
        
        elif service == 'ssh':
            # Check for vulnerable SSH versions
            if 'openssh' in product:
                if version.startswith('5.') or version.startswith('6.0') or version.startswith('6.1') or version.startswith('6.2') or version.startswith('6.3') or version.startswith('6.4'):
                    vulnerabilities.append({
                        "id": "CVE-2016-0777",
                        "name": "OpenSSH Information Disclosure",
                        "description": f"OpenSSH {version} is vulnerable to information disclosure (CVE-2016-0777)",
                        "severity": "Medium",
                        "ip": ip,
                        "port": port,
                        "service": service,
                        "product": product,
                        "version": version,
                        "module": "service_vulnerabilities",
                        "cvss_score": 5.8,
                        "remediation": "Upgrade to OpenSSH 7.1p2 or later, or disable roaming in the client configuration",
                        "references": ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0777"]
                    })
                if '7.2p1' in version or '7.2p2' in version:
                    vulnerabilities.append({
                        "id": "VULN-SSH-USER-ENUM",
                        "name": "OpenSSH User Enumeration Vulnerability",
                        "description": "This version of OpenSSH is vulnerable to user enumeration (CVE-2016-6210).",
                        "severity": "Medium",
                        "ip": ip,
                        "port": port,
                        "service": service,
                        "product": product,
                        "version": version,
                        "module": "service_vulnerabilities"
                    })
        
        elif service == 'ftp':
            # Check for vulnerable FTP servers
            if 'vsftpd' in product:
                if version.startswith('2.3.4'):
                    vulnerabilities.append({
                        "id": "VULN-VSFTPD-BACKDOOR",
                        "name": "vsFTPd Backdoor Vulnerability",
                        "description": "vsFTPd 2.3.4 contains a backdoor that allows remote attackers to gain shell access.",
                        "severity": "Critical",
                        "ip": ip,
                        "port": port,
                        "service": service,
                        "product": product,
                        "version": version,
                        "module": "service_vulnerabilities",
                        "cvss_score": 10.0,
                        "remediation": "Upgrade to VSFTPD 3.0.3 or later",
                        "references": ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-2523"]
                    })
                elif version.startswith('2.'):
                    vulnerabilities.append({
                        "id": "CVE-2015-1419",
                        "name": "VSFTPD Denial of Service",
                        "description": f"VSFTPD {version} is vulnerable to denial of service (CVE-2015-1419)",
                        "severity": "Medium",
                        "ip": ip,
                        "port": port,
                        "service": service,
                        "product": product,
                        "version": version,
                        "module": "service_vulnerabilities",
                        "cvss_score": 5.0,
                        "remediation": "Upgrade to VSFTPD 3.0.3 or later",
                        "references": ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1419"]
                    })
            elif 'proftpd' in product:
                if version.startswith('1.3.3'):
                    vulnerabilities.append({
                        "id": "VULN-PROFTPD-RCE",
                        "name": "ProFTPD Remote Code Execution",
                        "description": "ProFTPD 1.3.3 is vulnerable to remote code execution (CVE-2010-4221).",
                        "severity": "Critical",
                        "ip": ip,
                        "port": port,
                        "service": service,
                        "product": product,
                        "version": version,
                        "module": "service_vulnerabilities"
                    })
        
        elif service == 'mysql':
            # Check for vulnerable MySQL versions
            if version.startswith('5.5.') or version.startswith('5.0.') or version.startswith('4.'):
                vulnerabilities.append({
                    "id": "CVE-2021-2307",
                    "name": "MySQL Server Privilege Escalation",
                    "description": f"MySQL Server {version} is vulnerable to privilege escalation (CVE-2021-2307)",
                    "severity": "High",
                    "ip": ip,
                    "port": port,
                    "service": service,
                    "product": product,
                    "version": version,
                    "module": "service_vulnerabilities",
                    "cvss_score": 8.0,
                    "remediation": "Upgrade to MySQL 5.7.38, 5.6.51, or 5.5.63 or later",
                    "references": ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-2307"]
                })
        
        elif service == 'ms-sql-s':
            # Check for vulnerable MSSQL versions
            if '2000' in product or '2005' in product:
                vulnerabilities.append({
                    "id": "VULN-MSSQL-OLD",
                    "name": f"Outdated MS SQL Server Version ({product})",
                    "description": f"MS SQL Server {product} is outdated and may contain known vulnerabilities. Consider upgrading to the latest version.",
                    "severity": "High",
                    "ip": ip,
                    "port": port,
                    "service": service,
                    "product": product,
                    "version": version,
                    "module": "service_vulnerabilities"
                })
        
        elif service in ('microsoft-ds', 'netbios-ssn', 'smb'):
            # Check for vulnerable SMB versions
            if not version or version.startswith(('1.', '2.0')):
                vulnerabilities.append({
                    "id": "MS17-010",
                    "name": "EternalBlue SMB Vulnerability",
                    "description": "SMB v1/v2 is vulnerable to remote code execution (MS17-010/EternalBlue)",
                    "severity": "Critical",
                    "ip": ip,
                    "port": port,
                    "service": service,
                    "product": product,
                    "version": version,
                    "module": "service_vulnerabilities",
                    "cvss_score": 9.8,
                    "remediation": "Update Windows systems with the latest security patches, disable SMBv1",
                    "references": ["https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010"]
                })
        
        elif service == 'ms-wbt-server' or port == 3389:
            vulnerabilities.append({
                "id": "CVE-2019-0708",
                "name": "BlueKeep RDP Vulnerability",
                "description": "Remote Desktop Services may be vulnerable to remote code execution (BlueKeep)",
                "severity": "Critical",
                "ip": ip,
                "port": port,
                "service": service,
                "product": product,
                "version": version,
                "module": "service_vulnerabilities",
                "cvss_score": 9.8,
                "remediation": "Apply Windows security updates, enable Network Level Authentication (NLA)",
                "references": ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-0708"]
            })
        
        elif service == 'telnet':
            # Telnet is inherently insecure
            vulnerabilities.append({
                "id": "VULN-TELNET-CLEARTEXT",
                "name": "Telnet Service Exposed",
                "description": "Telnet transmits data in cleartext and is considered insecure. Consider using SSH instead.",
                "severity": "High",
                "ip": ip,
                "port": port,
                "service": service,
                "product": product,
                "version": version,
                "module": "service_vulnerabilities",
                "cvss_score": 7.5,
                "remediation": "Disable Telnet and use SSH instead",
                "references": ["https://www.owasp.org/index.php/Telnet"]
            })
        
            # Check for default credentials (This might be redundant if nmap scripts handle it, but keep for now)
            # default_cred_check = self._check_default_credentials_for_service(port_info) # Assuming a refactored check
            # if default_cred_check:
            #     vulnerabilities.append(default_cred_check)
        
        return vulnerabilities # Return vulnerabilities found by hardcoded checks (if any)
