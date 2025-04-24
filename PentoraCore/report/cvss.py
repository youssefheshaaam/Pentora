#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# This file is part of the Pentora project
# Copyright (C) 2025 Pentora Team
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

"""CVSS (Common Vulnerability Scoring System) Calculator for Pentora Reports.

This module provides functionality to calculate CVSS scores for vulnerabilities 
in Pentora reports based on NIST standards (CVSS v3.1). It can retrieve the latest 
data from the National Vulnerability Database (NVD) or use predefined scores.

This module is part of the report generation system and is used to add accurate
vulnerability severity scores to generated reports.
"""

import json
import time
import logging
import urllib.parse
from typing import Dict, Tuple, List, Optional, Any
import os
import httpx
from datetime import datetime, timedelta

# Setup logger for CVSS module
logger = logging.getLogger("cvss")

class NVDApi:
    """Client for the NIST National Vulnerability Database (NVD) API."""
    
    API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CACHE_DIR = os.path.expanduser("~/.pentora/cache")
    CACHE_FILE = os.path.join(CACHE_DIR, "nvd_cache.json")
    CACHE_EXPIRY = 24 * 60 * 60  # 24 hours in seconds
    
    def __init__(self, api_key: Optional[str] = "e8c759a7-705c-4f9a-a625-1a92c70b5785"):
        """Initialize the NVD API client.
        
        Args:
            api_key: NVD API key for authentication (required as of March 2025)
                    Register for a key at: https://nvd.nist.gov/developers/request-an-api-key
        """
        self.api_key = api_key
        self.cache = self._load_cache()
        
        # Create cache directory if it doesn't exist
        if not os.path.exists(self.CACHE_DIR):
            os.makedirs(self.CACHE_DIR, exist_ok=True)
    
    def _load_cache(self) -> Dict:
        """Load the NVD data cache from disk.
        
        Returns:
            Dictionary containing cached NVD data
        """
        if os.path.exists(self.CACHE_FILE):
            try:
                with open(self.CACHE_FILE, 'r') as f:
                    cache = json.load(f)
                    return cache
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Failed to load NVD cache: {e}")
        
        # Return empty cache if loading failed or file doesn't exist
        return {"cves": {}, "last_updated": time.time()}
    
    def _save_cache(self) -> None:
        """Save the NVD data cache to disk."""
        try:
            with open(self.CACHE_FILE, 'w') as f:
                json.dump(self.cache, f)
        except IOError as e:
            logger.warning(f"Failed to save NVD cache: {e}")
    
    def _is_cache_valid(self) -> bool:
        """Check if the cache is still valid based on expiry time.
        
        Returns:
            True if cache is valid, False otherwise
        """
        if "last_updated" not in self.cache:
            return False
        
        current_time = time.time()
        return (current_time - self.cache["last_updated"]) < self.CACHE_EXPIRY
    
    def search_cve(self, keyword: str) -> List[Dict]:
        """Search for CVEs based on a keyword.
        
        Args:
            keyword: Keyword to search for in CVE descriptions
            
        Returns:
            List of CVE data dictionaries
        """
        cache_key = f"keyword:{keyword}"
        
        # Check cache first
        if cache_key in self.cache.get("cves", {}):
            cache_entry = self.cache["cves"][cache_key]
            # Use cached data if it's still valid
            if time.time() - cache_entry["timestamp"] < self.CACHE_EXPIRY:
                return cache_entry["data"]
        
        # Prepare request parameters - updated for NVD API 2.0
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 20
        }
        
        # API key is now required for all requests to NVD
        if self.api_key:
            headers = {"apiKey": self.api_key}
        else:
            headers = {}
            logger.warning("No NVD API key provided. Requests will likely fail with 403 Forbidden.")
        
        # Make API request
        try:
            with httpx.Client(timeout=30.0) as client:
                response = client.get(self.API_BASE_URL, params=params, headers=headers)
                response.raise_for_status()
                result = response.json()
                
                # Extract CVEs from response
                cves = []
                if "vulnerabilities" in result:
                    for vuln in result["vulnerabilities"]:
                        if "cve" in vuln:
                            cves.append(vuln["cve"])
                
                # Update cache
                if not self.cache.get("cves"):
                    self.cache["cves"] = {}
                
                self.cache["cves"][cache_key] = {
                    "data": cves,
                    "timestamp": time.time()
                }
                self._save_cache()
                
                return cves
                
        except httpx.HTTPError as e:
            if e.response.status_code == 403:
                logger.error("NVD API request failed with 403 Forbidden. Please check your API key.")
            else:
                logger.error(f"Error fetching CVE data: {e}")
            return []
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing CVE data: {e}")
            return []
    
    def get_cve(self, cve_id: str) -> Optional[Dict]:
        """Get data for a specific CVE ID.
        
        Args:
            cve_id: CVE ID to look up (e.g., CVE-2021-44228)
            
        Returns:
            CVE data dictionary or None if not found
        """
        cache_key = f"id:{cve_id}"
        
        # Check cache first
        if cache_key in self.cache.get("cves", {}):
            cache_entry = self.cache["cves"][cache_key]
            # Use cached data if it's still valid
            if time.time() - cache_entry["timestamp"] < self.CACHE_EXPIRY:
                return cache_entry["data"]
        
        # Prepare request parameters
        params = {
            "cveId": cve_id
        }
        
        # API key is now required for all requests to NVD
        if self.api_key:
            headers = {"apiKey": self.api_key}
        else:
            headers = {}
            logger.warning("No NVD API key provided. Requests will likely fail with 403 Forbidden.")
        
        # Make API request
        try:
            with httpx.Client(timeout=30.0) as client:
                response = client.get(self.API_BASE_URL, params=params, headers=headers)
                response.raise_for_status()
                result = response.json()
                
                # Extract CVE from response
                if "vulnerabilities" in result and result["vulnerabilities"]:
                    cve_data = result["vulnerabilities"][0].get("cve")
                    
                    # Update cache
                    if not self.cache.get("cves"):
                        self.cache["cves"] = {}
                    
                    self.cache["cves"][cache_key] = {
                        "data": cve_data,
                        "timestamp": time.time()
                    }
                    self._save_cache()
                    
                    return cve_data
                
                return None
                
        except httpx.HTTPError as e:
            if e.response.status_code == 403:
                logger.error("NVD API request failed with 403 Forbidden. Please check your API key.")
            else:
                logger.error(f"Error fetching CVE data: {e}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing CVE data: {e}")
            return None
    
    def extract_cvss_data(self, cve_data: Dict) -> Tuple[float, str, str]:
        """Extract CVSS score, vector string, and severity from CVE data.
        
        Args:
            cve_data: CVE dictionary from NVD
            
        Returns:
            Tuple containing (score, vector_string, severity)
        """
        try:
            # Try to extract CVSS v3.1 metrics first
            metrics = cve_data.get("metrics", {})
            
            # Try CVSS v3.1 first
            if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                return (
                    float(cvss_data.get("baseScore", 0.0)),
                    cvss_data.get("vectorString", ""),
                    cvss_data.get("baseSeverity", "").lower().capitalize()
                )
            
            # Fall back to CVSS v3.0
            elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
                return (
                    float(cvss_data.get("baseScore", 0.0)),
                    cvss_data.get("vectorString", ""),
                    cvss_data.get("baseSeverity", "").lower().capitalize()
                )
            
            # Fall back to CVSS v2.0
            elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
                score = float(cvss_data.get("baseScore", 0.0))
                vector = cvss_data.get("vectorString", "")
                
                # Convert score to severity
                if score >= 7.0:
                    severity = "High"
                elif score >= 4.0:
                    severity = "Medium"
                else:
                    severity = "Low"
                
                return (score, vector, severity)
        
        except (KeyError, IndexError, ValueError) as e:
            logger.warning(f"Error extracting CVSS data: {e}")
        
        # Default values if extraction fails
        return (5.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", "Medium")


class CVSSCalculator:
    """Calculator for CVSS (Common Vulnerability Scoring System) scores.
    
    This class is used by report generators to add accurate severity scores
    to vulnerability reports. It can retrieve scores from the NVD API or
    use predefined default scores.
    """
    
    # Initialize the NVD API with the default key
    _nvd_api = NVDApi()
    
    # Flag to control whether API calls are made
    _use_api = True
    
    # In-memory cache for CVSS data to avoid repeated API calls
    _memory_cache = {}
    
    # Mapping of vulnerability names to CVE IDs
    # Note: Some categories are general and may not have a single representative CVE.
    # In such cases, the list remains empty, and default scores are used.
    VULN_TO_CVE_MAPPING = {
        "Backup File": [],  # General category, hard to map to a single CVE
        "Weak Credentials": [], # General category, hard to map to a single CVE
        "CRLF Injection": ["CVE-2019-17426"], # Example: Apache HTTP Server CRLF
        "Content Security Policy Configuration": [], # General config issue
        "Cross Site Request Forgery": ["CVE-2023-24488"], # Example: Citrix Gateway/ADC CSRF to RCE
        "Potentially Dangerous File": ["CVE-2017-7529"], # Example: nginx RCE via dangerous upload
        "Command Execution": ["CVE-2021-44228"], # Example: Log4Shell (often involves command injection)
        "Path Traversal": ["CVE-2021-41773"], # Example: Apache HTTP Server Path Traversal
        "Fingerprint Web Application Framework": [], # Information Disclosure
        "Fingerprint Web Server": [], # Information Disclosure
        "HTML Injection": ["CVE-2022-22963"], # Example: Spring Cloud Function SpEL RCE (can be via HTML injection)
        "Clickjacking Protection": [], # General config issue (X-Frame-Options)
        "HTTP Strict Transport Security (HSTS)": [], # General config issue
        "MIME Type Confusion": [], # General issue
        "HttpOnly Flag Cookie": [], # General config issue
        "Unencrypted Channels": [], # General config issue (Lack of HTTPS)
        "LDAP Injection": ["CVE-2016-1000027"], # Example: Spring Security LDAP Injection
        "Open Redirect": ["CVE-2019-0232"], # Example: Apache Tomcat RCE (can involve redirects)
        "Reflected Cross Site Scripting": ["CVE-2022-22963"], # Using Spring Cloud Function example again
        "Secure Flag Cookie": [], # General config issue
        "SQL Injection": ["CVE-2021-42392", "CVE-2021-31799"], # Existing
        "Server Side Request Forgery": ["CVE-2021-26855"], # Example: Exchange Server SSRF (ProxyLogon)
        "Stored HTML Injection": ["CVE-2022-22963"], # Using Spring Cloud Function example again
        "Stored Cross Site Scripting": ["CVE-2022-22963"], # Using Spring Cloud Function example again
        "Subdomain Takeover": [], # General config issue
        "Blind SQL Injection": ["CVE-2020-13379", "CVE-2021-28163"], # Existing
        "Unrestricted File Upload": ["CVE-2017-7529"], # Using nginx example again
        "Vulnerable Software": [], # Too general, depends on specific software found
        "Internal Server Error": [], # Symptom, not specific vulnerability type
        "Resource Consumption": ["CVE-2022-22965"], # Example: Spring4Shell (can lead to DoS)
        "Review Webserver Metafiles for Information Leakage": [], # Information Disclosure
        "Fingerprint Web Technology": [], # Information Disclosure
        "HTTP Methods": [], # General config issue (e.g., enabling TRACE)
        "XML External Entity": ["CVE-2018-1000656", "CVE-2019-10717"], # Existing
        "Shellshock": ["CVE-2014-6271", "CVE-2014-7169"], # Existing
        "Brute Force Login": [], # General category
        "Directory Buster": [] # General category
    }
    
    # Default CVSS scores for each vulnerability type
    DEFAULT_SCORES = {
        "Backup File": (5.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "Medium"),
        "Weak Credentials": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "High"),
        "CRLF Injection": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "Medium"),
        "Content Security Policy Configuration": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "Medium"),
        "Cross Site Request Forgery": (6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N", "Medium"),
        "Potentially Dangerous File": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "Medium"),
        "Command Execution": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical"),
        "Path Traversal": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "High"),
        "Fingerprint Web Application Framework": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "Medium"),
        "Fingerprint Web Server": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "Medium"),
        "HTML Injection": (5.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", "Medium"),
        "Clickjacking Protection": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "Medium"),
        "HTTP Strict Transport Security (HSTS)": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "Medium"),
        "MIME Type Confusion": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "Medium"),
        "HttpOnly Flag Cookie": (4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", "Medium"),
        "Unencrypted Channels": (5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "Medium"),
        "LDAP Injection": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "High"),
        "Open Redirect": (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "Medium"),
        "Reflected Cross Site Scripting": (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "Medium"), # Default score kept for reference
        "Secure Flag Cookie": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "Medium"),
        "SQL Injection": (8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:L", "High"), # Default score kept for reference
        "Server Side Request Forgery": (8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L", "High"), # Default score kept for reference
        "Stored HTML Injection": (5.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", "Medium"),
        "Stored Cross Site Scripting": (8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N", "High"),
        "Subdomain Takeover": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "High"),
        "Blind SQL Injection": (7.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", "High"),
        "Unrestricted File Upload": (8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L", "High"),
        "Vulnerable Software": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "High"),
        "Internal Server Error": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "Medium"),
        "Resource Consumption": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "Medium"),
        "Review Webserver Metafiles for Information Leakage": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "Medium"),
        "Fingerprint Web Technology": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "Medium"),
        "HTTP Methods": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "Medium"),
        "XML External Entity": (8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L", "High"),
        "Shellshock": (10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "Critical"),
        "Brute Force Login": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "High"),
        "Directory Buster": (5.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "Medium")
    }
    
    @classmethod
    def set_nvd_api_key(cls, api_key: str) -> None:
        """Set the API key for the NVD API.
        
        Args:
            api_key: NVD API key for authentication
        """
        cls._nvd_api = NVDApi(api_key)
    
    @classmethod
    def enable_api(cls, enable: bool = True) -> None:
        """Enable or disable API calls.
        
        Args:
            enable: Whether to enable API calls
        """
        cls._use_api = enable
    
    @classmethod
    def get_cvss_data(cls, vuln_name: str) -> Tuple[float, str, str]:
        """Get CVSS score, vector, and severity for a vulnerability name.
        
        Args:
            vuln_name: Name of the vulnerability
            
        Returns:
            Tuple of (score, vector, severity)
        """
        # Check in-memory cache first
        if vuln_name in cls._memory_cache:
            return cls._memory_cache[vuln_name]
        
        vuln_name_lower = vuln_name.lower()

        # --- Prioritize API lookup first ---
        if cls._use_api:
            try:
                # Try mapped CVE IDs first
                mapped_cve_ids = None
                for key, cve_ids in cls.VULN_TO_CVE_MAPPING.items():
                    if key.lower() == vuln_name_lower:
                        mapped_cve_ids = cve_ids
                        break

                if mapped_cve_ids:
                    # Try each mapped CVE ID
                    for cve_id in mapped_cve_ids:
                        cve_data = cls._nvd_api.get_cve(cve_id)
                        if cve_data:
                            cvss_data = cls._nvd_api.extract_cvss_data(cve_data)
                            if cvss_data[0] > 0:  # Valid score found
                                cls._memory_cache[vuln_name] = cvss_data
                                logger.debug(f"Using API score for {vuln_name} via mapped CVE {cve_id}")
                                return cvss_data
                else:
                    # If no mapped CVEs, try direct keyword search as a fallback API method
                    cves = cls._nvd_api.search_cve(vuln_name)
                    if cves:
                        # Use the first CVE with valid CVSS data
                        for cve in cves:
                            cvss_data = cls._nvd_api.extract_cvss_data(cve)
                            if cvss_data[0] > 0:  # Valid score found
                                cls._memory_cache[vuln_name] = cvss_data
                                logger.debug(f"Using API score for {vuln_name} via keyword search")
                                return cvss_data

            except Exception as e:
                logger.warning(f"API lookup for {vuln_name} failed: {e}. Falling back...")
                # Silently continue to fallback scores

        # --- Fallback to DEFAULT_SCORES if API failed or was disabled ---
        for key, score_data in cls.DEFAULT_SCORES.items():
            if key.lower() == vuln_name_lower:
                cls._memory_cache[vuln_name] = score_data
                logger.debug(f"Using default score for {vuln_name}")
                return score_data

        # --- Final fallback if no API score and no default score found ---
        logger.warning(f"No API score or default score found for {vuln_name}. Using generic medium score.")
        generic_default_score = (5.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", "Medium")
        cls._memory_cache[vuln_name] = generic_default_score
        return generic_default_score

# Initialize the NVD API on module load - this can be configured later
CVSSCalculator.set_nvd_api_key("e8c759a7-705c-4f9a-a625-1a92c70b5785")
# Disable API calls during scanning to avoid delays
CVSSCalculator.enable_api(False)
