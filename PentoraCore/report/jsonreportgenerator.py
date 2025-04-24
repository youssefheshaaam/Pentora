#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JSON Report Generator Module for Pentora Project
# Pentora Project

"""This module allows generating reports in JSON format."""
import os
import json
import time
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import quote

from httpx import Response

from PentoraCore.net.response import detail_response
from PentoraCore.report.reportgenerator import ReportGenerator
from PentoraCore.language.vulnerability import CRITICAL_LEVEL, HIGH_LEVEL, MEDIUM_LEVEL, LOW_LEVEL, INFO_LEVEL
from PentoraCore.report.cvss import CVSSCalculator


class BytesDump(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, bytes):
            return o.decode("utf-8", errors="replace")
        return json.JSONEncoder.default(self, o)


class JSONReportGenerator(ReportGenerator):
    """This class allow generating reports in JSON format.
    The root dictionary contains 5 dictionaries :
    - classifications : contains the description and references of a vulnerability type.
    - vulnerabilities : each key is matching a vulnerability class. Value is a list of found vulnerabilities.
    - anomalies : same as vulnerabilities but used only for error messages and timeouts (items of less importance).
    - additionals : some additional information about the target.
    - infos : information about the scan.
    """

    def __init__(self):
        super().__init__()
        # Use only one dict for vulnerability, anomaly and additional types
        self._flaw_types = {}

        self._vulns = {}
        self._anomalies = {}
        self._additionals = {}

    def generate_report(self):
        """
        Generates a JSON report.
        :return: The JSON report as a string.
        """
        report = dict()
        report[self.REPORT_NAME] = self._report_name
        report[self.REPORT_HEAD] = {
            self.REPORT_HEAD_TITLE: self._report_title,
            self.REPORT_HEAD_DESCRIPTION: self._report_description,
            self.REPORT_HEAD_DATE: self._report_date,
            self.REPORT_HEAD_PENTORA: self._report_pentora,
            self.REPORT_HEAD_TESTED_BY: self._report_tested_by,
            self.REPORT_HEAD_OWNER: self._report_owner,
            self.REPORT_HEAD_TARGET: self._report_target,
            self.REPORT_HEAD_START_DATE: self._report_start_date,
            self.REPORT_HEAD_END_DATE: self._report_end_date,
            self.REPORT_HEAD_SUBJECT: self._report_subject
        }

        # Filter out vulnerabilities, anomalies, and additionals with zero findings
        filtered_vulns = {k: v for k, v in self._vulns.items() if len(v) > 0}
        filtered_anomalies = {k: v for k, v in self._anomalies.items() if len(v) > 0}
        filtered_additionals = {k: v for k, v in self._additionals.items() if len(v) > 0}

        report[self.REPORT_BODY] = {
            self.REPORT_BODY_TARGET: self._target_data,
            self.REPORT_BODY_VULNS: filtered_vulns,
            self.REPORT_BODY_ANOMALIES: filtered_anomalies,
            self.REPORT_BODY_ADDITIONALS: filtered_additionals
        }

        # Store the report data for later use
        self._report_data = report

        report_path = os.path.join(self._output_path, self._report_filename)
        try:
            with open(report_path, 'w') as file:
                json.dump(report, file, indent=2)
        except Exception as e:
            print("Failed to write report: {}".format(e))

        return json.dumps(report, indent=2)

    # Vulnerabilities
    def add_vulnerability_type(self, name, description="", solution="", references=None, wstg=None, cvss_score=None, cvss_vector=None, cvss_severity=None):
        """Add information on a type of vulnerability, using pre-fetched CVSS data."""
        if name not in self._flaw_types:
            # Use passed-in CVSS data directly, no internal call needed
            # Fallback logic is handled in the controller (_init_report)
            self._flaw_types[name] = {
                "desc": description,
                "sol": solution,
                "ref": references,
                "wstg": wstg,
                "cvss": {
                    "score": cvss_score,
                    "vector": cvss_vector,
                    "severity": cvss_severity
                }
            }
        if name not in self._vulns:
            self._vulns[name] = []

    def add_vulnerability(
        self,
        module: str,
        category=None,
        level=0,
        request=None,
        parameter="",
        info="",
        wstg: str = None,
        response: Response = None
    ):
        """Add a vulnerability to the report."""
        # Ensure we have vulnerability type information for CVSS data
        if category not in self._flaw_types:
            self.add_vulnerability_type(category)
            
        # Get CVSS data for this vulnerability
        cvss_score = self._flaw_types[category]["cvss"]["score"]
        cvss_vector = self._flaw_types[category]["cvss"]["vector"]
        cvss_severity = self._flaw_types[category]["cvss"]["severity"]
            
        vuln_dict = {
            "method": request.method,
            "path": request.file_path,
            "info": info,
            "level": level,
            "parameter": parameter,
            "referer": request.referer,
            "module": module,
            "http_request": request.http_repr(left_margin=""),
            "curl_command": request.curl_repr,
            "wstg": wstg,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector, 
            "cvss_severity": cvss_severity
        }

        if self._infos["detailed_report_level"] == 2 and response:
            vuln_dict["detail"] = {
                "response": detail_response(response)
            }
            
        if category not in self._vulns:
            self._vulns[category] = []
        self._vulns[category].append(vuln_dict)

    # Anomalies
    def add_anomaly_type(self, name, description="", solution="", references=None, wstg=None):
        """Register a type of anomaly"""
        if name not in self._flaw_types:
            self._flaw_types[name] = {
                "desc": description,
                "sol": solution,
                "ref": references,
                "wstg": wstg,
            }
        if name not in self._anomalies:
            self._anomalies[name] = []

    def add_anomaly(
        self,
        module: str,
        category=None,
        level=0,
        request=None,
        parameter="",
        info="",
        wstg=None,
        response: Response = None
    ):
        """Store the information about an anomaly met during the attack."""
        anom_dict = {
            "method": request.method,
            "path": request.file_path,
            "info": info,
            "level": level,
            "parameter": parameter,
            "referer": request.referer,
            "module": module,
            "http_request": request.http_repr(left_margin=""),
            "curl_command": request.curl_repr,
            "wstg": wstg
        }
        if self._infos["detailed_report_level"] == 2:
            anom_dict["detail"] = {
                "response": detail_response(response)
            }
        if category not in self._anomalies:
            self._anomalies[category] = []
        self._anomalies[category].append(anom_dict)

    def add_additional_type(self, name, description="", solution="", references=None, wstg=None):
        """Register a type of additional"""
        if name not in self._flaw_types:
            self._flaw_types[name] = {
                "desc": description,
                "sol": solution,
                "ref": references,
                "wstg": wstg
            }
        if name not in self._additionals:
            self._additionals[name] = []

    def add_additional(
        self,
        module: str,
        category=None,
        level=0,
        request=None,
        parameter="",
        info="",
        wstg=None,
        response: Response = None
    ):
        """Store the information about an additional."""
        addition_dict = {
            "method": request.method,
            "path": request.file_path,
            "info": info,
            "level": level,
            "parameter": parameter,
            "referer": request.referer,
            "module": module,
            "http_request": request.http_repr(left_margin=""),
            "curl_command": request.curl_repr,
            "wstg": wstg
        }

        if self._infos["detailed_report_level"] == 2:
            addition_dict["detail"] = {
                "response": detail_response(response)
            }

        if category not in self._additionals:
            self._additionals[category] = []
        self._additionals[category].append(addition_dict)
