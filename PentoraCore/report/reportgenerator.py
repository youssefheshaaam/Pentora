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

"""This module provides a base class for report generation."""
import time
from httpx import Response
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Tuple

from PentoraCore.report.cvss import CVSSCalculator


class ReportGenerator(ABC):
    """
    This is an abstract class for all report generators.
    All report generators must inherit from this class and implement the generate_report method.
    """

    def __init__(self):
        self._infos = {}
        self._date = None

    def set_report_info(
        self,
        target: str,
        scope,
        date,
        version,
        auth,
        crawled_pages: list,
        crawled_pages_nbr: int,
        detailed_report_level: int
    ):
        """Set the information about the scan"""
        self._infos["target"] = target
        self._infos["date"] = time.strftime("%a, %d %b %Y %H:%M:%S +0000", date)
        self._infos["version"] = version
        self._infos["scope"] = scope
        self._infos["auth"] = auth
        self._infos["crawled_pages_nbr"] = crawled_pages_nbr
        if detailed_report_level in (1, 2):
            self._infos["crawled_pages"] = crawled_pages
        self._infos["detailed_report_level"] = detailed_report_level
        self._date = date

    @property
    def scan_date(self):
        return self._date

    @abstractmethod
    def generate_report(self, output_path):
        """
        Generate a report using the vulnerabilities list and the additionals dictionary to add information.
        
        Args:
            output_path: Path where the report will be saved
        """
        pass

    # Vulnerabilities
    def add_vulnerability_type(self, name: str, description: str = "", solution: str = "", references=None, wstg=None):
        """
        Add information on a type of vulnerability, including CVSS score data from NIST
        """
        # Get CVSS data (score, vector, severity) based on vulnerability name
        cvss_score, cvss_vector, cvss_severity = CVSSCalculator.get_cvss_data(name)
        
        # Store CVSS information along with other vulnerability type data
        # This method needs to be implemented by subclasses
        raise NotImplementedError("Must be overridden")

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
        raise NotImplementedError("Must be overridden")

    # Anomalies
    def add_anomaly_type(self, name, description="", solution="", references=None, wstg=None):
        raise NotImplementedError("Must be overridden")

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
        raise NotImplementedError("Must be overridden")

    # Additionals
    def add_additional_type(self, name, description="", solution="", references=None, wstg=None):
        raise NotImplementedError("Must be overridden")

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
        raise NotImplementedError("Must be overridden")
