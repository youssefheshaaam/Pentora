#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# HTML Report Generator Module for Pentora Project
# Pentora Project

"""This module allows generating reports in HTML format."""
import os
from importlib.resources import files
from shutil import copytree, rmtree, copy
from urllib.parse import urlparse
import time
import json
import random
import base64
import codecs
import html
import re
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import quote

from mako.template import Template

from PentoraCore.report.jsonreportgenerator import JSONReportGenerator
from PentoraCore.language.vulnerability import CRITICAL_LEVEL, HIGH_LEVEL, MEDIUM_LEVEL, LOW_LEVEL, INFO_LEVEL
from PentoraCore.report.cvss import CVSSCalculator

def level_to_emoji(level: int) -> str:
    if level == CRITICAL_LEVEL:
        return "🔥"
    if level == HIGH_LEVEL:
        return "🔴"
    if level == MEDIUM_LEVEL:
        return "🟠"
    if level == LOW_LEVEL:
        return "🟡"
    if level == INFO_LEVEL:
        return "🕵️"
    return ""


class HTMLReportGenerator(JSONReportGenerator):
    """
    This class generates a Pentora scan report in HTML format.
    """

    def __init__(self):
        super().__init__()
        self._final_path = None

    REPORT_DIR = "report_template"

    def generate_report(self, output_path):
        """
        Copy the report structure in the specified 'output_path' directory.
        If this directory already exists, overwrite the template files and add the HTML report.
        (This way we keep previous generated HTML files).
        """
        if os.path.isdir(output_path):
            for subdir in ("css", "js"):
                try:
                    rmtree(os.path.join(output_path, subdir))
                except FileNotFoundError:
                    pass

                copytree(
                    str(files("PentoraCore").joinpath(self.REPORT_DIR, subdir)),
                    os.path.join(output_path, subdir)
                )

            copy(str(files("PentoraCore").joinpath(self.REPORT_DIR, "Pentora_logo.png")), output_path)
        else:
            copytree(str(files("PentoraCore").joinpath(self.REPORT_DIR)), output_path)

        mytemplate = Template(
            filename=str(files("PentoraCore").joinpath(self.REPORT_DIR, "report.html")),
            input_encoding="utf-8",
            output_encoding="utf-8"
        )

        report_target_name = urlparse(self._infos['target']).netloc.replace(':', '_')
        report_time = time.strftime('%m%d%Y_%H%M', self._date)

        filename = f"{report_target_name}_{report_time}.html"

        self._final_path = os.path.join(output_path, filename)

        # Filter out all vulnerability categories with zero findings
        filtered_vulns = {k: v for k, v in self._vulns.items() if len(v) > 0}
        filtered_anomalies = {k: v for k, v in self._anomalies.items() if len(v) > 0}
        filtered_additionals = {k: v for k, v in self._additionals.items() if len(v) > 0}

        with open(self._final_path, "w", encoding='utf-8') as html_report_file:
            html_report_file.write(
                mytemplate.render_unicode(
                    pentora_version=self._infos["version"],
                    target=self._infos["target"],
                    scan_date=self._infos["date"],
                    scan_scope=self._infos["scope"],
                    auth_dict=self._infos["auth"],
                    auth_form_dict=self._infos["auth"]["form"] if self._infos.get("auth") is not None else None,
                    crawled_pages_nbr=self._infos["crawled_pages_nbr"],
                    vulnerabilities=filtered_vulns,
                    anomalies=filtered_anomalies,
                    additionals=filtered_additionals,
                    flaws=self._flaw_types,
                    level_to_emoji=level_to_emoji,
                    detailed_report_level=self._infos["detailed_report_level"]
                )
            )

    @property
    def final_path(self):
        return self._final_path
