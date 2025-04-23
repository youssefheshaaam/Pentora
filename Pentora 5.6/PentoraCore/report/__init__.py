#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from .reportgenerator import ReportGenerator
from .htmlreportgenerator import HTMLReportGenerator
from .jsonreportgenerator import JSONReportGenerator

GENERATORS = {
    "html": HTMLReportGenerator,
    "json": JSONReportGenerator
}


def get_report_generator_instance(report_format: str = "html"):
    """
    Get an instance of the specified report generator.
    
    Args:
        report_format: The format of the report (html, json)
        
    Returns:
        An instance of the specified report generator
    """
    return GENERATORS[report_format]()
