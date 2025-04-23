#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from typing import List

from PentoraCore.definitions.base import FindingBase


class ResourceConsumptionFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "Resource consumption"

    @classmethod
    def description(cls) -> str:
        return (
            "It took an abnormal time to the server to respond to a query. "
            "An attacker might leverage this kind of weakness to overload the server."
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "CWE-405: Asymmetric Resource Consumption (Amplification)",
                "url": "https://cwe.mitre.org/data/definitions/405.html"
            },
            {
                "title": "CWE-400: Uncontrolled Resource Consumption",
                "url": "https://cwe.mitre.org/data/definitions/400.html"
            },
            {
                "title": "OWASP: Improper Error Handling",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/latest/"
                    "4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/"
                    "01-Testing_For_Improper_Error_Handling"
                )
            }
        ]

    @classmethod
    def solution(cls) -> str:
        return (
            "The involved script is maybe using the server resources (CPU, memory, network, file access...) "
            "in a non-efficient way."
        )

    @classmethod
    def short_name(cls) -> str:
        return cls.name()

    @classmethod
    def type(cls) -> str:
        return "anomaly"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-ERRH-01"]
