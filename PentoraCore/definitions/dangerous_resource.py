#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from typing import List

from PentoraCore.definitions.base import FindingBase


class DangerousResourceFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "Potentially dangerous file"

    @classmethod
    def description(cls) -> str:
        return "A file with potential vulnerabilities has been found on the website."

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "Mitre: Search details of a CVE",
                "url": "https://cve.mitre.org/cve/search_cve_list.html"
            },
            {
                "title": "OWASP: Test Network Infrastructure Configuration",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/latest/"
                    "4-Web_Application_Security_Testing/"
                    "02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration"
                )
            }
        ]

    @classmethod
    def solution(cls) -> str:
        return "Make sure the script is up-to-date and restrict access to it if possible."

    @classmethod
    def short_name(cls) -> str:
        return cls.name()

    @classmethod
    def type(cls) -> str:
        return "vulnerability"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-CONF-04", "WSTG-CONF-01"]
