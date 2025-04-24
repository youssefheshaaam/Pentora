#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from typing import List

from PentoraCore.definitions.base import FindingBase


class SoftwareNameDisclosureFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "Fingerprint web technology"

    @classmethod
    def description(cls) -> str:
        return "The use of a web technology can be deducted due to the presence of its specific fingerprints."

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "OWASP: Fingerprint Web Server",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/stable/"
                    "4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server.html"
                )
            },
            {
                "title": "OWASP: Fingerprint Web Application Framework",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/stable/"
                    "4-Web_Application_Security_Testing/"
                    "01-Information_Gathering/08-Fingerprint_Web_Application_Framework.html"
                )
            }
        ]

    @classmethod
    def solution(cls) -> str:
        return "This is only for informational purposes."

    @classmethod
    def short_name(cls) -> str:
        return cls.name()

    @classmethod
    def type(cls) -> str:
        return "additional"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-INFO-02", "WSTG-INFO-08"]
