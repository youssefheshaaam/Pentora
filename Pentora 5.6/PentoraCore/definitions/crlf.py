#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from typing import List

from PentoraCore.definitions.base import FindingBase


class CrlfFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "CRLF Injection"

    @classmethod
    def description(cls) -> str:
        return (
            "The term CRLF refers to Carriage Return (ASCII 13, \\r) Line Feed (ASCII 10, \\n)."
        ) + " " + (
            "A CRLF Injection attack occurs when a user manages to submit a CRLF into an application."
        ) + " " + (
            "This is most commonly done by modifying an HTTP parameter or URL."
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "OWASP: CRLF Injection",
                "url": "https://owasp.org/www-community/vulnerabilities/CRLF_Injection"
            },
            {
                "title": "Acunetix: What Are CRLF Injection Attacks",
                "url": "https://www.acunetix.com/websitesecurity/crlf-injection/"
            },
            {
                "title": "CWE-93: Improper Neutralization of CRLF Sequences ('CRLF Injection')",
                "url": "https://cwe.mitre.org/data/definitions/93.html"
            },
            {
                "title": "OWASP: Testing for HTTP Splitting Smuggling",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/latest/"
                    "4-Web_Application_Security_Testing/07-Input_Validation_Testing/"
                    "15-Testing_for_HTTP_Splitting_Smuggling"
                )
            }
        ]

    @classmethod
    def solution(cls) -> str:
        return (
            "Check the submitted parameters and do not allow CRLF to be injected when it is not expected."
        )

    @classmethod
    def short_name(cls) -> str:
        return cls.name()

    @classmethod
    def type(cls) -> str:
        return "vulnerability"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-INPV-15"]
