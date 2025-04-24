#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from typing import List

from PentoraCore.definitions.base import FindingBase


class CspFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "Content Security Policy Configuration"

    @classmethod
    def description(cls) -> str:
        return (
            "Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain "
            "types of attacks, including Cross Site Scripting (XSS) and data injection attacks."
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "Mozilla: Content Security Policy (CSP)",
                "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
            },
            {
                "title": "OWASP: Content Security Policy Cheat Sheet",
                "url": (
                    "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"
                )
            },
            {
                "title": "OWASP: How to do Content Security Policy (PDF)",
                "url": (
                    "https://owasp.org/www-pdf-archive/2019-02-22_-_How_do_I_Content_Security_Policy_-_Print.pdf"
                )
            },
            {
                "title": "OWASP: Content Security Policy",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/latest/"
                    "4-Web_Application_Security_Testing/"
                    "02-Configuration_and_Deployment_Management_Testing/12-Test_for_Content_Security_Policy"
                )
            }
        ]

    @classmethod
    def solution(cls) -> str:
        return (
            "Configuring Content Security Policy involves adding the Content-Security-Policy HTTP header to a web page "
            "and giving it values to control what resources the user agent is allowed to load for that page."
        )

    @classmethod
    def short_name(cls) -> str:
        return "CSP Configuration"

    @classmethod
    def type(cls) -> str:
        return "vulnerability"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-CONF-12", "OSHP-Content-Security-Policy"]
