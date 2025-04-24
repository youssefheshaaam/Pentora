#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from typing import List

from PentoraCore.definitions.base import FindingBase


class CsrfFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "Cross Site Request Forgery"

    @classmethod
    def description(cls) -> str:
        return (
            "Cross-Site Request Forgery (CSRF) is an attack that forces an end user to execute unwanted actions "
            "on a web application in which they're currently authenticated."
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "OWASP: Testing for Cross Site Request Forgery",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/stable/"
                    "4-Web_Application_Security_Testing/06-Session_Management_Testing/"
                    "05-Testing_for_Cross_Site_Request_Forgery.html"
                )
            },
            {
                "title": "OWASP: Cross-Site Request Forgery Prevention Cheat Sheet",
                "url": (
                    "https://cheatsheetseries.owasp.org/cheatsheets/"
                    "Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
                )
            },
            {
                "title": "CWE-352: Cross-Site Request Forgery (CSRF)",
                "url": "https://cwe.mitre.org/data/definitions/352.html"
            },
        ]

    @classmethod
    def solution(cls) -> str:
        return (
            "Check if your framework has built-in CSRF protection and use it."
        ) + " " + (
            "If framework does not have built-in CSRF protection add CSRF tokens to all state changing requests "
            "(requests that cause actions on the site) and validate them on backend."
        )

    @classmethod
    def short_name(cls) -> str:
        return "CSRF"

    @classmethod
    def type(cls) -> str:
        return "vulnerability"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-SESS-05"]
