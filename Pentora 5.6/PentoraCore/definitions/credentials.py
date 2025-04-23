#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from typing import List

from PentoraCore.definitions.base import FindingBase


class CredentialsFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "Weak credentials"

    @classmethod
    def description(cls) -> str:
        return (
            "The web application is using either default credentials or weak passwords that can be found in well-known "
            "passwords lists."
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "CWE-798: Use of Hard-coded Credentials",
                "url": "https://cwe.mitre.org/data/definitions/798.html"
            },
            {
                "title": "CWE-521: Weak Password Requirements",
                "url": "https://cwe.mitre.org/data/definitions/521.html"
            },
            {
                "title": "OWASP: Testing for Weak Password Policy",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/stable/"
                    "4-Web_Application_Security_Testing/04-Authentication_Testing/07-Testing_for_Weak_Password_Policy"
                )
            }
        ]

    @classmethod
    def solution(cls) -> str:
        return (
            "Do not ship or deploy with any default credentials, particularly for admin users. "
            "Implement weak-password checks, such as testing new or changed passwords "
            "against a list of the top 10000 worst passwords."
        )

    @classmethod
    def short_name(cls) -> str:
        return cls.name()

    @classmethod
    def type(cls) -> str:
        return "vulnerability"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-ATHN-07"]
