#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from typing import List

from PentoraCore.definitions.base import FindingBase


class SqlInjectionFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "SQL Injection"

    @classmethod
    def description(cls) -> str:
        return (
            "SQL injection vulnerabilities allow an attacker to alter the queries executed on the backend database."
        ) + " " + (
            "An attacker may then be able to extract or modify information stored in the database or even escalate his "
            "privileges on the system."
        ) + " " + (
            "Blind SQL injection is a technique that exploits a vulnerability occurring in the database "
            "of an application."
        ) + " " + (
            "This kind of vulnerability is harder to detect than basic SQL injections because no error message will be "
            "displayed on the webpage."
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "OWASP: SQL Injection",
                "url": "https://owasp.org/www-community/attacks/SQL_Injection"
            },
            {
                "title": "Wikipedia: SQL injection",
                "url": "https://en.wikipedia.org/wiki/SQL_injection"
            },
            {
                "title": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
                "url": "https://cwe.mitre.org/data/definitions/89.html"
            },
            {
                "title": "OWASP: Blind SQL Injection",
                "url": "https://owasp.org/www-community/attacks/Blind_SQL_Injection"
            },
            {
                "title": "OWASP: SQL Injection",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/latest/"
                    "4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection"
                )
            }
        ]

    @classmethod
    def solution(cls) -> str:
        return (
            "To protect against SQL injection, user input must not directly be embedded in SQL statements."
        ) + " " + (
            "Instead, user input must be escaped or filtered or parameterized statements must be used."
        )

    @classmethod
    def short_name(cls) -> str:
        return "SQLI"

    @classmethod
    def type(cls) -> str:
        return "vulnerability"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-INPV-05"]
