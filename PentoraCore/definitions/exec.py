#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from typing import List

from PentoraCore.definitions.base import FindingBase


class CommandExecutionFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "Command execution"

    @classmethod
    def description(cls) -> str:
        return (
            "This attack consists in executing system commands on the server."
        ) + " " + (
            "The attacker tries to inject this commands in the request parameters."
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "OWASP: Command Injection",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/latest/"
                    "4-Web_Application_Security_Testing/"
                    "07-Input_Validation_Testing/12-Testing_for_Command_Injection"
                )
            },
            {
                "title": (
                    "CWE-78: Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)"
                ),
                "url": "https://cwe.mitre.org/data/definitions/78.html"
            },
        ]

    @classmethod
    def solution(cls) -> str:
        return (
            "Prefer working without user input when using file system calls."
        )

    @classmethod
    def short_name(cls) -> str:
        return cls.name()

    @classmethod
    def type(cls) -> str:
        return "vulnerability"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-INPV-12"]
