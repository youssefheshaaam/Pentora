#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from typing import List

from PentoraCore.definitions.base import FindingBase


class LdapInjectionFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "LDAP Injection"

    @classmethod
    def description(cls) -> str:
        return (
            "LDAP Injection is an attack used to exploit web based applications that construct LDAP statements "
            "based on user input. "
            "When an application fails to properly sanitize user input, it’s possible to modify LDAP statements using "
            "a local proxy. "
            "This could result in the execution of arbitrary commands such as granting permissions "
            "to unauthorized queries."
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "LDAP Injection",
                "url": "https://owasp.org/www-community/attacks/LDAP_Injection"
            },
            {
                "title": "LDAP Injection Prevention Cheat Sheet",
                "url": "https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html"
            },
            {
                "title": "CWE-90: Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')",
                "url": "https://cwe.mitre.org/data/definitions/90.html"
            }
        ]

    @classmethod
    def solution(cls) -> str:
        return (
            "To protect against XPATH injection, Escape all variables using the right LDAP encoding function. "
            "Use Frameworks that Automatically Protect from LDAP Injection."
        )

    @classmethod
    def short_name(cls) -> str:
        return "LDAPi"

    @classmethod
    def type(cls) -> str:
        return "vulnerability"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-INPV-06"]
