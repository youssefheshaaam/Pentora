#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from typing import List

from PentoraCore.definitions.base import FindingBase


class XPathInjectionFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "XPATH Injection"

    @classmethod
    def description(cls) -> str:
        return (
            "XPath Injection attacks occur when a web site uses user-supplied information to construct an XPath query "
            "for XML data. "
            "By sending intentionally malformed information into the web site, an attacker can find out how "
            "the XML data is structured, or access data that they may not normally have access to."
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "OWASP: XPATH Injection",
                "url": "https://owasp.org/www-community/attacks/XPATH_Injection"
            },
            {
                "title": "CWE-91: XML Injection (aka Blind XPath Injection)",
                "url": "https://cwe.mitre.org/data/definitions/91.html"
            }
        ]

    @classmethod
    def solution(cls) -> str:
        return (
            "To protect against XPATH injection, you need to use a parameterized XPath interface if one is available, "
            "or escape the user input to make it safe to include in a dynamically constructed query. "
            "Instead, user input must be escaped or filtered or parameterized statements must be used."
        )

    @classmethod
    def short_name(cls) -> str:
        return "Unrestricted Upload"

    @classmethod
    def type(cls) -> str:
        return "XPATHi"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-INPV-09"]
