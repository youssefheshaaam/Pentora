#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from typing import List

from PentoraCore.definitions.base import FindingBase


class SecureCookieFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "Secure Flag cookie"

    @classmethod
    def description(cls) -> str:
        return (
            "The secure flag is an option that can be set by the application server when sending a new cookie to the "
            "user within an HTTP Response. "
            "The purpose of the secure flag is to prevent cookies from being observed by unauthorized parties due "
            "to the transmission of a the cookie in clear text."
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "OWASP: Testing for Cookies Attributes",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/stable/"
                    "4-Web_Application_Security_Testing/06-Session_Management_Testing/"
                    "02-Testing_for_Cookies_Attributes.html"
                )
            },
            {
                "title": "OWASP: Secure Cookie Attribute",
                "url": "https://owasp.org/www-community/controls/SecureCookieAttribute"
            }
        ]

    @classmethod
    def solution(cls) -> str:
        return "When generating the cookie, make sure to set the Secure Flag to True."

    @classmethod
    def short_name(cls) -> str:
        return cls.name()

    @classmethod
    def type(cls) -> str:
        return "vulnerability"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-SESS-02"]
