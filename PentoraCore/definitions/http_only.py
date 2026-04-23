#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from typing import List

from PentoraCore.definitions.base import FindingBase


class HttpOnlyFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "HttpOnly Flag cookie"

    @classmethod
    def description(cls) -> str:
        return (
            "HttpOnly is an additional flag included in a Set-Cookie HTTP response header. "
            "Using the HttpOnly flag when generating a cookie helps mitigate the risk of client side script accessing "
            "the protected cookie (if the browser supports it)."
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "OWASP: Testing for Cookies Attributes",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/stable/"
                    "4-Web_Application_Security_Testing/"
                    "06-Session_Management_Testing/02-Testing_for_Cookies_Attributes.html"
                )
            },
            {
                "title": "OWASP: HttpOnly",
                "url": "https://owasp.org/www-community/HttpOnly"
            }
        ]

    @classmethod
    def solution(cls) -> str:
        return "While creation of the cookie, make sure to set the HttpOnly Flag to True."

    @classmethod
    def short_name(cls) -> str:
        return cls.name()

    @classmethod
    def type(cls) -> str:
        return "vulnerability"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-SESS-02"]
